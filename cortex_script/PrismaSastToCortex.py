"""PrismaSastToCortex - Cortex Cloud / XSOAR Script

Migrates Prisma Cloud SAST findings (Code Weaknesses) to Cortex Cloud.

For every Prisma Cloud repository with SAST weaknesses on the default branch
(open and suppressed), the script builds one SARIF 2.1.0 document and uploads
it to an existing Cortex Cloud "3rd Party AppSec Collector".

Runs in DRY-RUN mode by default: nothing is uploaded unless no_dry_run=true.

Arguments:
    prisma_api_url (str): Required. Prisma Cloud API URL, e.g. https://api2.prismacloud.io
    prisma_access_key_id (str): Required. Prisma Cloud access key id.
    prisma_secret_key (str): Required. Prisma Cloud secret key.
    collector_url (str): Required when no_dry_run=true. Collector API URL
        (".../public_api/appsec/v1/collectors/<id>", from "Copy API URL").
    collector_token_id (str): Required when no_dry_run=true. Collector Token ID.
    collector_token (str): Required when no_dry_run=true. Collector API Token.
    no_dry_run (bool): Optional. Default: false. Set to true to upload.
    repositories (array): Optional. Prisma repository names (owner/name) to
        process. Default: all repositories.
    tool_name (str): Optional. SARIF tool.driver.name; must match the collector
        name in Cortex. Default: PrismaCloudSAST.
    attach_sarif (bool): Optional. Default: false. Attach the SARIF files to
        the War Room.

Notes:
    - Cortex only accepts findings for repositories already onboarded in
      Cortex. Repositories are matched by the URL reported by Prisma;
      repositories without a URL (CLI, GitHub Actions, ...) are SKIPPED.
    - The Cortex tenant API key is not needed: the upload authenticates with
      the collector token only.

Output:
    Context path: PrismaSastToCortex.Summary
    Context path: PrismaSastToCortex.Repository (one entry per SARIF file)
    Context path: PrismaSastToCortex.NotUploaded (what was not uploaded and why;
        in dry-run, what would not be uploaded)
"""

import hashlib
import json
import re
import time
import traceback
from urllib.parse import urlparse

import requests


# ============================================================================
# CONSTANTS
# ============================================================================

PAGE_LIMIT = 1000           # Prisma branch_scan page size
REPO_BATCH_SIZE = 100       # repositories per branch_scan filter
MAX_RETRIES = 5
HTTP_TIMEOUT = 120          # seconds per HTTP request

# Prisma check statuses to export: open findings and suppressed findings.
STATUSES = {"open": "Error", "suppressed": "Suppressed"}

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
DEFAULT_TOOL_NAME = "PrismaCloudSAST"
MAX_SARIF_BYTES = 10 * 1024 * 1024  # Cortex collector upload limit per request
POLICY_DOCS_URL = (
    "https://docs.prismacloud.io/en/enterprise-edition/policy-reference/"
    "sast-policies/{folder}-policies/sast-policy-{number}"
)
# Prisma language -> folder name used in the policy reference docs.
POLICY_DOCS_FOLDER = {"typescript": "javascript"}

# Prisma severity -> SARIF level and numeric "security-severity" (CVSS-like).
SEVERITY_MAP = {
    "CRITICAL": ("error", "9.5"),
    "HIGH": ("error", "8.0"),
    "MEDIUM": ("warning", "5.5"),
    "LOW": ("note", "3.0"),
    "INFO": ("note", "0.0"),
}

CONTEXT_PREFIX = "PrismaSastToCortex"


# ============================================================================
# HELPERS
# ============================================================================

def url_problem(url: str) -> str | None:
    """Return a description of what is wrong with an API URL, or None if it looks valid."""
    parsed = urlparse(url.strip())
    if parsed.scheme != "https":
        return "it must start with https://"
    host = parsed.hostname or ""
    if not host or " " in url.strip():
        return "the host name is missing or contains spaces"
    labels = host.split(".")
    if any(len(label) > 63 or not label for label in labels) or "." not in host:
        return (
            "the host name is malformed (check that an API key or token was not "
            "pasted into the URL)"
        )
    return None


def safe_name(value: str) -> str:
    """Turn a repository full name into a filesystem-friendly name."""
    return re.sub(r"[^A-Za-z0-9._-]+", "__", value).strip("_")


def repo_full_name(repo: dict) -> str:
    """Return 'owner/repository' for a Prisma repository object."""
    owner = repo.get("owner") or ""
    name = repo.get("repository") or repo.get("name") or repo.get("id")
    return f"{owner}/{name}" if owner else str(name)


def request_with_retries(session: requests.Session, method: str, url: str, **kwargs) -> requests.Response:
    """Send an HTTP request, retrying on 429, 5xx (except 503) and network errors."""
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = session.request(method, url, timeout=HTTP_TIMEOUT, **kwargs)
            retryable = response.status_code == 429 or (
                response.status_code >= 500 and response.status_code != 503
            )
            if not retryable or attempt == MAX_RETRIES:
                return response
            demisto.debug(f"{method} {url} -> HTTP {response.status_code}, retrying")
        except requests.RequestException as err:
            if attempt == MAX_RETRIES:
                raise
            demisto.debug(f"{method} {url} -> network error {err}, retrying")
        time.sleep(2 ** attempt)
    raise DemistoException(f"{method} {url} failed after {MAX_RETRIES} attempts")


# ============================================================================
# PRISMA CLOUD CLIENT
# ============================================================================

class PrismaClient:
    """Minimal Prisma Cloud API client with token refresh and retries."""

    def __init__(self, api_url: str, key_id: str, secret_key: str):
        self.api_url = api_url.rstrip("/")
        self.key_id = key_id
        self.secret_key = secret_key
        self.session = requests.Session()
        self.session.headers.update(
            {"Content-Type": "application/json", "Accept": "application/json"}
        )

    def login(self) -> None:
        response = request_with_retries(
            self.session,
            "POST",
            f"{self.api_url}/login",
            json={"username": self.key_id, "password": self.secret_key},
        )
        if response.status_code != 200:
            raise DemistoException(
                f"Prisma Cloud login failed (HTTP {response.status_code}). "
                "Check prisma_api_url, prisma_access_key_id and prisma_secret_key."
            )
        token = response.json().get("token")
        if not token:
            raise DemistoException("Prisma Cloud login did not return a token")
        self.session.headers["x-redlock-auth"] = token

    def request(self, method: str, endpoint: str, body=None):
        """Send an authenticated request, re-authenticating once on 401."""
        if "x-redlock-auth" not in self.session.headers:
            self.login()
        url = f"{self.api_url}/{endpoint.lstrip('/')}"
        response = request_with_retries(self.session, method, url, json=body)
        if response.status_code == 401:
            self.login()
            response = request_with_retries(self.session, method, url, json=body)
        if not response.ok:
            raise DemistoException(
                f"Prisma Cloud {method} {endpoint} failed (HTTP {response.status_code}): "
                f"{response.text[:300]}"
            )
        return response.json() if response.content else None

    def list_repositories(self) -> list[dict]:
        data = self.request("GET", "code/api/v1/repositories")
        if isinstance(data, dict):
            data = data.get("data", data.get("repositories", []))
        return data or []

    def get_weaknesses(self, check_status: str, repo_ids: list[str] | None = None) -> list[dict]:
        """
        Return all SAST weaknesses on the default branch for a check status.

        Queries the whole tenant in a few pages (much faster than one query
        per repository); optionally restricted to repo_ids, in batches.
        """
        batches = [None] if not repo_ids else [
            repo_ids[i:i + REPO_BATCH_SIZE] for i in range(0, len(repo_ids), REPO_BATCH_SIZE)
        ]
        issues = []
        for batch in batches:
            filters = {
                "branch": "default",
                "checkStatus": check_status,
                "codeCategories": ["Weaknesses"],
            }
            if batch:
                filters["repositories"] = batch
            offset = 0
            while True:
                payload = {"filters": filters, "limit": PAGE_LIMIT, "offset": offset}
                data = self.request("POST", "code/api/v2/code-issues/branch_scan", body=payload) or {}
                page = data.get("data", [])
                issues.extend(page)
                has_next = data.get("hasNext", len(page) == PAGE_LIMIT)
                if not page or not has_next:
                    break
                offset += PAGE_LIMIT
        return issues


# ============================================================================
# SARIF GENERATION (same logic as the local prisma_sast_to_cortex.py)
# ============================================================================

def parse_lines(value) -> tuple[int, int]:
    """Parse Prisma 'codeIssueLine' ('36' or '17-27') into (start, end)."""
    numbers = [int(n) for n in re.findall(r"\d+", str(value or ""))]
    if not numbers:
        # startLine is mandatory for the Cortex collector; default to line 1.
        return 1, 1
    start = max(numbers[0], 1)
    end = max(numbers[-1], start)
    return start, end


def cwe_ids(issue: dict) -> list[str]:
    """Extract 'CWE-208' style ids from 'CWE-208: Observable Timing ...'."""
    ids = []
    for cwe in issue.get("cwes") or []:
        match = re.match(r"\s*(CWE-\d+)", str(cwe))
        if match and match.group(1) not in ids:
            ids.append(match.group(1))
    return ids


def policy_help_uri(issue: dict) -> str | None:
    """Build the Prisma policy reference URL for built-in SAST policies."""
    match = re.fullmatch(r"BC_SAST_(\d+)", issue.get("violationId", ""))
    language = (issue.get("language") or "").lower()
    if not match or not language:
        return None  # custom policies have no public documentation
    folder = POLICY_DOCS_FOLDER.get(language, language)
    return POLICY_DOCS_URL.format(folder=folder, number=match.group(1))


def finding_fingerprint(issue: dict, occurrence: int = 0) -> str:
    """
    Stable hash identifying a single finding.

    resourceUuid identifies the file, not the finding, and the same
    policy/path/line can be reported more than once with different data
    flows, so the data flow is part of the identity. Prisma also returns
    fully identical records (several hits on the same line); 'occurrence'
    (0, 1, 2...) keeps those distinct.
    """
    parts = [
        issue.get("repository", ""),
        issue.get("violationId", ""),
        issue.get("path", ""),
        str(issue.get("codeIssueLine", "")),
        json.dumps(issue.get("dataFlow") or {}, sort_keys=True),
    ]
    if occurrence:
        parts.append(str(occurrence))
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


def flow_location(point: dict, role: str) -> dict:
    """Convert a Prisma dataFlow source/sink point into a SARIF threadFlowLocation."""
    start = point.get("start") or {}
    end = point.get("end") or {}
    region = {"startLine": max(int(start.get("row") or 1), 1)}
    if start.get("column"):
        region["startColumn"] = int(start["column"])
    if end.get("row"):
        region["endLine"] = max(int(end["row"]), region["startLine"])
    if end.get("column"):
        region["endColumn"] = int(end["column"])
    return {
        "location": {
            "physicalLocation": {
                "artifactLocation": {"uri": str(point.get("path", "")).lstrip("/")},
                "region": region,
            },
            "message": {"text": role},
        }
    }


def issue_to_rule(issue: dict) -> dict:
    """Build a SARIF reportingDescriptor (rule) from a Prisma issue."""
    severity = (issue.get("severity") or "INFO").upper()
    level, security_severity = SEVERITY_MAP.get(severity, SEVERITY_MAP["INFO"])
    cwes = cwe_ids(issue)
    title = issue.get("policy") or issue.get("violationId")

    tags = ["security", "sast"]
    tags += cwes
    tags += [o for o in issue.get("owasp") or [] if o]
    tags += [label for label in issue.get("labels") or [] if label]

    help_lines = [title]
    if issue.get("cwes"):
        help_lines.append("CWE: " + "; ".join(issue["cwes"]))
    if issue.get("owasp"):
        help_lines.append("OWASP: " + "; ".join(issue["owasp"]))
    help_uri = policy_help_uri(issue)
    if help_uri:
        help_lines.append(f"Reference: {help_uri}")

    rule = {
        "id": issue["violationId"],
        "name": title,
        "shortDescription": {"text": title},
        "fullDescription": {"text": title},
        "help": {"text": "\n".join(help_lines)},
        "defaultConfiguration": {"level": level},
        "properties": {
            "tags": list(dict.fromkeys(tags)),
            "severity": severity,
            "security-severity": security_severity,
            "precision": "medium",
            "language": issue.get("language"),
        },
    }
    if help_uri:
        rule["helpUri"] = help_uri
    return rule


def issue_to_result(
    issue: dict, rule_index: int, suppressed: bool, occurrence: int = 0
) -> dict:
    """Map a single Prisma weakness to a SARIF result."""
    severity = (issue.get("severity") or "INFO").upper()
    level, security_severity = SEVERITY_MAP.get(severity, SEVERITY_MAP["INFO"])
    start, end = parse_lines(issue.get("codeIssueLine"))
    path = str(issue.get("path") or issue.get("codePath") or "").lstrip("/")
    cwes = cwe_ids(issue)

    message = issue.get("policy") or issue["violationId"]
    if cwes:
        message += f" ({', '.join(cwes)})"

    result = {
        "ruleId": issue["violationId"],
        "ruleIndex": rule_index,
        "level": level,
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": path},
                    "region": {"startLine": start, "endLine": end},
                }
            }
        ],
        "partialFingerprints": {
            "prismaFindingHash/v1": finding_fingerprint(issue, occurrence)
        },
        "properties": {
            "severity": severity,
            "security-severity": security_severity,
            "cwe": issue.get("cwes") or [],
            "owasp": issue.get("owasp") or [],
            "labels": issue.get("labels") or [],
            "language": issue.get("language"),
            "firstDetected": issue.get("firstDetected"),
            "gitUser": issue.get("gitUser"),
            "commitHash": issue.get("commitHash"),
            "prismaResourceId": issue.get("resourceId"),
            "prismaResourceUuid": issue.get("resourceUuid"),
            "prismaCheckStatus": issue.get("checkStatus"),
        },
    }

    data_flow = issue.get("dataFlow") or {}
    if data_flow.get("source") and data_flow.get("sink"):
        result["codeFlows"] = [
            {
                "threadFlows": [
                    {
                        "locations": [
                            flow_location(data_flow["source"], "source"),
                            flow_location(data_flow["sink"], "sink"),
                        ]
                    }
                ]
            }
        ]

    if suppressed:
        result["suppressions"] = [
            {
                "kind": "external",
                "status": "accepted",
                "justification": "Suppressed in Prisma Cloud",
            }
        ]
    return result


def build_sarif(raw: dict, tool_name: str) -> dict:
    """Build a SARIF 2.1.0 log for one repository's raw Prisma data."""
    repo = raw["repo"]
    rules: list[dict] = []
    rule_index: dict[str, int] = {}
    results = []
    seen: dict[str, int] = {}  # base fingerprint -> occurrences so far

    for key, suppressed in (("open", False), ("suppressed", True)):
        for issue in raw.get(key, []):
            rule_id = issue["violationId"]
            if rule_id not in rule_index:
                rule_index[rule_id] = len(rules)
                rules.append(issue_to_rule(issue))
            base = finding_fingerprint(issue)
            occurrence = seen.get(base, 0)
            seen[base] = occurrence + 1
            results.append(
                issue_to_result(issue, rule_index[rule_id], suppressed, occurrence)
            )

    run = {
        "tool": {
            "driver": {
                "name": tool_name,
                "organization": "Palo Alto Networks",
                "fullName": "Prisma Cloud Application Security - SAST",
                "informationUri": "https://www.paloaltonetworks.com/prisma/cloud",
                "rules": rules,
            }
        },
        "results": results,
        "properties": {
            "prismaRepository": repo_full_name(repo),
            "prismaRepositoryId": repo.get("id"),
            "prismaSource": repo.get("source"),
        },
    }
    if repo.get("url"):
        provenance = {"repositoryUri": repo["url"]}
        if repo.get("defaultBranch"):
            provenance["branch"] = repo["defaultBranch"]
        run["versionControlProvenance"] = [provenance]

    return {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}


def split_sarif(sarif: dict, max_bytes: int = MAX_SARIF_BYTES) -> list[dict]:
    """Split a SARIF log into chunks below max_bytes (results only are split)."""
    if len(json.dumps(sarif).encode()) <= max_bytes:
        return [sarif]
    run = sarif["runs"][0]
    results = run["results"]
    chunks: list[list] = [[]]
    base_size = len(json.dumps({**sarif, "runs": [{**run, "results": []}]}).encode())
    size = base_size
    for result in results:
        result_size = len(json.dumps(result).encode()) + 1
        if chunks[-1] and size + result_size > max_bytes:
            chunks.append([])
            size = base_size
        chunks[-1].append(result)
        size += result_size
    return [{**sarif, "runs": [{**run, "results": chunk}]} for chunk in chunks]


def validate_sarif(sarif: dict) -> list[str]:
    """Structural checks for the fields the Cortex collector requires."""
    errors = []
    if sarif.get("version") != "2.1.0":
        errors.append("version must be 2.1.0")
    for run_idx, run in enumerate(sarif.get("runs", [])):
        driver = run.get("tool", {}).get("driver", {})
        if not driver.get("name"):
            errors.append(f"runs[{run_idx}].tool.driver.name is missing")
        rule_ids = {r.get("id") for r in driver.get("rules", [])}
        if not rule_ids:
            errors.append(f"runs[{run_idx}] has no rules")
        for res_idx, result in enumerate(run.get("results", [])):
            where = f"runs[{run_idx}].results[{res_idx}]"
            if result.get("ruleId") not in rule_ids:
                errors.append(f"{where}.ruleId '{result.get('ruleId')}' not in rules")
            if not result.get("message", {}).get("text"):
                errors.append(f"{where}.message.text is missing")
            locations = result.get("locations") or []
            if not locations:
                errors.append(f"{where}.locations is empty")
                continue
            physical = locations[0].get("physicalLocation", {})
            if not physical.get("artifactLocation", {}).get("uri"):
                errors.append(f"{where} artifactLocation.uri is missing")
            if not physical.get("region", {}).get("startLine"):
                errors.append(f"{where} region.startLine is missing")
    return errors


# ============================================================================
# CORTEX COLLECTOR UPLOAD
# ============================================================================

def upload_sarif(collector: dict, repository_url: str, body: bytes) -> tuple[int, dict]:
    """POST a SARIF document to the collector. Returns (http_status, response_json)."""
    session = requests.Session()
    headers = {
        "Authorization": collector["token"],
        "x-crtx-auth-id": str(collector["token_id"]),
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    response = request_with_retries(
        session,
        "POST",
        collector["url"],
        params={"repository_url": repository_url},
        data=body,
        headers=headers,
    )
    try:
        data = response.json() if response.content else {}
        if not isinstance(data, dict):
            data = {"response": data}
    except ValueError:
        data = {"message": response.text[:500]}
    return response.status_code, data


def response_message(data: dict) -> str:
    """Extract a readable message from the various Cortex response shapes."""
    reply = data.get("reply") if isinstance(data.get("reply"), dict) else {}
    parts = [
        data.get("status"),
        data.get("errorCode") or reply.get("err_code"),
        data.get("message") or reply.get("err_msg"),
        reply.get("err_extra"),
    ]
    text = " | ".join(str(p) for p in parts if p) or json.dumps(data)[:500]
    return " ".join(text.split())  # flatten newlines for the War Room table


# ============================================================================
# MAIN FLOW
# ============================================================================

def parse_args() -> dict:
    """Read and validate the script arguments."""
    args = demisto.args()
    config = {
        "prisma_api_url": (args.get("prisma_api_url") or "").strip(),
        "prisma_access_key_id": (args.get("prisma_access_key_id") or "").strip(),
        "prisma_secret_key": (args.get("prisma_secret_key") or "").strip(),
        "collector": {
            "url": (args.get("collector_url") or "").strip(),
            "token_id": (args.get("collector_token_id") or "").strip(),
            "token": (args.get("collector_token") or "").strip(),
        },
        "dry_run": not argToBoolean(args.get("no_dry_run", "false")),
        "repositories": [r.strip() for r in argToList(args.get("repositories")) if r.strip()],
        "tool_name": (args.get("tool_name") or DEFAULT_TOOL_NAME).strip(),
        "attach_sarif": argToBoolean(args.get("attach_sarif", "false")),
    }

    missing = [k for k in ("prisma_api_url", "prisma_access_key_id", "prisma_secret_key") if not config[k]]
    if missing:
        raise DemistoException(f"Missing required arguments: {', '.join(missing)}")
    problem = url_problem(config["prisma_api_url"])
    if problem:
        raise DemistoException(f"Invalid prisma_api_url: {problem}")

    if not config["dry_run"]:
        names = {"url": "collector_url", "token_id": "collector_token_id", "token": "collector_token"}
        missing = [names[k] for k, v in config["collector"].items() if not v]
        if missing:
            raise DemistoException(
                f"no_dry_run=true requires: {', '.join(missing)}. Create the 3rd Party "
                "AppSec Collector in Cortex and use its API URL, Token ID and API Token."
            )
        problem = url_problem(config["collector"]["url"])
        if problem:
            raise DemistoException(f"Invalid collector_url: {problem}")
        if "/collectors/" not in config["collector"]["url"]:
            raise DemistoException("Invalid collector_url: expected .../public_api/appsec/v1/collectors/<id>")
    return config


def collect_findings(client: PrismaClient, wanted: list[str]) -> tuple[dict, list[str]]:
    """
    Fetch repositories and weaknesses, grouped per repository id.

    Returns ({repo_id: {"repo", "open", "suppressed"}}, [names not found]).
    """
    repos = client.list_repositories()
    repos_by_id = {r["id"]: r for r in repos if r.get("id")}

    not_found = []
    repo_ids = None
    if wanted:
        by_name = {repo_full_name(r).lower(): r for r in repos}
        repo_ids = []
        for name in wanted:
            repo = by_name.get(name.lower())
            if repo:
                repo_ids.append(repo["id"])
            else:
                not_found.append(name)
        if not repo_ids:
            return {}, not_found

    grouped: dict[str, dict] = {}
    for key, status in STATUSES.items():
        for issue in client.get_weaknesses(status, repo_ids):
            repo_id = issue.get("repositoryUuid")
            if repo_id not in grouped:
                # Fall back to a minimal repo object if it is not in the list.
                repo = repos_by_id.get(repo_id) or {
                    "id": repo_id, "repository": issue.get("repository", repo_id)
                }
                grouped[repo_id] = {"repo": repo, "open": [], "suppressed": []}
            grouped[repo_id][key].append(issue)
    return grouped, not_found


def process_repository(raw: dict, config: dict, file_entries: list) -> list[dict]:
    """Build the SARIF for one repository and upload it (or dry-run). Returns table rows."""
    repo = raw["repo"]
    name = repo_full_name(repo)
    url = repo.get("url") or ""
    sarif = build_sarif(raw, config["tool_name"])
    base_row = {"repository": name, "repository_url": url, "http_status": "", "message": ""}

    errors = validate_sarif(sarif)
    if errors:
        return [{**base_row, "file": "", "results": len(sarif["runs"][0]["results"]),
                 "status": "INVALID_SARIF", "message": "; ".join(errors[:5])}]

    rows = []
    chunks = split_sarif(sarif)
    for idx, chunk in enumerate(chunks, start=1):
        suffix = f".part{idx}" if len(chunks) > 1 else ""
        file_name = f"{safe_name(name)}{suffix}.sarif"
        body = json.dumps(chunk, ensure_ascii=False).encode()
        row = {**base_row, "file": file_name, "results": len(chunk["runs"][0]["results"])}

        if config["attach_sarif"]:
            file_entries.append(fileResult(file_name, json.dumps(chunk, indent=2, ensure_ascii=False)))

        if not url:
            row.update(status="SKIPPED", message="no repository URL in Prisma (CLI/CI repository)")
        elif config["dry_run"]:
            row.update(status="DRY_RUN", message=f"{len(body)} bytes")
        else:
            try:
                status, data = upload_sarif(config["collector"], url, body)
                ok = 200 <= status < 300
                row.update(
                    http_status=status,
                    status=data.get("status") or ("OK" if ok else "FAILED"),
                    message=response_message(data),
                )
                if not ok and row["status"] not in ("INGESTED_FAILED", "INVALID"):
                    row["status"] = "FAILED"
            except Exception as ex:  # keep processing the other repositories
                row.update(status="FAILED", message=str(ex)[:300])
        rows.append(row)
    return rows


UPLOADED_STATUSES = ("INGESTED", "PARTIALLY_VALID", "OK")


def build_not_uploaded(rows: list[dict], not_found: list[str]) -> list[dict]:
    """
    List what was not uploaded and why.

    DRY_RUN rows are excluded: they would be uploaded with no_dry_run=true.
    In dry-run mode the list therefore shows what will NOT be uploaded.
    """
    items = [
        {
            "repository": row["repository"],
            "file": row["file"],
            "results": row["results"],
            "repository_url": row["repository_url"],
            "status": row["status"],
            "reason": row["message"],
        }
        for row in rows
        if row["status"] not in UPLOADED_STATUSES + ("DRY_RUN",)
    ]
    items += [
        {
            "repository": name,
            "file": "",
            "results": 0,
            "repository_url": "",
            "status": "NOT_FOUND",
            "reason": "repository not found in Prisma Cloud",
        }
        for name in not_found
    ]
    return items


def build_summary(rows: list[dict], dry_run: bool, findings: int, repos: int,
                  not_uploaded: list[dict]) -> dict:
    statuses = [row["status"] for row in rows]
    return {
        "dry_run": dry_run,
        "repositories_with_findings": repos,
        "findings": findings,
        "files": len(rows),
        "ingested": sum(s in UPLOADED_STATUSES for s in statuses),
        "skipped": statuses.count("SKIPPED"),
        "dry_run_files": statuses.count("DRY_RUN"),
        "failed": sum(s not in UPLOADED_STATUSES + ("SKIPPED", "DRY_RUN") for s in statuses),
        "not_uploaded": len(not_uploaded),
        "not_uploaded_findings": sum(item["results"] for item in not_uploaded),
    }


def build_readable(summary: dict, rows: list[dict], not_uploaded: list[dict]) -> str:
    mode = "DRY-RUN (nothing uploaded; set no_dry_run=true to upload)" if summary["dry_run"] else "UPLOAD"
    output = (
        f"## Prisma Cloud SAST to Cortex Cloud\n"
        f"**Mode:** {mode}\n\n"
        f"**Repositories with findings:** {summary['repositories_with_findings']} | "
        f"**Findings:** {summary['findings']} | **SARIF files:** {summary['files']}\n\n"
        f"**Ingested:** {summary['ingested']} | **Skipped (no URL):** {summary['skipped']} | "
        f"**Dry-run:** {summary['dry_run_files']} | **Failed:** {summary['failed']}\n"
    )
    if not_uploaded:
        title = (
            "Repositories that will NOT be uploaded"
            if summary["dry_run"] else "Repositories not uploaded"
        )
        output += "\n" + tableToMarkdown(
            f"{title} ({summary['not_uploaded']}, {summary['not_uploaded_findings']} findings)",
            not_uploaded,
            headers=["repository", "results", "status", "reason", "repository_url"],
            removeNull=False,
        )
    else:
        output += "\n**All repositories were uploaded (or will be, in dry-run).**\n"
    headers = ["repository", "results", "status", "http_status", "repository_url", "message"]
    output += "\n" + tableToMarkdown("All repositories", rows, headers=headers, removeNull=False)
    return output


def main():
    """Main entry point."""
    try:
        config = parse_args()
        client = PrismaClient(
            config["prisma_api_url"], config["prisma_access_key_id"], config["prisma_secret_key"]
        )

        grouped, not_found = collect_findings(client, config["repositories"])
        findings = sum(len(g["open"]) + len(g["suppressed"]) for g in grouped.values())
        demisto.debug(f"{len(grouped)} repositories with findings, {findings} findings")

        rows: list[dict] = []
        file_entries: list = []
        for raw in sorted(grouped.values(), key=lambda g: repo_full_name(g["repo"]).lower()):
            rows.extend(process_repository(raw, config, file_entries))

        not_uploaded = build_not_uploaded(rows, not_found)
        summary = build_summary(rows, config["dry_run"], findings, len(grouped), not_uploaded)
        result = CommandResults(
            outputs_prefix=CONTEXT_PREFIX,
            outputs={"Summary": summary, "Repository": rows, "NotUploaded": not_uploaded},
            readable_output=build_readable(summary, rows, not_uploaded),
            raw_response={"summary": summary, "repositories": rows, "not_uploaded": not_uploaded},
        )
        return_results([result] + file_entries)

    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f"PrismaSastToCortex failed: {str(ex)}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
