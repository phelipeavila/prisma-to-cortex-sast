# Prisma Cloud SAST to Cortex Cloud

`prisma_sast_to_cortex.py` copies SAST findings (Code Weaknesses) from Prisma Cloud Application Security into Cortex Cloud.

For every Prisma repository, the script does three things:

1. It downloads every SAST weakness on the default branch, both open and suppressed.
2. It converts them into one SARIF 2.1.0 file per repository.
3. It uploads each file to Cortex Cloud through the **3rd Party AppSec Collector** data source.

The script uses only the Python standard library, so there is nothing to install.

> **Safe by default:** the script runs in **dry-run** mode and sends nothing to Cortex. Add `--no-dry-run` to upload.

> **Running inside Cortex Cloud / XSOAR?** Use the automation script in [`cortex_script/`](cortex_script/README.md). It can run from playbooks, takes credentials as arguments, and has no pre-check or repo map.

---

## Project layout

| Path | Description |
|---|---|
| `prisma_sast_to_cortex.py` | Local script (this README) |
| `cortex_script/` | The same migration as a Cortex Cloud / XSOAR automation script, with its own [README](cortex_script/README.md) |
| `.env` | Your settings and credentials. Not versioned. |
| `repo_map.csv` | Optional manual repository mapping. Not versioned. |
| `output/` | Generated files: raw findings, SARIF, summaries. Not versioned. |
| `.gitignore` | Keeps secrets and customer data out of git |

---

## Requirements

- Python 3.10 or later.
- A Prisma Cloud access key that can read Application Security data.
- A **3rd Party AppSec Collector** that already exists in Cortex Cloud. The script does not create it. See [Create the collector](#1-create-the-collector-in-cortex).
- The target repositories must already be onboarded in Cortex Cloud. Cortex rejects findings for repositories it does not know.
- Optional, only for `--precheck`: a Cortex tenant API key that can read Application Security repositories.

---

## Setup

### 1. Create the collector in Cortex

1. In Cortex Cloud, open **Settings → Data Sources & Integrations** and add a **3rd Party AppSec Collector**.
2. Set these fields:
   - **Collector name:** `PrismaCloudSAST`. It must match the SARIF tool name. You can change it with `--tool-name`.
   - **Detection method:** SAST
   - **File type:** SARIF
3. Click **Generate API key** and write down the **Token ID** and the **API Token**. Cortex shows them only once.
4. Click **Copy API URL**. The URL looks like `https://api-<tenant>.xdr.<region>.paloaltonetworks.com/public_api/appsec/v1/collectors/<id>`.

### 2. Create the `.env` file

All settings go in one `.env` file next to the script, in `KEY=VALUE` format with one variable per line. Values may be wrapped in quotes, and lines that start with `#` are comments. To use a different file, pass `--env-file PATH`.

```ini
# --- Prisma Cloud (source) ------------------------------------------------
# Required by the 'fetch' stage. The access key must be able to read
# Application Security data.
PRISMA_API_URL=https://api2.prismacloud.io
PRISMA_ACCESS_KEY_ID=<prisma access key id>
PRISMA_SECRET_KEY=<prisma secret key>

# --- Cortex Cloud: 3rd Party AppSec Collector (destination) ---------------
# Required for a real upload (--no-dry-run). Use the values from step 1.
CORTEX_COLLECTOR_URL=https://api-<tenant>.xdr.<region>.paloaltonetworks.com/public_api/appsec/v1/collectors/<id>
CORTEX_COLLECTOR_TOKEN_ID=<collector Token ID>
CORTEX_COLLECTOR_TOKEN=<collector API Token>

# --- Cortex Cloud: tenant API key (optional) ------------------------------
# Only used by --precheck to list the repositories onboarded in Cortex.
CORTEX_API_URL=https://api-<tenant>.xdr.<region>.paloaltonetworks.com
CORTEX_API_KEY_ID=<tenant API key id>
CORTEX_API_KEY=<tenant API key>
```

| Variable | Needed for | Where to find it |
|---|---|---|
| `PRISMA_API_URL` | `fetch` | Prisma Cloud API URL for your stack, for example `https://api2.prismacloud.io` |
| `PRISMA_ACCESS_KEY_ID`, `PRISMA_SECRET_KEY` | `fetch` | Prisma Cloud → Settings → Access Keys |
| `CORTEX_COLLECTOR_URL` | upload with `--no-dry-run` | Collector → **Copy API URL** |
| `CORTEX_COLLECTOR_TOKEN_ID`, `CORTEX_COLLECTOR_TOKEN` | upload with `--no-dry-run` | Collector → **Generate API key** |
| `CORTEX_API_URL`, `CORTEX_API_KEY_ID`, `CORTEX_API_KEY` | `--precheck` only | Cortex → Settings → API Keys (**Copy API URL** and the key) |

An environment variable with the same name overrides the value in the file. This lets CI/CD pipelines pass secrets without a `.env` file:

```bash
export CORTEX_COLLECTOR_TOKEN=...   # takes precedence over .env
```

> `.env` contains secrets. Do not commit it to version control. The `.gitignore` already excludes it.

---

## Usage

### Full pipeline (default)

Run without a subcommand to execute fetch, then sarif, then upload.

```bash
# Dry-run (default): fetches and builds SARIF files, shows what would be uploaded
python3 prisma_sast_to_cortex.py

# Same, but also check which repositories are onboarded in Cortex
python3 prisma_sast_to_cortex.py --precheck

# Real upload
python3 prisma_sast_to_cortex.py --precheck --no-dry-run

# Only some repositories (repeat --repo for each one)
python3 prisma_sast_to_cortex.py --repo owner/name --no-dry-run
```

### Running a single stage

Each stage reads the previous stage's output from disk, so you can run and check them one at a time. Put the stage options after the subcommand. The global options `--env-file`, `--output-dir` and `-v` work either before or after it.

```bash
python3 prisma_sast_to_cortex.py fetch  [--repo OWNER/NAME]
python3 prisma_sast_to_cortex.py sarif  [--repo OWNER/NAME] [--tool-name NAME]
python3 prisma_sast_to_cortex.py upload [--repo OWNER/NAME] [--precheck] [--no-dry-run]
```

| Stage | Reads | Writes |
|---|---|---|
| `fetch` | Prisma Cloud API | `output/raw/repositories.json`, `output/raw/<owner>__<repo>.json` |
| `sarif` | `output/raw/` (no network) | `output/sarif/<owner>__<repo>.sarif` |
| `upload` | `output/sarif/`, `repo_map.csv` | Cortex collector, `output/summary.csv` |

`fetch` writes a raw file only for repositories that have findings. A full run, without `--repo`, also deletes files left over from earlier runs, so outdated data is never uploaded.

### Options

| Option | Default | Description |
|---|---|---|
| `--repo OWNER/NAME` | all repositories | Limit to one Prisma repository. Repeatable. Use the name shown by Prisma, for example `123456789012345678_owner/repo` for CLI repositories. |
| `--dry-run` / `--no-dry-run` | dry-run | Upload for real only with `--no-dry-run`. |
| `--precheck` | off | List the Cortex repositories first and skip the ones that are not onboarded. Needs the `CORTEX_API_*` settings. |
| `--tool-name` | `PrismaCloudSAST` | Value for SARIF `tool.driver.name`. Must match the collector name. |
| `--repo-map` | `repo_map.csv` | Manual mapping from Prisma repositories to Cortex repositories. |
| `--env-file` | `.env` | Settings file. |
| `--output-dir` | `output` | Folder for all generated files. |
| `-v`, `--verbose` | off | Debug logging. |

---

## Repository matching

Cortex identifies a repository by `repository_url` or `repository_id`, and the repository must already be onboarded in Cortex. The script picks the target in this order:

1. The row in **`repo_map.csv`** for that repository, if there is one.
2. The **repository URL reported by Prisma**. Repositories connected through a VCS integration have one. CLI, GitHub Actions and similar repositories do not.
3. If neither exists, the repository is **skipped**. It is listed in `output/repo_map_missing.csv`, which is ready to fill in and save as `repo_map.csv`.

### `repo_map.csv`

```csv
prisma_repository,repository_url,repository_id
123456789012345678_owner/repo,https://github.com/owner/repo,
123456789012345678_org/other-repo,,<cortex repository asset id (sha256)>
```

- `prisma_repository` is the repository name exactly as Prisma shows it.
- `repository_url` is the repository URL in Cortex.
- `repository_id` is the Cortex repository asset id. Use it for Cortex repositories that have no URL, such as GitHub Actions or Jenkins.

Fill in either `repository_url` or `repository_id`.

### Pre-check (`--precheck`)

With `--precheck`, the script first lists the repositories onboarded in Cortex. Then, for each Prisma repository:

- **Exact match** by URL or id: the file is uploaded using the Cortex `repository_id`. URL differences in case, a trailing `/` or a `.git` suffix do not matter.
- **No match:** the repository is marked `NOT_ONBOARDED` and is not uploaded. If the script finds candidates with the same owner and name, it writes them to `output/repo_map_suggested.csv`. For CLI repositories, the numeric Prisma tenant prefix is removed before comparing. Review the candidates and copy the correct rows into `repo_map.csv`.

> If two Prisma repositories map to the same Cortex repository, the second upload probably replaces the first. Map only one of them.

---

## SARIF mapping

| Prisma field | SARIF |
|---|---|
| `violationId` (for example `BC_SAST_161`) | `rule.id` and `result.ruleId` |
| `policy` | rule name, descriptions and `result.message` |
| `severity` | `result.level` and `properties.severity` (original value) and `properties.security-severity` |
| `cwes`, `owasp`, `labels` | `rule.properties.tags` (for example `CWE-208`, `A03:2021-Injection`, `OWASP top 10`) |
| `path` | `physicalLocation.artifactLocation.uri` |
| `codeIssueLine` (`"36"` or `"17-27"`) | `region.startLine` / `region.endLine` |
| `dataFlow` (source and sink) | `result.codeFlows` |
| policy documentation link | `rule.helpUri` (built-in policies only) |
| repository URL and default branch | `run.versionControlProvenance` |
| suppressed findings | `result.suppressions` (`kind: external`) |

Severity maps to SARIF `level` and `security-severity` as follows:

| Prisma | `level` | `security-severity` |
|---|---|---|
| CRITICAL | `error` | 9.5 |
| HIGH | `error` | 8.0 |
| MEDIUM | `warning` | 5.5 |
| LOW | `note` | 3.0 |
| INFO | `note` | 0.0 |

Each result has a stable `partialFingerprints.prismaFindingHash/v1`. It is built from the repository, policy, path, lines and data flow. When Prisma reports fully identical records, an occurrence index keeps them apart, so no finding is dropped as a duplicate.

---

## Output files

| File | Content |
|---|---|
| `output/raw/repositories.json` | Every repository returned by Prisma |
| `output/raw/<owner>__<repo>.json` | Raw weaknesses per repository: `{repo, open, suppressed}` |
| `output/sarif/<owner>__<repo>.sarif` | SARIF file to upload. Split into `.partN.sarif` above 10 MB. |
| `output/summary.csv` | One row per repository: `repository`, `file`, `results`, `repository_url`, `repository_id`, `http_status`, `status`, `message` |
| `output/repo_map_missing.csv` | Repositories with no URL, ready to fill in as `repo_map.csv` |
| `output/repo_map_suggested.csv` | `--precheck` candidates to review |

### Upload statuses in `summary.csv`

| Status | Meaning |
|---|---|
| `INGESTED` | Accepted. The findings show up in Cortex after a few minutes. |
| `PARTIALLY_VALID` | Accepted, but some results were rejected. Check the message. |
| `INGESTED_FAILED` / `INVALID` | Rejected (HTTP 400). The most common cause is `Repository with URL ... not found`, which means the repository is not onboarded in Cortex. |
| `NOT_ONBOARDED` | `--precheck` did not find the repository in Cortex. Nothing was sent. |
| `SKIPPED` | No repository URL or mapping. Nothing was sent. |
| `DRY_RUN` | Dry-run mode. Nothing was sent. |

---

## Recommended workflow

1. Run `python3 prisma_sast_to_cortex.py --precheck` (dry-run) and review `output/summary.csv`.
2. Test one SARIF file with the collector's **Test** action in the Cortex console. You should get `VALID`.
3. Fill in `repo_map.csv` from `output/repo_map_missing.csv` and `output/repo_map_suggested.csv` as needed.
4. Upload one repository: `python3 prisma_sast_to_cortex.py --repo owner/name --precheck --no-dry-run`. Then check the findings in Cortex under **Application Security → Code Weaknesses**.
5. Run everything: `python3 prisma_sast_to_cortex.py --precheck --no-dry-run`.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `Missing settings for ...` | A required variable is not in `.env` or in the environment. The message lists the missing variables. |
| `Invalid <NAME>_URL in .env: ...` | The URL is malformed: it does not start with `https://`, or its host name is broken. A common cause is a key or token pasted into the URL line, or two variables merged onto one line. The message never prints the value. |
| HTTP 401/403 on upload | Wrong `CORTEX_COLLECTOR_TOKEN_ID` or `CORTEX_COLLECTOR_TOKEN`. Generate a new key in the collector settings. |
| HTTP 403 `Insufficient permissions for api key` on `--precheck` | The tenant API key (`CORTEX_API_KEY`) cannot read Application Security repositories. |
| `Repository with URL ... not found` | The repository is not onboarded in Cortex, or its URL is different there. Use `--precheck` and `repo_map.csv`. |
| HTTP 503 | The collector is disabled in Cortex. |
| Slow fetch | Each repository takes two API calls (open and suppressed). Use `--repo` for quick tests. |
