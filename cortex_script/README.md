# PrismaSastToCortex (Cortex Cloud / XSOAR script)

`PrismaSastToCortex` is an automation script that runs inside Cortex Cloud (or XSOAR). It moves SAST findings (Code Weaknesses) from Prisma Cloud into Cortex Cloud through the **3rd Party AppSec Collector**. You can run it by hand from the Playground or from a playbook.

This is the in-platform version of [`../prisma_sast_to_cortex.py`](../prisma_sast_to_cortex.py). It builds the same SARIF 2.1.0 output. It differs in four ways:

- Credentials are script **arguments**, not a `.env` file.
- There is no pre-check and no `repo_map.csv`. Repositories are matched only by the URL that Prisma reports.
- Nothing is written to disk. The results go to the War Room and to context. The SARIF files can be attached on request.
- It fetches all weaknesses for the tenant in a few paged API calls instead of two calls per repository. A full run takes seconds, so the default script timeout is enough.

> **Safe by default:** the script runs in **dry-run** mode and sends nothing to Cortex. Set `no_dry_run=true` to upload.

| File | Purpose |
|---|---|
| `PrismaSastToCortex.yml` | Ready to import into Cortex (code, arguments and outputs) |
| `PrismaSastToCortex.py` | The same code as a standalone file, for review or for pasting into the script editor |

> **Keep both files in sync.** The `script:` field of the `.yml` holds the full content of the `.py`. If you change the `.py`, update the `.yml` the same way before importing it again, or paste the new code into the Cortex script editor.

---

## Prerequisites

1. **A 3rd Party AppSec Collector in Cortex.** Go to Settings → Data Sources & Integrations → **3rd Party AppSec Collector** and set:
   - **Name:** `PrismaCloudSAST`. It must match the `tool_name` argument.
   - **Detection method:** SAST
   - **File type:** SARIF

   Then click **Copy API URL** and **Generate API key**. You get the URL, the Token ID and the API Token.
2. **A Prisma Cloud access key** that can read Application Security data.
3. **Repositories onboarded in Cortex.** Cortex rejects findings for repositories it does not know.
4. **Outbound HTTPS** from the script container to the Prisma Cloud API, for example `api2.prismacloud.io`, and to the Cortex API.

You do **not** need a Cortex tenant API key. The upload authenticates with the collector token alone.

---

## Import

**Option A: upload the YAML (recommended)**
1. Go to **Investigation & Response → Automation → Scripts**.
2. Click **Upload** (or **Import**) and select `PrismaSastToCortex.yml`.

**Option B: create the script by hand**
1. Click **+ New Script**, name it `PrismaSastToCortex` and set the language to Python 3.
2. Paste the contents of `PrismaSastToCortex.py`.
3. Create the arguments listed below. Mark the key and token arguments as **Secret** and mark `repositories` as **Is array**.
4. Set the Docker image to `demisto/python3:3.12.14.13053055`.

---

## Arguments

| Argument | Required | Default | Description |
|---|---|---|---|
| `prisma_api_url` | yes | none | Prisma Cloud API URL, for example `https://api2.prismacloud.io` |
| `prisma_access_key_id` | yes | none | Prisma Cloud access key id. Secret. |
| `prisma_secret_key` | yes | none | Prisma Cloud secret key. Secret. |
| `collector_url` | when `no_dry_run=true` | none | Collector API URL, in the form `.../public_api/appsec/v1/collectors/<id>` |
| `collector_token_id` | when `no_dry_run=true` | none | Collector Token ID. Secret. |
| `collector_token` | when `no_dry_run=true` | none | Collector API Token. Secret. |
| `no_dry_run` | no | `false` | `true` uploads to Cortex. `false` is a dry-run that sends nothing. |
| `repositories` | no | all | Prisma repository names (`owner/name`) to process. This is an array. |
| `tool_name` | no | `PrismaCloudSAST` | SARIF `tool.driver.name`. Must match the collector name. |
| `attach_sarif` | no | `false` | Attach the generated `.sarif` files to the War Room |

> Avoid typing keys as plain text in playbooks. Store them in **Settings → Credentials** and pass them to the script inputs from there. The arguments are marked `secret`, and the script never writes them to logs, the War Room or context.

---

## Usage

### Playground

Dry-run of everything, attaching the SARIF files for review:

```
!PrismaSastToCortex prisma_api_url=https://api2.prismacloud.io prisma_access_key_id=<id> prisma_secret_key=<secret> attach_sarif=true
```

Upload one repository:

```
!PrismaSastToCortex prisma_api_url=https://api2.prismacloud.io prisma_access_key_id=<id> prisma_secret_key=<secret> collector_url=<url> collector_token_id=<token id> collector_token=<token> repositories=owner/name no_dry_run=true
```

You can test an attached SARIF file with the collector's **Test** action. It should report `VALID`.

### Playbook

Add a task that runs **PrismaSastToCortex**, fill in the inputs (preferably from credentials), and set `no_dry_run` to `true`. Later tasks can read:

- `${PrismaSastToCortex.Summary.failed}`, for example to send a notification when it is greater than 0
- `${PrismaSastToCortex.NotUploaded}`, the repositories that were not uploaded and why (see [List of repositories not uploaded](#list-of-repositories-not-uploaded))
- `${PrismaSastToCortex.Repository}`, which has one entry per SARIF file

To keep Cortex in sync, run the playbook on a schedule, for example as a scheduled job.

---

## Output

The War Room shows the mode (DRY-RUN or UPLOAD), the totals, and a table with one row per repository.

| Context path | Type | Description |
|---|---|---|
| `PrismaSastToCortex.Summary.dry_run` | Boolean | `true` when nothing was uploaded |
| `PrismaSastToCortex.Summary.repositories_with_findings` | Number | Repositories with SAST findings in Prisma |
| `PrismaSastToCortex.Summary.findings` | Number | Total findings, open and suppressed |
| `PrismaSastToCortex.Summary.files` | Number | SARIF files generated |
| `PrismaSastToCortex.Summary.ingested` | Number | Files accepted by Cortex |
| `PrismaSastToCortex.Summary.skipped` | Number | Files skipped because the repository has no URL |
| `PrismaSastToCortex.Summary.dry_run_files` | Number | Files not sent because of dry-run |
| `PrismaSastToCortex.Summary.failed` | Number | Files rejected or failed |
| `PrismaSastToCortex.Summary.not_uploaded` | Number | Entries in `NotUploaded` |
| `PrismaSastToCortex.Summary.not_uploaded_findings` | Number | Findings in the entries that were not uploaded |
| `PrismaSastToCortex.Repository.repository` | String | Prisma repository name |
| `PrismaSastToCortex.Repository.file` | String | SARIF file name |
| `PrismaSastToCortex.Repository.results` | Number | Findings in the file |
| `PrismaSastToCortex.Repository.repository_url` | String | Repository URL used as the Cortex target |
| `PrismaSastToCortex.Repository.http_status` | Number | HTTP status of the upload |
| `PrismaSastToCortex.Repository.status` | String | See the status table below |
| `PrismaSastToCortex.Repository.message` | String | Message from Cortex, or the reason the file was skipped |
| `PrismaSastToCortex.NotUploaded.repository` | String | Repository that was not uploaded |
| `PrismaSastToCortex.NotUploaded.file` | String | SARIF file name. Empty for `NOT_FOUND`. |
| `PrismaSastToCortex.NotUploaded.results` | Number | Findings that were not uploaded |
| `PrismaSastToCortex.NotUploaded.repository_url` | String | Repository URL from Prisma. Empty when Prisma has none. |
| `PrismaSastToCortex.NotUploaded.status` | String | `SKIPPED`, `NOT_FOUND`, `FAILED`, `INGESTED_FAILED`, `INVALID` or `INVALID_SARIF` |
| `PrismaSastToCortex.NotUploaded.reason` | String | Why it was not uploaded |

### List of repositories not uploaded

`PrismaSastToCortex.NotUploaded` lists every repository whose findings did not reach Cortex, with the reason. The War Room shows the same list in its own table above the full table.

- **Upload mode** (`no_dry_run=true`): the list shows what was not uploaded. That covers repositories without a URL (`SKIPPED`), repositories rejected by Cortex (for example `INGESTED_FAILED` when the repository is not onboarded), HTTP or network errors (`FAILED`), and invalid SARIF.
- **Dry-run:** the list shows what **will not** be uploaded, such as repositories without a URL or with invalid SARIF. Repositories that would be sent (`DRY_RUN`) are left out. Cortex rejections such as "not onboarded" only show up in upload mode.
- Names given in `repositories` that do not exist in Prisma appear as `NOT_FOUND`.

In a playbook, you can use `${PrismaSastToCortex.NotUploaded}` to open a ticket or notify the team, for example when `${PrismaSastToCortex.Summary.not_uploaded}` is greater than 0.

| Status | Meaning |
|---|---|
| `INGESTED` | Accepted. Findings appear in Cortex after a few minutes. |
| `PARTIALLY_VALID` | Accepted, but some results were rejected. Check the message. |
| `INGESTED_FAILED` / `INVALID` | Rejected. `Repository with URL ... not found` means the repository is not onboarded in Cortex. |
| `FAILED` | HTTP or network error |
| `SKIPPED` | The repository has no URL in Prisma (CLI, GitHub Actions, Terraform Cloud, and so on). Nothing was sent. |
| `DRY_RUN` | Dry-run mode. Nothing was sent. |
| `INVALID_SARIF` | The generated SARIF failed local validation. Nothing was sent. |
| `NOT_FOUND` | The name given in `repositories` does not exist in Prisma. Appears only in `NotUploaded`. |

The SARIF mapping (severity, CWE and OWASP tags, data flows, fingerprints) is the same as in the local script. See the [main README](../README.md#sarif-mapping).

---

## Limitations

- **Repositories without a URL are skipped.** This version has no `repo_map`. To migrate those repositories, use the local script with `repo_map.csv`.
- **Uploads are matched by URL only.** If Cortex stores the repository under a different URL, the upload fails with `Repository with URL ... not found`. The local script's `--precheck` handles this by uploading by `repository_id`.
- If two Prisma repositories point to the same Cortex repository, the second upload probably replaces the first.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `Missing required arguments` | Provide `prisma_api_url`, `prisma_access_key_id` and `prisma_secret_key`. |
| `no_dry_run=true requires: ...` | Provide the three `collector_*` arguments. |
| `Invalid ..._url` | The URL must start with `https://`. Check that a key or token was not pasted into the URL. |
| `Prisma Cloud login failed (HTTP 401)` | Wrong Prisma access key or API URL for your stack. |
| HTTP 401/403 on upload | Wrong collector Token ID or API Token. Generate a new key in the collector settings. |
| HTTP 503 | The collector is disabled in Cortex. |
| Connection errors or timeouts | The script container cannot reach the Prisma or Cortex API. Check egress and proxy settings. |
