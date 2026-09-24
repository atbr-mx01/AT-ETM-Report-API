# AT-ETM-Report-API
Web interface with python script to login and generate reports in Qualys ETM

Generate a **Qualys Enterprise TruRisk Management (ETM)** findings report through the API and save it
as **JSON** (exactly as Qualys delivers it) and **CSV** (same data, with readable dates), from a local
web page or from the terminal.

It automates the same steps as the Postman collection:

1. **Token**: `POST /auth` with your username and password
2. **Request the report**: `POST /etm/api/rest/v1/reports/findings` with your Findings QQL and optional Asset QQL
3. **Wait for status**: `GET /etm/api/rest/v1/reports/{id}` until it is `COMPLETED`
4. **Download**: `GET /etm/api/rest/v1/reports/{id}/download`, then save the JSON and CSV

## Features

- **Local web page**: fill in credentials and QQL, press *Run report*, follow each step and download the files.
- **Asset tag helper**: adds `` asset.tag.name:`Tag` `` to the Asset QQL, with *and* / *or*.
- **QQL check before sending**: catches unknown tokens (with "did you mean" suggestions), unbalanced
  brackets and text without a token, so a typo doesn't cost you a failed report.
- **JSON copy is untouched**: saved byte-for-byte as Qualys sends it.
- **CSV copy**:
  - nested fields become dotted columns, e.g. `cve.cvss3Info.basescore`
  - lists are kept as JSON text
  - every date is written as `YYYY-MM-DD HH:MM:SS`, in UTC or your local time; this covers
    epoch-millisecond fields such as `lastFound`, `firstFound`, `lastSync` and `assetPublish`
  - a final check re-reads both files and confirms the CSV matches the JSON
- **Rate-limit safe**: on HTTP 429, 502, 503, 504 or a network drop, it waits (2 minutes by default)
  and retries instead of stopping.
- **Resume / Stop**: stop waiting at any time and resume the same report later using its report ID.
- **Count diagnosis**: `etm_diagnose.py` explains why a report has a different number of rows than
  the ETM console.

## Files

| File | What it does |
|---|---|
| `etm_report_web.py` | Local web page (recommended way to run it) |
| `etm_report.py` | The report logic; can also be run in the terminal |
| `etm_qql.py` | QQL token list and checker (from the ETM search-token docs) |
| `etm_diagnose.py` | Explains row-count differences between a report and the console |
| `requirements.txt` | Python dependency (`requests`) |

Keep all the `.py` files in the same folder.

## Requirements

- Python 3.9 or newer
- A Qualys account with ETM API access

## Installation (macOS / Linux)

```bash
git clone https://github.com/<your-user>/<your-repo>.git
cd <your-repo>

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

On Windows, activate the environment with `.venv\Scripts\activate` instead.

## Usage

### Web page (recommended)

```bash
source .venv/bin/activate
python etm_report_web.py
```

The browser opens at <http://127.0.0.1:8080>. Stop the page with **Ctrl + C** in the terminal.

The page only listens on `127.0.0.1`, so other machines can't open it. Your password is used only to
request the token: it is never saved, logged or written to disk.

| Option | Default | Description |
|---|---|---|
| `--port` | `8080` | Port for the page |
| `--output-dir` | `etm_reports` | Folder where the files are saved |
| `--no-browser` | | Don't open the browser automatically |

### Terminal

```bash
python etm_report.py
```

It asks for your username, password, Findings QQL and Asset QQL. Or pass them as options:

```bash
python etm_report.py \
  --qql "finding.riskFactor.rti:Cisa_Known_Exploited_Vulns and finding.status:NEW" \
  --asset-qql "asset.tag.name:\`Service Now\`"
```

| Option | Default | Description |
|---|---|---|
| `--base-url` | `https://gateway.qg2.apps.qualys.com` | Your Qualys platform gateway |
| `--username` | asked | Qualys username (or env `ETM_USERNAME`) |
| `--qql` | asked | Findings QQL |
| `--asset-qql` | asked | Asset QQL |
| `--name`, `--description` | | Optional report name / description |
| `--report-id` | | Skip creation and download an existing report |
| `--output-dir` | `etm_reports` | Output folder |
| `--interval` | `15` | Seconds between status checks |
| `--timeout` | `3600` | Maximum seconds to wait for the report |
| `--retry-wait` | `120` | Seconds to wait after HTTP 429 or a temporary error |
| `--max-retries` | `5` | Retries per call |
| `--date-tz` | `utc` | `utc` or `local`, for dates in the CSV |
| `--no-qql-check` | | Send the QQL without the local token check |

The password is always typed at a hidden prompt, or read from the `ETM_PASSWORD` environment variable.
It is never a command-line option.

## Output

Files go to `etm_reports/`, named after the report ID and the time of the run:

```
Findings_Report_<report-id>_<YYYY-MM-DD_HHMMSS>.json          # one part
Findings_Report_<report-id>_<YYYY-MM-DD_HHMMSS>_part1.json    # or several parts
Findings_Report_<report-id>_<YYYY-MM-DD_HHMMSS>.csv
```

- **JSON**: the file(s) from the Qualys ZIP, unchanged.
- **CSV**:
  - one row per finding, with all records from all parts
  - UTF-8 with BOM, so Excel shows accents correctly
  - dates formatted as described above
  - hidden NUL characters (`\u0000`) are removed from text, because they break CSV readers and
    Excel; the log says how many and where, and the JSON keeps them

Tip: Excel shows long numeric IDs in scientific notation. To keep them intact, import the CSV with
**Data → From Text/CSV** and set those columns to *Text*.

## QQL tips

- **Asset tags** (Asset QQL): `` asset.tag.name:`Firewall Detected` ``
- **Finding tags** (Findings QQL): `` finding.tags.name:`Wiz` ``
- **Values with spaces**: put them in backticks, e.g. `` finding.truConfirm.status:`Exploit Validated` ``
- **Several tags**: `` (asset.tag.name:`Prod` or asset.tag.name:`PCI`) ``
- **Token reference**: [Search Tokens for Findings](https://docs.qualys.com/en/etm/latest/search_tips/search_tokens_findings.htm)
- **API reference**: [Submit Finding Report Request](https://docs.qualys.com/en/etm/latest/mergedProjects/etm_apis/reports/submit_finding_report.htm)

If Qualys adds a token the checker doesn't know yet:

- add it to `EXTRA_TOKENS` in `etm_qql.py`, or
- tick **Skip token check** on the page, or use `--no-qql-check` in the terminal.

## Report count differs from the console?

```bash
python etm_diagnose.py --expect 275     # 275 = the number shown in the ETM console
```

It reads the latest report in `etm_reports/`, without contacting Qualys, and shows:

- rows per file and exact duplicate rows
- how many distinct values each ID-like field has
- breakdowns of status, type and similar fields

## Troubleshooting

| Message | What to do |
|---|---|
| `Invalid QQL token` (HTTP 400) | A token name is wrong. The page shows a suggestion. |
| `The report ended with status FAILED` | Usually a QQL value problem, such as text without a token or missing backticks. Fix it and run again, with the report ID field empty. |
| Status stays `REQUESTED` for a long time | Qualys hasn't started building the report yet. The page keeps checking until the timeout; use **Stop** and resume later if needed. |
| `HTTP 429` | Rate limit. It retries automatically after 2 minutes. |
| `Address already in use` | Port 8080 is taken: `python etm_report_web.py --port 9000` |
| `SSL: CERTIFICATE_VERIFY_FAILED` (macOS, python.org Python) | Run `Install Certificates.command` in `/Applications/Python 3.x/` |

## Security

- **Don't commit report output.** `etm_reports/`, report files and `.venv/` are listed in
  `.gitignore` because reports contain asset and vulnerability data.
- **Never put credentials in the code or the repository.** Type them in the page or prompt, or use
  environment variables.
