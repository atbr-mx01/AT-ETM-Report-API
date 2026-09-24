#!/usr/bin/env python3
"""
Qualys ETM - Findings report automation
=======================================

Flow (same as the ETM-Report Postman collection):
  1. POST /auth                                  -> asks for username/password, gets the JWT token
  2. POST /etm/api/rest/v1/reports/findings      -> asks for the findings QQL (+ optional asset QQL)
  3. GET  /etm/api/rest/v1/reports/{id}          -> polls the status until it is COMPLETED
  4. GET  /etm/api/rest/v1/reports/{id}/download -> downloads the report (ZIP with JSON part files)
  5. Saves the JSON exactly as received (byte-for-byte, no changes) and a CSV copy with the
     same records, then verifies that the CSV holds the same data as the JSON.

CSV notes
  * Every date is written in ONE format: YYYY-MM-DD HH:MM:SS (UTC by default, or your local time
    with --date-tz local). This covers epoch-millisecond numbers such as lastFound / firstFound /
    lastUpdated (which Excel otherwise shows as 1.75591E+12) and ISO text dates.
  * Everything else is copied exactly as in the JSON.

Rate limits / temporary errors
  * HTTP 429, 502, 503, 504 and network drops are retried automatically after 2 minutes
    (change with --retry-wait / --max-retries). The run does not stop on the first 429.

Requirements:  pip install requests
Usage:         python etm_report.py
               python etm_report.py --qql "finding.severity:[5]" --asset-qql "asset.tag.name:`Production`"

Files needed in the same folder: etm_report.py, etm_qql.py (and etm_report_web.py for the page)
"""

import argparse
import csv
import getpass
import io
import json
import os
import re
import sys
import time
import zipfile
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import etm_qql  # QQL token check (etm_qql.py, same folder)

try:
    import requests
except ImportError:
    sys.exit("The 'requests' package is required. Install it with:  pip install requests")

DEFAULT_BASE_URL = "https://gateway.qg2.apps.qualys.com"
DEFAULT_QQL = ("finding.riskFactor.rti:Cisa_Known_Exploited_Vulns and "
               "finding.severity:[5] and finding.status:NEW")

SUCCESS_STATUSES = {"COMPLETED", "COMPLETE", "SUCCESS", "SUCCEEDED", "FINISHED", "DONE"}
FAILED_STATUSES = {"FAILED", "FAILURE", "ERROR", "CANCELLED", "CANCELED", "EXPIRED", "ABORTED"}
UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")

# Settings the web page can change too
RETRY_WAIT = 120          # seconds to wait after a 429 / temporary error
MAX_RETRIES = 5           # how many times to retry the same call
RETRY_CODES = {429, 502, 503, 504}
DATE_TZ = "utc"           # "utc" or "local"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
WAIT_HOOK = None          # optional callback(seconds, reason, attempt, max) used by the web page
CANCEL_CHECK = None       # optional callback() -> True to stop waiting (web page "Stop" button)


def log(msg):
    print(f"[{datetime.now():%H:%M:%S}] {msg}", flush=True)


def fail(msg, response=None):
    if response is not None:
        msg += f"\n  HTTP {response.status_code}: {response.text[:1000]}"
    sys.exit(f"ERROR: {msg}")


# ----------------------------------------------------------------------------------------------
# HTTP with automatic retry on 429 / temporary errors
# ----------------------------------------------------------------------------------------------
def _retry_after(response):
    try:
        return int(response.headers.get("Retry-After", ""))
    except (TypeError, ValueError):
        return 0


def request(session, method, url, what, **kwargs):
    """Send a request; on 429/502/503/504 or a network drop, wait RETRY_WAIT seconds and retry."""
    attempt = 0
    while True:
        try:
            r = session.request(method, url, **kwargs)
            if r.status_code not in RETRY_CODES:
                return r
            reason = ("Qualys rate limit reached (HTTP 429)" if r.status_code == 429
                      else f"Qualys temporarily unavailable (HTTP {r.status_code})")
            wait = max(RETRY_WAIT, _retry_after(r))
        except (requests.ConnectionError, requests.Timeout) as e:
            r, reason, wait = None, f"Network problem ({e.__class__.__name__})", RETRY_WAIT

        attempt += 1
        if attempt > MAX_RETRIES:
            if r is not None:
                fail(f"{what}: still failing after {MAX_RETRIES} retries.", r)
            fail(f"{what}: network still failing after {MAX_RETRIES} retries.")
        resume_at = datetime.now().timestamp() + wait
        log(f"  {reason} while trying to {what.lower()}. Waiting {wait // 60}m {wait % 60:02d}s, "
            f"retrying at {datetime.fromtimestamp(resume_at):%H:%M:%S} (retry {attempt}/{MAX_RETRIES})...")
        if WAIT_HOOK:
            WAIT_HOOK(resume_at, reason, attempt, MAX_RETRIES)
        time.sleep(wait)
        if WAIT_HOOK:
            WAIT_HOOK(None, None, attempt, MAX_RETRIES)


# ----------------------------------------------------------------------------------------------
# Step 1 - Token
# ----------------------------------------------------------------------------------------------
def generate_token(session, base_url, username, password):
    log("Step 1/4 - Generating token...")
    r = request(session, "POST", f"{base_url}/auth", "Generate the token",
                data={"username": username, "password": password, "token": "true"},
                headers={"Content-Type": "application/x-www-form-urlencoded"}, timeout=60)
    if r.status_code not in (200, 201):
        fail("Could not generate the token (check username/password and platform URL).", r)
    token = r.text.strip().strip('"')
    if not token:
        fail("The /auth call succeeded but returned an empty token.", r)
    log("Token generated.")
    return token


# ----------------------------------------------------------------------------------------------
# Step 2 - Create the findings report
# ----------------------------------------------------------------------------------------------
def _find_report_id(data):
    """Look for the report id in the create-report response, whatever its exact shape."""
    if isinstance(data, str):
        m = UUID_RE.search(data)
        return m.group(0) if m else None
    if isinstance(data, dict):
        for key in ("reportId", "reportID", "report_id", "id", "uuid", "reportUuid"):
            if key in data and isinstance(data[key], (str, int)) and str(data[key]).strip():
                return str(data[key])
        for value in data.values():
            found = _find_report_id(value)
            if found:
                return found
    if isinstance(data, list):
        for value in data:
            found = _find_report_id(value)
            if found:
                return found
    return None


def create_report(session, base_url, qql, asset_qql=None, name=None, description=None):
    log("Step 2/4 - Requesting findings report...")
    body = {"reportFormat": "JSON"}
    if name:
        body["name"] = name
    if description:
        body["description"] = description
    if asset_qql:
        body["assetQql"] = asset_qql
        log(f"  Asset QQL:    {asset_qql}")
    if qql:
        body["findingsQql"] = qql
        log(f"  Findings QQL: {qql}")
    r = request(session, "POST", f"{base_url}/etm/api/rest/v1/reports/findings",
                "Create the report", json=body,
                headers={"Accept": "application/json", "X-Requested-With": "Python"}, timeout=120)
    if r.status_code not in (200, 201, 202):
        fail("The report could not be created (check the QQL).", r)
    try:
        data = r.json()
    except ValueError:
        data = r.text
    report_id = _find_report_id(data)
    if not report_id:
        fail(f"Report created but no report id found in the response: {r.text[:1000]}")
    log(f"Report requested. Report ID: {report_id}")
    return report_id


# ----------------------------------------------------------------------------------------------
# Step 3 - Poll the status
# ----------------------------------------------------------------------------------------------
def _find_status(data):
    if isinstance(data, dict):
        for key in ("status", "reportStatus", "state"):
            if key in data and isinstance(data[key], str):
                return data[key]
        for value in data.values():
            found = _find_status(value)
            if found:
                return found
    if isinstance(data, list):
        for value in data:
            found = _find_status(value)
            if found:
                return found
    return None


def wait_for_report(session, base_url, report_id, interval, timeout):
    log("Step 3/4 - Checking report status...")
    started = time.time()
    deadline = started + timeout
    last_status, noted = None, False
    while True:
        if CANCEL_CHECK and CANCEL_CHECK():
            fail(f"Stopped by user while waiting. Report ID: {report_id} (you can resume it later).")
        r = request(session, "GET", f"{base_url}/etm/api/rest/v1/reports/{report_id}",
                    "Read the report status", headers={"Accept": "application/json"}, timeout=60)
        if r.status_code != 200:
            fail("Could not read the report status.", r)
        try:
            status = _find_status(r.json())
        except ValueError:
            status = None
        status_norm = (status or "UNKNOWN").strip().upper()
        elapsed = int(time.time() - started)
        log(f"  Status: {status_norm}  (waiting {elapsed // 60}m {elapsed % 60:02d}s)")
        if status_norm != last_status:
            last_status, noted = status_norm, False
        if status_norm in ("REQUESTED", "QUEUED") and elapsed >= 300 and not noted:
            noted = True
            log(f"  Note: Qualys has not started building the report yet (still {status_norm}). "
                f"This is on the Qualys side; checking continues until the {timeout // 60} min limit.")

        if status_norm in SUCCESS_STATUSES:
            log("Report is completed.")
            return
        if status_norm in FAILED_STATUSES:
            fail(f"The report ended with status {status_norm}.", r)
        if time.time() >= deadline:
            fail(f"Timed out after {timeout}s waiting for the report (last status: {status_norm}). "
                 f"You can re-run later with --report-id {report_id}")
        for _ in range(interval):  # sleep in 1s steps so Stop reacts quickly
            if CANCEL_CHECK and CANCEL_CHECK():
                break
            time.sleep(1)


# ----------------------------------------------------------------------------------------------
# Step 4 - Download, save JSON (unchanged) and CSV
# ----------------------------------------------------------------------------------------------
def download_report(session, base_url, report_id):
    log("Step 4/4 - Downloading report...")
    r = request(session, "GET", f"{base_url}/etm/api/rest/v1/reports/{report_id}/download",
                "Download the report", timeout=600)
    if r.status_code != 200:
        fail("Could not download the report.", r)
    filename = None
    m = re.search(r'filename="?([^";]+)"?', r.headers.get("Content-Disposition", ""))
    if m:
        filename = os.path.basename(m.group(1))
    log(f"Downloaded {len(r.content):,} bytes.")
    return r.content, filename


def extract_json_parts(content):
    """Return [(name, raw_bytes)] of the JSON files. The API returns a ZIP of part_*.json files;
    a plain JSON response is also supported."""
    if content[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(content)) as z:
            names = sorted(n for n in z.namelist() if n.lower().endswith(".json"))
            if not names:
                fail(f"The downloaded ZIP has no JSON files: {z.namelist()}")
            return [(os.path.basename(n), z.read(n)) for n in names]
    return [("report.json", content)]


def _records_from(data):
    """Get the list of findings from a parsed JSON part without changing anything."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        list_values = [v for v in data.values() if isinstance(v, list)]
        if len(list_values) == 1 and all(isinstance(x, dict) for x in list_values[0]):
            return list_values[0]  # e.g. {"data": [ ...findings... ]}
        return [data]
    return [{"value": data}]


# ---- dates -----------------------------------------------------------------------------------
class JsonFloat(str):
    """A JSON decimal number, kept as its exact text."""


# Date detection, per column:
#  1. by name: any word of the field name (camelCase / snake_case split) is date-like,
#     e.g. lastFound, firstSync, assetPublish, cvePublishedDate, sortTimestamp, createdAt
#  2. by value: every value in the column is an epoch-milliseconds number between 2000 and 2100
#     and the name doesn't look like an id / count / score (catches names we can't guess)
DATE_WORDS = {"date", "dates", "time", "times", "timestamp", "ts", "datetime", "found", "updated",
              "update", "created", "create", "modified", "seen", "scanned", "scan", "fixed",
              "expiry", "expires", "expiration", "expired", "detected", "closed", "opened",
              "published", "publish", "discovered", "remediated", "resolved", "since", "until",
              "sync", "synced", "start", "started", "end", "ended", "epoch", "checked", "activity",
              "eol", "eos", "deleted", "ingested", "reopened", "last", "first"}
NOT_DATE_WORDS = {"id", "ids", "uuid", "count", "counts", "size", "number", "num", "score",
                  "qid", "port", "bytes", "total", "version", "risk", "severity"}
ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?$")
MS_MIN, MS_MAX = 946684800000, 4102444800000  # 2000-01-01 .. 2100-01-01 in epoch ms

try:  # allow very long text cells (long descriptions) when reading the CSV back
    csv.field_size_limit(sys.maxsize)
except OverflowError:
    csv.field_size_limit(2 ** 31 - 1)


def _words(key):
    k = key.rsplit(".", 1)[-1]
    return [w.lower() for w in re.findall(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+", k)]


def _name_is_date(key):
    words = _words(key)
    if not words or any(w in NOT_DATE_WORDS for w in words):
        return False
    if words[-1] in ("at", "on") and len(words) > 1:   # createdAt, fixedOn
        return True
    # "last"/"first" alone are not enough (lastScore); they need a date-ish partner or a number check
    strong = [w for w in words if w in DATE_WORDS and w not in ("last", "first")]
    return bool(strong)


def _is_number(v):
    return isinstance(v, (int, JsonFloat)) and not isinstance(v, bool)


def _date_columns(raw_rows):
    """Decide which columns hold epoch dates (numbers)."""
    by_col = {}
    for row in raw_rows:
        for k, v in row.items():
            if v is not None:
                by_col.setdefault(k, []).append(v)
    cols = set()
    for k, values in by_col.items():
        nums = [v for v in values if _is_number(v)]
        if not nums or len(nums) != len(values):
            continue
        if _name_is_date(k):
            cols.add(k)
        elif (not any(w in NOT_DATE_WORDS for w in _words(k))
              and all(MS_MIN <= float(v) < MS_MAX for v in nums)):
            cols.add(k)
    return cols


def _fmt(dt):
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc) if DATE_TZ == "utc" else dt.astimezone()
    return dt.strftime(DATE_FORMAT)


def _as_date(value, date_column):
    """Return the formatted date if value is a date, else None."""
    if _is_number(value) and date_column:
        n = float(value)
        if 1e11 <= n < 1e13:        # epoch milliseconds (1973 - 2286)
            n /= 1000
        elif not 1e8 <= n < 1e10:   # epoch seconds (1973 - 2286); 0 and others stay as they are
            return None
        return _fmt(datetime.fromtimestamp(n, tz=timezone.utc))
    if isinstance(value, str) and not isinstance(value, JsonFloat) and ISO_RE.match(value.strip()):
        s = value.strip().replace(" ", "T", 1).replace("Z", "+00:00")
        s = re.sub(r"(\.\d{6})\d+", r"\1", s)                       # max 6 decimals
        s = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", s)             # +0000 -> +00:00
        try:
            return _fmt(datetime.fromisoformat(s))
        except ValueError:
            return None
    return None


def _cell(key, value, date_cols, stats):
    """Convert a JSON value to CSV text. Dates get one consistent format, everything else as-is
    (except hidden NUL characters, which CSV readers and Excel can't handle)."""
    date = _as_date(value, key in date_cols)
    if date is not None:
        stats["dates"] = stats.get("dates", 0) + 1
        stats.setdefault("date_columns", set()).add(key)
        return date
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        text = value
    elif isinstance(value, int):
        return str(value)
    else:  # lists are kept as their full JSON text so no data is lost
        text = json.dumps(value, ensure_ascii=False, default=str)
    if "\x00" in text:
        stats["nul"] = stats.get("nul", 0) + text.count("\x00")
        stats.setdefault("nul_columns", set()).add(key)
        text = text.replace("\x00", "")
    return text


def _flatten_raw(obj, prefix=""):
    """Nested objects become dotted columns (e.g. asset.name); values stay as parsed JSON."""
    flat = {}
    if isinstance(obj, dict) and obj:
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, dict) and v:
                flat.update(_flatten_raw(v, key))
            else:
                flat[key] = v
    else:
        flat[prefix or "value"] = obj
    return flat


def build_rows(records):
    """Return (rows as text dicts, columns in order, stats)."""
    raw_rows = [_flatten_raw(rec) for rec in records]
    date_cols = _date_columns(raw_rows)
    stats = {}
    rows = [{k: _cell(k, v, date_cols, stats) for k, v in r.items()} for r in raw_rows]
    columns, seen = [], set()
    for row in rows:
        for col in row:
            if col not in seen:
                seen.add(col)
                columns.append(col)
    return rows, columns, stats


def _load(raw):
    # decimals are kept as their exact text from the file (no float rounding or reformatting)
    return json.loads(raw.decode("utf-8-sig"), parse_float=JsonFloat)


def save_outputs(parts, out_dir, base_name):
    os.makedirs(out_dir, exist_ok=True)

    # JSON copy: raw bytes exactly as delivered by Qualys
    json_paths = []
    for i, (_, raw) in enumerate(parts, 1):
        name = f"{base_name}.json" if len(parts) == 1 else f"{base_name}_part{i}.json"
        path = os.path.join(out_dir, name)
        with open(path, "wb") as f:
            f.write(raw)
        json_paths.append(path)

    # CSV copy: every record from every part
    records = []
    for _, raw in parts:
        records.extend(_records_from(_load(raw)))
    rows, columns, stats = build_rows(records)

    csv_path = os.path.join(out_dir, f"{base_name}.csv")
    with open(csv_path, "w", newline="", encoding="utf-8-sig") as f:  # BOM so Excel reads UTF-8
        writer = csv.DictWriter(f, fieldnames=columns, quoting=csv.QUOTE_ALL)
        writer.writeheader()
        for row in rows:
            writer.writerow({c: row.get(c, "") for c in columns})

    if stats.get("dates"):
        tz_label = "UTC" if DATE_TZ == "utc" else "local time"
        cols = ", ".join(sorted(stats["date_columns"]))
        log(f"  Dates formatted as YYYY-MM-DD HH:MM:SS ({tz_label}): {stats['dates']} values "
            f"in {len(stats['date_columns'])} columns ({cols})")
    if stats.get("nul"):
        log(f"  Removed {stats['nul']} hidden NUL characters (\\u0000) from CSV text in "
            f"{', '.join(sorted(stats['nul_columns']))}; they break CSV readers and Excel. "
            f"The JSON file still has them.")
    return json_paths, csv_path, rows, columns


def verify(json_paths, csv_path, columns):
    """Re-read both files from disk and confirm the CSV holds exactly the JSON data
    (with dates in the CSV date format)."""
    records = []
    for p in json_paths:
        with open(p, "rb") as f:
            records.extend(_records_from(_load(f.read())))
    expected, _, _ = build_rows(records)
    try:
        with open(csv_path, newline="", encoding="utf-8-sig") as f:
            actual = list(csv.DictReader(f))
    except csv.Error as e:
        return False, f"could not read the CSV back ({e})"

    if len(expected) != len(actual):
        return False, f"record count differs (JSON {len(expected)} vs CSV {len(actual)})"
    for i, (e, a) in enumerate(zip(expected, actual), 1):
        for col in columns:
            if e.get(col, "") != a.get(col, ""):
                return False, f"record {i}, column '{col}' differs"
    return True, f"{len(expected)} records x {len(columns)} columns match"


# ----------------------------------------------------------------------------------------------
def main():
    global RETRY_WAIT, MAX_RETRIES, DATE_TZ
    p = argparse.ArgumentParser(description="Generate and download a Qualys ETM findings report.")
    p.add_argument("--base-url", default=os.getenv("ETM_BASE_URL", DEFAULT_BASE_URL),
                   help=f"Qualys gateway URL (default: {DEFAULT_BASE_URL})")
    p.add_argument("--username", default=os.getenv("ETM_USERNAME"), help="Qualys username")
    p.add_argument("--qql", help="Findings QQL (asked interactively if omitted)")
    p.add_argument("--asset-qql", help="Asset QQL, e.g. to filter by tag (asked if omitted)")
    p.add_argument("--name", help="Report name (optional)")
    p.add_argument("--description", help="Report description (optional)")
    p.add_argument("--report-id", help="Skip creation and download an existing report id")
    p.add_argument("--output-dir", default="etm_reports", help="Folder for the output files")
    p.add_argument("--interval", type=int, default=15, help="Seconds between status checks")
    p.add_argument("--timeout", type=int, default=3600, help="Max seconds to wait for the report")
    p.add_argument("--retry-wait", type=int, default=RETRY_WAIT,
                   help="Seconds to wait before retrying after HTTP 429 or a temporary error (default 120)")
    p.add_argument("--max-retries", type=int, default=MAX_RETRIES,
                   help="How many times to retry the same call (default 5)")
    p.add_argument("--no-qql-check", action="store_true",
                   help="Skip the local QQL token check (Qualys still validates the query)")
    p.add_argument("--date-tz", choices=["utc", "local"], default="utc",
                   help="Time zone for dates in the CSV (default utc)")
    args = p.parse_args()
    base_url = args.base_url.rstrip("/")
    RETRY_WAIT, MAX_RETRIES, DATE_TZ = args.retry_wait, args.max_retries, args.date_tz

    # --- credentials ---
    print("=== Qualys ETM Findings Report ===")
    print(f"Platform: {base_url}\n")
    username = args.username or input("Username: ").strip()
    password = os.getenv("ETM_PASSWORD") or getpass.getpass("Password: ")
    if not username or not password:
        fail("Username and password are required.")

    # --- QQL (asked and checked before logging in, so typos don't cost an API call) ---
    report_id = args.report_id
    qql = asset_qql = None
    if not report_id:
        qql, asset_qql = args.qql, args.asset_qql
        interactive = qql is None or asset_qql is None
        while True:
            if args.qql is None:
                print(f"\nEnter the findings QQL (press Enter to use the default):\n  {DEFAULT_QQL}")
                print(f"  Finding tags: {etm_qql.TAG_TOKEN}:`TagName`")
                qql = input("Findings QQL: ").strip() or DEFAULT_QQL
            if args.asset_qql is None:
                print(f"\nEnter the asset QQL, e.g. {etm_qql.ASSET_TAG_TOKEN}:`Firewall Detected` "
                      "(press Enter for all assets):")
                asset_qql = input("Asset QQL: ").strip()
            if args.no_qql_check:
                break
            problems = etm_qql.check_all(qql, asset_qql)
            for label, key in (("Findings QQL", "findings"), ("Asset QQL", "asset")):
                for msg in problems["warnings"][key]:
                    print(f"  Warning - {label}: {msg}")
            if not problems["findings"] and not problems["asset"]:
                log("QQL token check: OK")
                break
            print("\nQQL problems found (token list: " + etm_qql.DOC_URL + "):")
            for label, key in (("Findings QQL", "findings"), ("Asset QQL", "asset")):
                for msg in problems[key]:
                    print(f"  - {label}: {msg}")
            if not interactive or (args.qql is not None and args.asset_qql is not None):
                fail("Fix the QQL, or use --no-qql-check to send it anyway.")
            print("Please enter the QQL again.")

    session = requests.Session()
    token = generate_token(session, base_url, username, password)
    session.headers["Authorization"] = f"Bearer {token}"  # used for every next call

    if not report_id:
        report_id = create_report(session, base_url, qql, asset_qql, args.name, args.description)

    # --- status ---
    wait_for_report(session, base_url, report_id, args.interval, args.timeout)

    # --- download + outputs ---
    content, _ = download_report(session, base_url, report_id)
    parts = extract_json_parts(content)
    base_name = f"Findings_Report_{report_id}_{datetime.now():%Y-%m-%d_%H%M%S}"
    json_paths, csv_path, rows, columns = save_outputs(parts, args.output_dir, base_name)

    ok, detail = verify(json_paths, csv_path, columns)
    print()
    log("Done.")
    for jp in json_paths:
        print(f"  JSON : {os.path.abspath(jp)}")
    print(f"  CSV  : {os.path.abspath(csv_path)}")
    print(f"  Records: {len(rows)}   Columns: {len(columns)}")
    print(f"  Check : {'OK - ' if ok else 'MISMATCH - '}{detail}")
    if not ok:
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\nCancelled by user.")
    except requests.RequestException as e:
        sys.exit(f"ERROR: network problem talking to Qualys: {e}")
