#!/usr/bin/env python3
"""
Qualys ETM - Findings report: local web page
============================================

Starts a small web page on YOUR computer (http://127.0.0.1:8080) to run the report:
fill in credentials + QQL, press "Run report", watch the progress, download JSON and CSV.

Requirements:  pip install requests
               etm_report.py must be in the same folder as this file.
Usage:         python etm_report_web.py            (opens the browser automatically)
               python etm_report_web.py --port 9000 --output-dir reports

Credentials are only kept in memory for the run and are never written to disk or logs.
The page only listens on 127.0.0.1, so it is not reachable from other machines.
"""

import argparse
import json
import os
import sys
import threading
import traceback
import uuid
import webbrowser
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import etm_report as etm
except ImportError:
    sys.exit("etm_report.py must be in the same folder as etm_report_web.py")

import requests
import etm_qql

JOBS = {}
RUN_LOCK = threading.Lock()
OUTPUT_DIR = "etm_reports"


# ----------------------------------------------------------------------------------------------
# Background run
# ----------------------------------------------------------------------------------------------
def run_job(job, params):
    def log(msg):
        job["logs"].append(f"[{datetime.now():%H:%M:%S}] {msg}")

    def on_wait(resume_at, reason, attempt, max_retries):
        job["waiting"] = (None if resume_at is None else
                          {"until": resume_at, "reason": reason,
                           "attempt": attempt, "max": max_retries})

    etm.log = log  # send the script's progress messages to the page
    etm.WAIT_HOOK = on_wait
    etm.CANCEL_CHECK = lambda: job.get("cancel", False)
    try:
        base_url = (params.get("base_url") or etm.DEFAULT_BASE_URL).strip().rstrip("/")
        interval = max(1, int(params.get("interval") or 15))
        timeout = max(60, int(params.get("timeout") or 3600))
        etm.RETRY_WAIT = max(10, int(params.get("retry_wait") or 120))
        etm.MAX_RETRIES = max(0, int(params.get("max_retries") or 5))
        etm.DATE_TZ = "local" if params.get("date_tz") == "local" else "utc"

        session = requests.Session()
        job["step"] = 1
        token = etm.generate_token(session, base_url, params["username"], params["password"])
        session.headers["Authorization"] = f"Bearer {token}"

        job["step"] = 2
        report_id = (params.get("report_id") or "").strip()
        if report_id:
            log(f"Using existing report ID: {report_id}")
        else:
            qql = (params.get("qql") or "").strip()
            asset_qql = (params.get("asset_qql") or "").strip()
            if not qql and not asset_qql:
                qql = etm.DEFAULT_QQL
            report_id = etm.create_report(
                session, base_url, qql, asset_qql,
                (params.get("name") or "").strip() or None,
                (params.get("description") or "").strip() or None)
        job["report_id"] = report_id

        job["step"] = 3
        etm.wait_for_report(session, base_url, report_id, interval, timeout)

        job["step"] = 4
        content, _ = etm.download_report(session, base_url, report_id)
        parts = etm.extract_json_parts(content)
        base_name = f"Findings_Report_{report_id}_{datetime.now():%Y-%m-%d_%H%M%S}"
        json_paths, csv_path, rows, columns = etm.save_outputs(parts, OUTPUT_DIR, base_name)
        ok, detail = etm.verify(json_paths, csv_path, columns)

        job["files"] = [os.path.abspath(p) for p in json_paths + [csv_path]]
        job["summary"] = {"records": len(rows), "columns": len(columns),
                          "check_ok": ok, "check": detail,
                          "folder": os.path.abspath(OUTPUT_DIR)}
        log(f"Saved {len(rows)} records. Check: {'OK' if ok else 'MISMATCH'} - {detail}")
        job["step"] = 5
        job["state"] = "done" if ok else "error"
        if not ok:
            job["error"] = f"CSV/JSON check failed: {detail}"
    except SystemExit as e:  # etm.fail() exits with the error text
        job["state"], job["error"] = "error", str(e).replace("ERROR: ", "", 1)
        job["report_failed"] = "The report ended with status" in job["error"]
        log(job["error"])
    except requests.RequestException as e:
        job["state"], job["error"] = "error", f"Network problem talking to Qualys: {e}"
        log(job["error"])
    except Exception as e:
        job["state"], job["error"] = "error", f"Unexpected error: {e}"
        log(traceback.format_exc())
    finally:
        job["waiting"] = None
        params.pop("password", None)
        RUN_LOCK.release()


# ----------------------------------------------------------------------------------------------
# HTTP handler
# ----------------------------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ctype="application/json; charset=utf-8", extra=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        url = urlparse(self.path)
        q = parse_qs(url.query)
        if url.path == "/":
            return self._send(200, PAGE.replace("__DEFAULT_QQL__", etm.DEFAULT_QQL)
                              .replace("__DEFAULT_URL__", etm.DEFAULT_BASE_URL)
                              .replace("__DOC_URL__", etm_qql.DOC_URL),
                              "text/html; charset=utf-8")
        if url.path == "/status":
            job = JOBS.get(q.get("job", [""])[0])
            if not job:
                return self._send(404, {"error": "unknown job"})
            view = {k: v for k, v in job.items() if k != "files"}
            view["files"] = [{"index": i, "name": os.path.basename(p)}
                             for i, p in enumerate(job.get("files", []))]
            return self._send(200, view)
        if url.path == "/download":
            job = JOBS.get(q.get("job", [""])[0])
            try:
                path = job["files"][int(q.get("i", ["-1"])[0])]
            except (TypeError, KeyError, IndexError, ValueError):
                return self._send(404, {"error": "file not found"})
            with open(path, "rb") as f:
                data = f.read()
            ctype = "text/csv" if path.endswith(".csv") else "application/json"
            return self._send(200, data, ctype, {
                "Content-Disposition": f'attachment; filename="{os.path.basename(path)}"'})
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if urlparse(self.path).path == "/stop":
            job = JOBS.get(parse_qs(urlparse(self.path).query).get("job", [""])[0])
            if job and job["state"] == "running":
                job["cancel"] = True
                job["logs"].append(f"[{datetime.now():%H:%M:%S}] Stop requested...")
            return self._send(200, {"ok": True})
        if urlparse(self.path).path == "/validate":
            try:
                params = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
            except ValueError:
                return self._send(400, {"error": "invalid request"})
            return self._send(200, etm_qql.check_all(params.get("qql"), params.get("asset_qql")))
        if urlparse(self.path).path != "/start":
            return self._send(404, {"error": "not found"})
        try:
            params = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
        except ValueError:
            return self._send(400, {"error": "invalid request"})
        if not params.get("username") or not params.get("password"):
            return self._send(400, {"error": "Username and password are required."})
        if not (params.get("report_id") or "").strip() and not params.get("skip_check"):
            problems = etm_qql.check_all(params.get("qql"), params.get("asset_qql"))
            if problems["findings"] or problems["asset"]:
                return self._send(400, {"error": "Fix the QQL problems shown above (or tick "
                                                 "'Skip token check').", "problems": problems})
        if not RUN_LOCK.acquire(blocking=False):
            return self._send(409, {"error": "A report is already running. Wait for it to finish."})
        job_id = uuid.uuid4().hex
        JOBS[job_id] = {"state": "running", "step": 0, "logs": [], "files": [],
                        "report_id": None, "summary": None, "error": None, "waiting": None,
                        "report_failed": False}
        threading.Thread(target=run_job, args=(JOBS[job_id], params), daemon=True).start()
        self._send(200, {"job": job_id})


# ----------------------------------------------------------------------------------------------
# Page
# ----------------------------------------------------------------------------------------------
PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ETM Findings Report</title>
<style>
:root{--bg:#f5f6f8;--card:#fff;--ink:#1d2330;--muted:#667085;--line:#e3e6eb;--accent:#2f5fd0;
 --accent-ink:#fff;--ok:#1f8a4c;--err:#c0392b;--warn:#a15c00;--warn-bg:#fff6e6;--code:#0f1420;--code-ink:#d6dbe6;
 --chip:#eef2fb}
@media (prefers-color-scheme:dark){:root{--bg:#0f1218;--card:#171b23;--ink:#e6e9ef;--muted:#98a2b3;
 --line:#2a303b;--accent:#6b8ff0;--accent-ink:#0f1218;--ok:#4cc38a;--err:#f07166;--warn:#f0b34a;--warn-bg:#2a2112;
 --code:#0b0e14;--code-ink:#c9d1e0;--chip:#1f2635}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:760px;margin:0 auto;padding:32px 16px 48px}
h1{font-size:22px;margin:0 0 4px}
h2{font-size:13px;letter-spacing:.05em;text-transform:uppercase;color:var(--muted);margin:4px 0 12px}
.sub{color:var(--muted);margin:0 0 24px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:20px;margin-bottom:16px}
label{display:block;font-weight:600;font-size:13px;margin:0 0 6px}
input,textarea,select{width:100%;padding:10px 12px;border:1px solid var(--line);border-radius:8px;
 background:var(--bg);color:var(--ink);font:inherit}
textarea{min-height:72px;resize:vertical;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px}
input:focus,textarea:focus,select:focus{outline:2px solid var(--accent);outline-offset:1px}
.row{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:14px}
.field{margin-bottom:14px}
.hint{color:var(--muted);font-size:12px;margin-top:4px}
.hint code{background:var(--chip);padding:1px 5px;border-radius:4px}
hr{border:0;border-top:1px solid var(--line);margin:18px 0}
.tagrow{display:grid;grid-template-columns:1fr auto auto;gap:8px;margin-top:8px}
.tagrow select{width:auto}
.tagrow4{grid-template-columns:1fr auto auto auto}
.qcheck.warn{color:var(--warn)}
details{margin:4px 0 16px}summary{cursor:pointer;color:var(--muted);font-size:13px}
details .row{margin-top:12px}
button{background:var(--accent);color:var(--accent-ink);border:0;border-radius:8px;padding:11px 20px;
 font:600 15px system-ui,sans-serif;cursor:pointer}
button.ghost{background:transparent;color:var(--accent);border:1px solid var(--line);padding:9px 14px;font-size:14px}
button.ghost:hover{border-color:var(--accent)}
button:disabled{opacity:.55;cursor:not-allowed}
.steps{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-bottom:14px}
.step{border:1px solid var(--line);border-radius:8px;padding:8px 10px;font-size:13px;color:var(--muted)}
.step b{display:block;font-size:11px;letter-spacing:.04em;text-transform:uppercase}
.step.active{border-color:var(--accent);color:var(--ink)}
.step.wait{border-color:var(--warn);color:var(--warn)}
.step.done{border-color:var(--ok);color:var(--ok)}
.step.fail{border-color:var(--err);color:var(--err)}
pre:empty{display:none}
pre{background:var(--code);color:var(--code-ink);border-radius:8px;padding:12px;margin:0;max-height:280px;
 overflow:auto;font-size:12.5px;white-space:pre-wrap;word-break:break-word}
.msg{padding:10px 12px;border-radius:8px;margin-bottom:12px;font-size:14px;white-space:pre-line;word-break:break-word}
.msg.ok{border:1px solid var(--ok);color:var(--ok)}.msg.err{border:1px solid var(--err);color:var(--err)}
.msg.warn{border:1px solid var(--warn);color:var(--warn);background:var(--warn-bg)}
.msg .actions{margin-top:10px}
.files{margin-bottom:14px}
.files a{display:inline-block;margin:6px 8px 0 0;padding:8px 12px;border:1px solid var(--line);border-radius:8px;
 color:var(--accent);text-decoration:none;font-size:13px;word-break:break-all}
.files a:hover{border-color:var(--accent)}
.hidden{display:none}
a{color:var(--accent)}
.qcheck{font-size:12.5px;margin-top:6px}
.qcheck.ok{color:var(--ok)}.qcheck.bad{color:var(--err)}
.qcheck ul{margin:4px 0 0;padding-left:18px}
.inline{display:flex;gap:8px;align-items:center;font-weight:500;font-size:13px}
.inline input{width:auto}
@media (max-width:560px){.tagrow4{grid-template-columns:1fr}.row{grid-template-columns:1fr}.steps{grid-template-columns:1fr 1fr}
 .tagrow{grid-template-columns:1fr}.tagrow select{width:100%}}
</style></head>
<body><main>
<h1>ETM Findings Report</h1>
<p class="sub">Generate a Qualys ETM findings report and download it as JSON and CSV.</p>

<form id="f" class="card" autocomplete="off">
  <h2>Credentials</h2>
  <div class="row">
    <div><label for="username">Username</label><input id="username" required></div>
    <div><label for="password">Password</label><input id="password" type="password" required></div>
  </div>
  <hr>
  <h2>Report filters</h2>
  <div class="field">
    <label for="qql">Findings QQL</label>
    <textarea id="qql">__DEFAULT_QQL__</textarea>
    <div class="qcheck" id="check_qql"></div>
  </div>
  <div class="field">
    <label for="asset_qql">Asset QQL <span class="hint">(optional: leave empty for all assets)</span></label>
    <textarea id="asset_qql" placeholder="e.g. asset.tag.name:`Firewall Detected`"></textarea>
    <div class="qcheck" id="check_asset_qql"></div>
  </div>
  <div class="field">
    <label for="tag">Add an asset tag</label>
    <div class="tagrow">
      <input id="tag" placeholder="Tag name, e.g. Firewall Detected">
      <select id="tagjoin" aria-label="How to combine with existing tags">
        <option value="and">and</option>
        <option value="or">or</option>
      </select>
      <button type="button" class="ghost" id="addtag">Add tag</button>
    </div>
    <div class="hint">Writes <code>asset.tag.name:`Tag`</code> into the Asset QQL. Backticks keep names with
      spaces together. Several tags joined with <b>or</b> are wrapped in parentheses.</div>
  </div>
  <div class="row">
    <div><label for="name">Report name <span class="hint">(optional)</span></label><input id="name"></div>
    <div><label for="description">Description <span class="hint">(optional)</span></label><input id="description"></div>
  </div>
  <details><summary>Advanced options</summary>
    <div class="row">
      <div><label for="base_url">Platform URL</label><input id="base_url" value="__DEFAULT_URL__"></div>
      <div><label for="report_id">Existing report ID (optional)</label><input id="report_id" placeholder="Skip creation, download this report"></div>
    </div>
    <div class="row">
      <div><label for="interval">Status check every (seconds)</label><input id="interval" type="number" min="1" value="15"></div>
      <div><label for="timeout">Give up after (seconds)</label><input id="timeout" type="number" min="60" value="3600"></div>
    </div>
    <div class="row">
      <div><label for="retry_wait">On HTTP 429 / temporary error, retry after (seconds)</label><input id="retry_wait" type="number" min="10" value="120"></div>
      <div><label for="max_retries">Max retries per call</label><input id="max_retries" type="number" min="0" value="5"></div>
    </div>
    <div class="field"><label class="inline"><input type="checkbox" id="skip_check">
      Skip token check (send the QQL to Qualys as typed)</label>
      <div class="hint">Use only if Qualys added a new token that this page doesn't know yet.</div></div>
    <div class="row">
      <div><label for="date_tz">Dates in the CSV</label>
        <select id="date_tz"><option value="utc">UTC</option><option value="local">This computer's time zone</option></select>
        <div class="hint">All dates are written as YYYY-MM-DD HH:MM:SS.</div></div>
    </div>
  </details>
  <div id="ridnote" class="msg warn hidden">An existing report ID is set (Advanced options): this run
    only checks and downloads that report. The QQL above is <b>not</b> used and no new report is created.
    <div class="actions"><button type="button" class="ghost" id="clearrid">Clear report ID</button></div></div>
  <button id="go" type="submit">Run report</button>
  <button id="stop" type="button" class="ghost hidden">Stop</button>
</form>

<section id="progress" class="card hidden">
  <div class="steps">
    <div class="step" data-s="1"><b>Step 1</b>Token</div>
    <div class="step" data-s="2"><b>Step 2</b>Request report</div>
    <div class="step" data-s="3"><b>Step 3</b>Wait for status</div>
    <div class="step" data-s="4"><b>Step 4</b>Download &amp; save</div>
  </div>
  <div id="waiting"></div>
  <div id="result"></div>
  <pre id="log"></pre>
</section>
</main>
<script>
const $ = id => document.getElementById(id);
const FIELDS = ["username","password","qql","asset_qql","name","description","base_url","report_id",
                "interval","timeout","retry_wait","max_retries","date_tz"];

function showCheck(id, problems, empty, warnings) {
  const el = $(id); el.replaceChildren();
  if ($("skip_check").checked) { el.className = "qcheck"; return; }
  const list = (title, items, cls) => {
    const box = document.createElement("div"); box.className = "qcheck " + cls; box.textContent = title;
    const ul = document.createElement("ul");
    items.forEach(p => { const li = document.createElement("li"); li.textContent = p; ul.appendChild(li); });
    box.appendChild(ul); el.appendChild(box);
  };
  el.className = "qcheck";
  if (problems && problems.length) list("Token problems (must fix):", problems, "bad");
  if (warnings && warnings.length) list("Warnings (the run is allowed):", warnings, "warn");
  if ((!problems || !problems.length) && (!warnings || !warnings.length) && !empty) {
    el.className = "qcheck ok"; el.textContent = "✓ Tokens OK";
  }
}
let vTimer = null;
async function validate() {
  try {
    const r = await fetch("/validate", {method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({qql: $("qql").value, asset_qql: $("asset_qql").value})});
    const d = await r.json();
    showCheck("check_qql", d.findings, !$("qql").value.trim(), d.warnings.findings);
    showCheck("check_asset_qql", d.asset, !$("asset_qql").value.trim(), d.warnings.asset);
  } catch {}
}
["qql","asset_qql"].forEach(id => $(id).addEventListener("input", () => { clearTimeout(vTimer); vTimer = setTimeout(validate, 350); }));
$("skip_check").addEventListener("change", validate);
validate();
function ridNote() { $("ridnote").classList.toggle("hidden", !$("report_id").value.trim()); }
$("report_id").addEventListener("input", ridNote);
$("clearrid").addEventListener("click", () => { $("report_id").value = ""; ridNote(); });
ridNote();
let job = null, timer = null, lastReportId = null;

$("addtag").addEventListener("click", () => {
  const tag = $("tag").value.trim().replace(/`/g, "");
  if (!tag) { $("tag").focus(); return; }
  const box = $("asset_qql"), tok = "asset.tag.name";
  const piece = tok + ":`" + tag + "`", join = $("tagjoin").value, esc = tok.replace(/\./g, "\\.");
  let cur = box.value.trim();
  if (!cur) cur = piece;
  else if (join === "and") cur = `${cur} and ${piece}`;
  else {
    // "or" another tag: keep the tag group together in parentheses so the rest still applies
    const one = `${esc}:\`[^\`]*\``;
    const grp = new RegExp(`\\((${one}(?: or ${one})*)\\)$`), last = new RegExp(`(${one})$`);
    if (grp.test(cur)) cur = cur.replace(grp, (m, g) => `(${g} or ${piece})`);
    else if (cur === cur.match(last)?.[0]) cur = `${cur} or ${piece}`;
    else if (last.test(cur)) cur = cur.replace(last, (m, g) => `(${g} or ${piece})`);
    else cur = `${cur} and ${piece}`;
  }
  box.value = cur; $("tag").value = ""; $("tag").focus(); validate();
});
$("tag").addEventListener("keydown", e => { if (e.key === "Enter") { e.preventDefault(); $("addtag").click(); } });

$("f").addEventListener("submit", async e => {
  e.preventDefault();
  const body = {};
  FIELDS.forEach(k => body[k] = $(k).value);
  body.skip_check = $("skip_check").checked;
  $("go").disabled = true; $("go").textContent = "Running...";
  $("progress").classList.remove("hidden"); $("result").innerHTML = ""; $("waiting").innerHTML = "";
  $("log").textContent = ""; lastReportId = null;
  paint(0, "running", false);
  const r = await fetch("/start", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(body)});
  const d = await r.json();
  $("password").value = "";
  if (!r.ok) {
    finish(); showError(d.error);
    if (d.problems) { showCheck("check_qql", d.problems.findings, false, d.problems.warnings.findings);
      showCheck("check_asset_qql", d.problems.asset, false, d.problems.warnings.asset);
      $("f").scrollIntoView({behavior:"smooth"}); }
    return;
  }
  job = d.job; timer = setInterval(poll, 1000); poll();
  $("stop").disabled = false; $("stop").textContent = "Stop"; $("stop").classList.remove("hidden");
});

function paint(step, state, waiting) {
  document.querySelectorAll(".step").forEach(el => {
    const s = +el.dataset.s; el.className = "step";
    if (s < step || state === "done") el.classList.add("done");
    else if (s === step) el.classList.add(state === "error" ? "fail" : waiting ? "wait" : "active");
  });
}
function showError(msg, reportId) {
  const div = document.createElement("div"); div.className = "msg err"; div.textContent = msg;
  if (reportId) {
    const act = document.createElement("div"); act.className = "actions";
    const b = document.createElement("button"); b.type = "button"; b.className = "ghost";
    b.textContent = "Resume this report (" + reportId.slice(0, 8) + "…)";
    b.onclick = () => {
      $("report_id").value = reportId; ridNote(); document.querySelector("details").open = true;
      $("password").focus(); $("password").scrollIntoView({behavior:"smooth", block:"center"});
    };
    const note = document.createElement("div"); note.className = "hint";
    note.textContent = "Fills the report ID so the next run checks and downloads this same report instead of creating a new one. Re-enter your password, then Run report.";
    act.append(b, note); div.appendChild(act);
  }
  $("result").replaceChildren(div);
}
function finish() { clearInterval(timer); $("go").disabled = false; $("go").textContent = "Run report";
  $("stop").classList.add("hidden"); }
$("stop").addEventListener("click", async () => {
  if (!job) return; $("stop").disabled = true; $("stop").textContent = "Stopping...";
  await fetch("/stop?job=" + job, {method: "POST"});
});

function renderWaiting(w) {
  if (!w) { $("waiting").innerHTML = ""; return; }
  const secs = Math.max(0, Math.round(w.until - Date.now() / 1000));
  const at = new Date(w.until * 1000).toLocaleTimeString();
  const div = document.createElement("div"); div.className = "msg warn";
  div.textContent = `${w.reason}. Not stopping: retrying automatically at ${at} ` +
    `(in ${Math.floor(secs / 60)}m ${String(secs % 60).padStart(2, "0")}s, retry ${w.attempt} of ${w.max}).`;
  $("waiting").replaceChildren(div);
}

async function poll() {
  let d;
  try { d = await (await fetch("/status?job=" + job)).json(); }
  catch { finish(); showError("Lost connection to the local script. Is it still running?", lastReportId); return; }
  if (d.report_id) lastReportId = d.report_id;
  paint(d.step, d.state, !!d.waiting);
  renderWaiting(d.state === "running" ? d.waiting : null);
  const log = $("log"), atEnd = log.scrollTop + log.clientHeight >= log.scrollHeight - 5;
  log.textContent = d.logs.join("\n");
  if (atEnd) log.scrollTop = log.scrollHeight;
  if (d.state === "running") return;
  finish();
  if (d.state === "error") {
    if (d.report_failed) {
      // Qualys could not build this report: resuming it is pointless, a new report is needed
      if ($("report_id").value.trim() === d.report_id) { $("report_id").value = ""; ridNote(); }
      showError("Qualys could not build this report (status FAILED). Check the QQL (see any warnings " +
        "above) and run again to create a new report.\n\n" + d.error);
      validate();
    } else showError(d.error || "The run failed.", d.report_id);
    return;
  }
  const s = d.summary, box = document.createElement("div");
  const m = document.createElement("div"); m.className = "msg ok";
  m.textContent = `Done: ${s.records} records, ${s.columns} columns. CSV and JSON match. Saved in ${s.folder}`;
  const files = document.createElement("div"); files.className = "files";
  d.files.forEach(f => { const a = document.createElement("a");
    a.href = `/download?job=${job}&i=${f.index}`; a.textContent = "Download " + f.name; files.appendChild(a); });
  box.append(m, files); $("result").replaceChildren(box);
}
</script>
</body></html>
"""


def main():
    global OUTPUT_DIR
    p = argparse.ArgumentParser(description="Local web page to run the Qualys ETM findings report.")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--output-dir", default="etm_reports", help="Folder where files are saved")
    p.add_argument("--no-browser", action="store_true", help="Don't open the browser automatically")
    args = p.parse_args()
    OUTPUT_DIR = args.output_dir

    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    url = f"http://127.0.0.1:{args.port}/"
    print(f"ETM report page running at {url}  (press Ctrl+C to stop)")
    if not args.no_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
