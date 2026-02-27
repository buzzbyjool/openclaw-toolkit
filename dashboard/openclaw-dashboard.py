#!/usr/bin/env python3
"""
openclaw-dashboard.py -- Lightweight monitoring dashboard for OpenClaw.
Serves a web UI on port 18790, accessible via Tailscale Serve.

Panels:
  1. Bridge logs (IN/OUT inter-agent messages)
  2. Security logs (exec-guardian decisions)
  3. Memory (MEMORY.md current state + distill history)

Zero dependencies -- Python 3.9+ stdlib only.
"""

import json
import os
import re
import sys
from datetime import datetime, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse, parse_qs

PORT = 18790
HOME = Path.home()

# --- Paths ---
BRIDGE_LOGS_DIR = HOME / ".openclaw" / "bridge" / "logs"
GUARDIAN_LOGS_DIR = HOME / ".openclaw" / "guardian" / "logs"
MEMORY_FILE = HOME / ".openclaw" / "workspace" / "MEMORY.md"
MEMORY_DIR = HOME / ".openclaw" / "workspace" / "memory"
MEMORY_LOGS_DIR = HOME / ".openclaw" / "workspace" / "memory" / ".logs"
MEMORY_STATE_DIR = HOME / ".openclaw" / "workspace" / "memory" / ".state"
MEMORY_DB_DIR = HOME / ".openclaw" / "memory"


def read_bridge_logs(date_str: str = None, limit: int = 100) -> list:
    if not date_str:
        date_str = datetime.now().strftime("%Y-%m-%d")
    log_file = BRIDGE_LOGS_DIR / f"{date_str}.jsonl"
    entries = []
    if log_file.exists():
        with open(log_file) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    return entries[-limit:]


def read_guardian_logs(date_str: str = None, limit: int = 200) -> list:
    if not date_str:
        date_str = datetime.now().strftime("%Y-%m-%d")
    log_file = GUARDIAN_LOGS_DIR / f"guardian-{date_str}.log"
    entries = []
    if log_file.exists():
        with open(log_file) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                m = re.match(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+ \[(\w+)\] (.+)', line)
                if m:
                    ts, level, msg = m.groups()
                    entry = {"timestamp": ts, "level": level, "message": msg}
                    if "ALLOW" in msg:
                        entry["decision"] = "allow"
                    elif "DENY" in msg:
                        entry["decision"] = "deny"
                    elif "ASK" in msg:
                        entry["decision"] = "ask"
                    elif "Request:" in msg:
                        entry["decision"] = "request"
                    elif "Response:" in msg:
                        entry["decision"] = "response"
                    else:
                        entry["decision"] = "info"
                    entries.append(entry)
    return entries[-limit:]


def read_memory() -> str:
    if MEMORY_FILE.exists():
        with open(MEMORY_FILE) as f:
            return f.read()
    return "(MEMORY.md not found)"


def read_memory_files() -> list:
    files = []
    if MEMORY_DIR.exists():
        for f in sorted(MEMORY_DIR.glob("*.md"), reverse=True)[:14]:
            stat = f.stat()
            files.append({
                "name": f.name,
                "size": stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            })
    return files


def available_dates() -> list:
    dates = set()
    if BRIDGE_LOGS_DIR.exists():
        for f in BRIDGE_LOGS_DIR.glob("*.jsonl"):
            dates.add(f.stem)
    if GUARDIAN_LOGS_DIR.exists():
        for f in GUARDIAN_LOGS_DIR.glob("guardian-*.log"):
            d = f.stem.replace("guardian-", "")
            if re.match(r'^\d{4}-\d{2}-\d{2}$', d):
                dates.add(d)
    return sorted(dates, reverse=True)[:30]


def read_vector_status() -> dict:
    """Read SQLite vector DB status for each agent."""
    import sqlite3
    agents = []
    if MEMORY_DB_DIR.exists():
        for db_file in sorted(MEMORY_DB_DIR.glob("*.sqlite")):
            agent_name = db_file.stem
            info = {"agent": agent_name, "size_kb": round(db_file.stat().st_size / 1024)}
            try:
                conn = sqlite3.connect(str(db_file))
                cur = conn.cursor()
                cur.execute("SELECT COUNT(*) FROM chunks")
                info["chunks"] = cur.fetchone()[0]
                cur.execute("SELECT COUNT(*) FROM files")
                info["files"] = cur.fetchone()[0]
                cur.execute("SELECT value FROM meta WHERE key='dims'")
                row = cur.fetchone()
                info["dims"] = int(row[0]) if row else 0
                conn.close()
                info["status"] = "ok"
            except Exception as e:
                info["status"] = f"error: {e}"
                info["chunks"] = 0
                info["files"] = 0
            agents.append(info)
    return {"agents": agents}


def read_memory_logs() -> list:
    """Read extract and distill log entries."""
    entries = []
    if not MEMORY_LOGS_DIR.exists():
        return entries

    for log_file in sorted(MEMORY_LOGS_DIR.glob("*.log"), key=lambda f: f.stat().st_mtime, reverse=True)[:10]:
        fname = log_file.name
        if "distill" in fname and "launchd" not in fname:
            log_type = "distill"
        elif "extract" in fname and "launchd" not in fname:
            log_type = "extract"
        else:
            continue

        with open(log_file) as f:
            current_block = None
            for line in f:
                line = line.strip()
                if not line:
                    continue
                m = re.match(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+ (\w+) (.+)', line)
                if not m:
                    continue
                ts, level, msg = m.groups()

                if "START" in msg:
                    current_block = {"type": log_type, "start": ts, "details": [], "status": "running"}
                elif "DONE" in msg:
                    if current_block:
                        current_block["end"] = ts
                        current_block["status"] = "ok"
                        current_block["summary"] = msg
                        entries.append(current_block)
                        current_block = None
                elif current_block:
                    if any(k in msg for k in ["Wrote", "updated", "Reindex", "response", "events", "chars", "tokens", "Backup"]):
                        current_block["details"].append(msg)

    entries.sort(key=lambda e: e.get("start", ""), reverse=True)
    return entries[:50]


def read_memory_state() -> dict:
    """Read current state of extract and distill."""
    state = {}
    extract_state = MEMORY_STATE_DIR / "extract-state.json"
    distill_state = MEMORY_STATE_DIR / "distill-state.json"
    if extract_state.exists():
        with open(extract_state) as f:
            state["extract"] = json.load(f)
    if distill_state.exists():
        with open(distill_state) as f:
            state["distill"] = json.load(f)
    return state


HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OpenClaw Monitor</title>
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg viewBox='0 0 120 120' fill='none' xmlns='http://www.w3.org/2000/svg'%3E%3Cdefs%3E%3ClinearGradient id='g' x1='0%25' y1='0%25' x2='100%25' y2='100%25'%3E%3Cstop offset='0%25' stop-color='%23ff4d4d'/%3E%3Cstop offset='100%25' stop-color='%23991b1b'/%3E%3C/linearGradient%3E%3C/defs%3E%3Cpath d='M60 10 C30 10 15 35 15 55 C15 75 30 95 45 100 L45 110 L55 110 L55 100 C55 100 60 102 65 100 L65 110 L75 110 L75 100 C90 95 105 75 105 55 C105 35 90 10 60 10Z' fill='url(%23g)'/%3E%3Cpath d='M20 45 C5 40 0 50 5 60 C10 70 20 65 25 55 C28 48 25 45 20 45Z' fill='url(%23g)'/%3E%3Cpath d='M100 45 C115 40 120 50 115 60 C110 70 100 65 95 55 C92 48 95 45 100 45Z' fill='url(%23g)'/%3E%3Ccircle cx='45' cy='35' r='6' fill='%23050810'/%3E%3Ccircle cx='75' cy='35' r='6' fill='%23050810'/%3E%3Ccircle cx='46' cy='34' r='2' fill='%2300e5cc'/%3E%3Ccircle cx='76' cy='34' r='2' fill='%2300e5cc'/%3E%3C/svg%3E">
<link href="https://api.fontshare.com/v2/css?f[]=clash-display@700,600,500&f[]=satoshi@400,500,700&display=swap" rel="stylesheet">
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: 'Satoshi', -apple-system, BlinkMacSystemFont, sans-serif; background: #050810; color: #e0e0e0; }

.header { background: #0a0e18; border-bottom: 1px solid #1a1f2e; padding: 12px 20px; display: flex; align-items: center; justify-content: space-between; position: sticky; top: 0; z-index: 100; }
.header .logo { display: flex; align-items: center; gap: 10px; }
.header .logo svg { width: 32px; height: 32px; filter: drop-shadow(0 0 6px rgba(255,77,77,0.4)); }
.header h1 { font-family: 'Clash Display', sans-serif; font-size: 18px; font-weight: 700; letter-spacing: -0.03em; background: linear-gradient(135deg, #ff4d4d 0%, #991b1b 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; }
.header h1 .monitor { font-family: 'Satoshi', sans-serif; font-size: 13px; font-weight: 400; -webkit-text-fill-color: #666; margin-left: 8px; letter-spacing: 0; }
.header .controls { display: flex; gap: 8px; align-items: center; }
.header select, .header button { background: #0f1420; border: 1px solid #1a1f2e; color: #ccc; padding: 4px 10px; border-radius: 4px; font-size: 12px; cursor: pointer; font-family: 'Satoshi', sans-serif; }
.header button:hover { background: #151b28; border-color: #2a3040; }
.header .live { display: inline-block; width: 8px; height: 8px; background: #00e5cc; border-radius: 50%; margin-right: 6px; animation: pulse 2s infinite; }
@keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }

.tabs { display: flex; background: #0a0e18; border-bottom: 1px solid #1a1f2e; padding: 0 20px; }
.tab { padding: 10px 20px; font-size: 13px; cursor: pointer; border-bottom: 2px solid transparent; color: #888; transition: all 0.15s; font-family: 'Satoshi', sans-serif; }
.tab:hover { color: #ccc; }
.tab.active { color: #ff4d4d; border-bottom-color: #ff4d4d; }
.tab .count { background: #151b28; color: #888; padding: 1px 6px; border-radius: 8px; font-size: 11px; margin-left: 6px; }

.panel { display: none; padding: 16px 20px; }
.panel.active { display: block; }

/* Bridge */
.msg { padding: 10px 14px; margin: 4px 0; border-radius: 6px; font-size: 13px; line-height: 1.5; cursor: pointer; transition: background 0.15s; }
.msg.out { background: #0c1f0c; border-left: 3px solid #22c55e; }
.msg.in { background: #0c0c1f; border-left: 3px solid #3b82f6; }
.msg.out:hover { background: #0f280f; }
.msg.in:hover { background: #0f0f28; }
.msg .meta { font-size: 11px; color: #666; margin-bottom: 4px; display: flex; justify-content: space-between; }
.msg .meta .dir { font-weight: 600; }
.msg .meta .dir.out { color: #22c55e; }
.msg .meta .dir.in { color: #3b82f6; }
.msg .meta .click-hint { color: #444; font-size: 10px; }
.msg .body { white-space: pre-wrap; word-break: break-word; }
.msg .http { font-size: 11px; color: #666; margin-top: 4px; }
.msg .rewrite { font-size: 12px; color: #888; margin-top: 6px; padding-top: 6px; border-top: 1px solid #1a1a2a; }
.msg .rewrite-label { font-size: 10px; color: #555; text-transform: uppercase; letter-spacing: 1px; }
.msg .json-detail { display: none; margin-top: 8px; padding: 10px; background: #0a0a0a; border: 1px solid #222; border-radius: 4px; font-size: 11px; line-height: 1.5; white-space: pre-wrap; word-break: break-all; color: #999; max-height: 400px; overflow-y: auto; }
.msg .json-detail.open { display: block; }
.msg .json-label { font-size: 10px; color: #555; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 4px; }
.msg .body-full { display: none; white-space: pre-wrap; word-break: break-word; }
.msg .expand-link { font-size: 10px; color: #ff4d4d; cursor: pointer; margin-top: 4px; display: inline-block; }
.msg .expand-link:hover { color: #ff6b6b; text-decoration: underline; }

/* Guardian */
.log-line { padding: 4px 14px; font-size: 12px; display: flex; gap: 12px; border-bottom: 1px solid #141414; }
.log-line:hover { background: #111; }
.log-line .ts { color: #555; min-width: 140px; flex-shrink: 0; }
.log-line .level { min-width: 50px; flex-shrink: 0; font-weight: 600; }
.log-line .level.INFO { color: #888; }
.log-line .level.WARNING { color: #eab308; }
.log-line .level.ERROR { color: #ef4444; }
.log-line .msg-text { flex: 1; word-break: break-all; }
.log-line .badge { display: inline-block; padding: 1px 6px; border-radius: 3px; font-size: 10px; font-weight: 600; }
.log-line .badge.allow { background: #052e05; color: #22c55e; }
.log-line .badge.deny { background: #2e0505; color: #ef4444; }
.log-line .badge.ask { background: #2e2505; color: #eab308; }

/* Memory */
.memory-section { margin-bottom: 20px; }
.memory-section h3 { font-size: 13px; color: #ff6b35; margin-bottom: 8px; font-weight: 600; }
.memory-content { background: #111; border: 1px solid #222; border-radius: 6px; padding: 16px; font-size: 12px; line-height: 1.6; white-space: pre-wrap; max-height: 50vh; overflow-y: auto; }
.memory-files { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 12px; }
.memory-file { background: #151515; border: 1px solid #252525; border-radius: 4px; padding: 6px 12px; font-size: 11px; cursor: pointer; }
.memory-file:hover { border-color: #444; }
.memory-file .name { color: #ff6b35; }
.memory-file .size { color: #555; margin-left: 6px; }

/* Vector status */
.vector-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 10px; margin-bottom: 16px; }
.vector-card { background: #111; border: 1px solid #222; border-radius: 6px; padding: 12px; }
.vector-card .agent-name { font-size: 13px; font-weight: 600; color: #e0e0e0; margin-bottom: 6px; }
.vector-card .metric { font-size: 11px; color: #888; margin: 2px 0; }
.vector-card .metric strong { color: #ccc; }
.vector-card .status-ok { color: #22c55e; }
.vector-card .status-err { color: #ef4444; }

/* Memory logs */
.mem-log { padding: 8px 12px; margin: 4px 0; border-radius: 6px; font-size: 12px; cursor: pointer; transition: background 0.15s; }
.mem-log.extract { background: #0c0c1f; border-left: 3px solid #8b5cf6; }
.mem-log.distill { background: #1f0c1f; border-left: 3px solid #ec4899; }
.mem-log:hover { filter: brightness(1.2); }
.mem-log .log-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px; }
.mem-log .log-type { font-weight: 600; text-transform: uppercase; font-size: 10px; letter-spacing: 1px; }
.mem-log .log-type.extract { color: #8b5cf6; }
.mem-log .log-type.distill { color: #ec4899; }
.mem-log .log-time { font-size: 11px; color: #666; }
.mem-log .log-summary { color: #999; }
.mem-log .log-details { display: none; margin-top: 6px; padding-top: 6px; border-top: 1px solid #222; font-size: 11px; color: #777; }
.mem-log .log-details.open { display: block; }
.mem-log .log-details div { margin: 2px 0; }

.stats { display: flex; gap: 16px; padding: 10px 20px; background: #080c14; border-bottom: 1px solid #1a1f2e; }
.stat { font-size: 11px; color: #666; }
.stat strong { color: #aaa; }

.empty { text-align: center; padding: 40px; color: #444; font-size: 14px; }

/* Footer */
.footer { border-top: 1px solid #1a1f2e; padding: 16px 20px; display: flex; align-items: center; justify-content: center; gap: 8px; margin-top: 40px; }
.footer span { font-size: 11px; color: #444; font-family: 'Satoshi', sans-serif; }

/* Pagination */
.pagination { display: flex; justify-content: center; align-items: center; gap: 8px; padding: 12px 0; }
.pagination button { background: #0f1420; border: 1px solid #1a1f2e; color: #ccc; padding: 4px 12px; border-radius: 4px; font-size: 11px; cursor: pointer; font-family: 'Satoshi', sans-serif; }
.pagination button:hover { background: #151b28; border-color: #2a3040; }
.pagination button.active { background: #ff4d4d; border-color: #ff4d4d; color: #fff; }
.pagination button:disabled { opacity: 0.3; cursor: default; }
.pagination .page-info { font-size: 11px; color: #555; }
</style>
</head>
<body>

<div class="header">
  <div class="logo">
    <span class="live"></span>
    <svg viewBox="0 0 120 120" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path d="M60 10 C30 10 15 35 15 55 C15 75 30 95 45 100 L45 110 L55 110 L55 100 C55 100 60 102 65 100 L65 110 L75 110 L75 100 C90 95 105 75 105 55 C105 35 90 10 60 10Z" fill="url(#lg)"/>
      <path d="M20 45 C5 40 0 50 5 60 C10 70 20 65 25 55 C28 48 25 45 20 45Z" fill="url(#lg)"/>
      <path d="M100 45 C115 40 120 50 115 60 C110 70 100 65 95 55 C92 48 95 45 100 45Z" fill="url(#lg)"/>
      <path d="M45 15 Q35 5 30 8" stroke="#ff4d4d" stroke-width="2" stroke-linecap="round"/>
      <path d="M75 15 Q85 5 90 8" stroke="#ff4d4d" stroke-width="2" stroke-linecap="round"/>
      <circle cx="45" cy="35" r="6" fill="#050810"/>
      <circle cx="75" cy="35" r="6" fill="#050810"/>
      <circle cx="46" cy="34" r="2" fill="#00e5cc"/>
      <circle cx="76" cy="34" r="2" fill="#00e5cc"/>
      <defs><linearGradient id="lg" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stop-color="#ff4d4d"/><stop offset="100%" stop-color="#991b1b"/></linearGradient></defs>
    </svg>
    <h1>OpenClaw<span class="monitor">Monitor</span></h1>
  </div>
  <div class="controls">
    <select id="dateSelect"></select>
    <button onclick="refresh()">Refresh</button>
    <label style="font-size:11px;color:#666;"><input type="checkbox" id="autoRefresh" checked style="margin-right:4px;">Auto 30s</label>
  </div>
</div>

<div class="tabs">
  <div class="tab active" data-panel="bridge" onclick="switchTab(this)">Bridge <span class="count" id="bridgeCount">0</span></div>
  <div class="tab" data-panel="guardian" onclick="switchTab(this)">Security <span class="count" id="guardianCount">0</span></div>
  <div class="tab" data-panel="memory" onclick="switchTab(this)">Memory</div>
</div>

<div id="stats" class="stats"></div>

<div id="bridge" class="panel active"></div>
<div id="guardian" class="panel"></div>
<div id="memory" class="panel"></div>

<script>
let currentDate = '';
let autoTimer = null;
const PAGE_SIZE = 25;
let bridgePage = 0;
let guardianPage = 0;
let bridgeData = [];
let guardianData = [];

function switchTab(el) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  el.classList.add('active');
  document.getElementById(el.dataset.panel).classList.add('active');
}

function esc(s) {
  if (!s) return '';
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function toggleJson(el) {
  const detail = el.querySelector('.json-detail');
  if (detail) detail.classList.toggle('open');
}

function prettyJson(obj) {
  try { return JSON.stringify(obj, null, 2); } catch { return String(obj); }
}

const MSG_TRUNC = 120;
function bodyHtml(text) {
  const t = text || '';
  if (t.length <= MSG_TRUNC) return '<div class="body">' + esc(t) + '</div>';
  return '<div class="body">' + esc(t.substring(0, MSG_TRUNC)) + '...</div>'
    + '<div class="body-full">' + esc(t) + '</div>'
    + '<span class="expand-link" onclick="toggleBody(this)">show more</span>';
}

function toggleBody(btn) {
  event.stopPropagation();
  const msg = btn.closest('.msg');
  const short = msg.querySelector('.body');
  const full = msg.querySelector('.body-full');
  if (!short || !full) return;
  if (full.style.display === 'none' || full.style.display === '') {
    short.style.display = 'none';
    full.style.display = 'block';
    btn.textContent = 'show less';
  } else {
    short.style.display = 'block';
    full.style.display = 'none';
    btn.textContent = 'show more';
  }
}

function renderPagination(total, page, onPageChange) {
  const pages = Math.ceil(total / PAGE_SIZE);
  if (pages <= 1) return '';
  let html = '<div class="pagination">';
  html += '<button ' + (page === 0 ? 'disabled' : 'onclick="' + onPageChange + '(' + (page-1) + ')"') + '>&lt;</button>';
  for (let i = 0; i < pages; i++) {
    const cls = i === page ? ' active' : '';
    html += '<button class="' + cls + '" onclick="' + onPageChange + '(' + i + ')">' + (i+1) + '</button>';
  }
  html += '<button ' + (page >= pages-1 ? 'disabled' : 'onclick="' + onPageChange + '(' + (page+1) + ')"') + '>&gt;</button>';
  html += '<span class="page-info">' + total + ' items</span>';
  html += '</div>';
  return html;
}

function formatTs(ts) {
  if (!ts) return '';
  try {
    const d = new Date(ts);
    if (isNaN(d)) return ts.substring(11, 19);
    return d.toLocaleTimeString('en-US', {hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false});
  } catch { return ts; }
}

async function loadDates() {
  const resp = await fetch('/dashboard/api/dates');
  const dates = await resp.json();
  const sel = document.getElementById('dateSelect');
  sel.innerHTML = '';
  dates.forEach(d => {
    const opt = document.createElement('option');
    opt.value = d;
    opt.textContent = d;
    sel.appendChild(opt);
  });
  if (dates.length > 0) {
    currentDate = dates[0];
    sel.value = currentDate;
  }
  sel.onchange = () => { currentDate = sel.value; refresh(); };
}

function setBridgePage(p) { bridgePage = p; renderBridge(); }

async function loadBridge() {
  const resp = await fetch('/dashboard/api/bridge?date=' + currentDate);
  bridgeData = (await resp.json()).reverse();
  bridgePage = 0;
  renderBridge();
}

function renderBridge() {
  const el = document.getElementById('bridge');
  const data = bridgeData;
  document.getElementById('bridgeCount').textContent = data.length;
  if (data.length === 0) { el.innerHTML = '<div class="empty">No bridge messages for this date.</div>'; return; }

  const start = bridgePage * PAGE_SIZE;
  const pageData = data.slice(start, start + PAGE_SIZE);
  let html = renderPagination(data.length, bridgePage, 'setBridgePage');
  for (const m of pageData) {
    const dir = m.direction || '?';
    const cls = dir === 'OUT' ? 'out' : 'in';
    const label = dir === 'OUT'
      ? 'OUT > ' + (m.target || '?').toUpperCase()
      : (m.source || '?').toUpperCase() + ' > IN';
    const ts = formatTs(m.timestamp);
    const jsonStr = esc(prettyJson(m));

    if (dir === 'OUT') {
      const status = m.http_status ? 'HTTP ' + m.http_status + ' | ' + m.duration_ms + 'ms' : '';
      html += '<div class="msg ' + cls + '" onclick="toggleJson(this)">'
        + '<div class="meta"><span class="dir ' + cls + '">' + label + '</span><span class="click-hint">click = JSON</span><span>' + ts + '</span></div>'
        + bodyHtml(m.message)
        + (status ? '<div class="http">' + esc(status) + '</div>' : '')
        + '<div class="json-detail"><div class="json-label">Full JSON</div>' + jsonStr + '</div>'
        + '</div>';
    } else {
      html += '<div class="msg ' + cls + '" onclick="toggleJson(this)">'
        + '<div class="meta"><span class="dir ' + cls + '">' + label + '</span><span class="click-hint">click = JSON</span><span>' + ts + '</span></div>'
        + bodyHtml(m.raw_message)
        + (m.bridge_reader_rewrite ? '<div class="rewrite"><div class="rewrite-label">bridge-reader rewrite</div>' + esc(m.bridge_reader_rewrite) + '</div>' : '')
        + '<div class="json-detail"><div class="json-label">Full JSON</div>' + jsonStr + '</div>'
        + '</div>';
    }
  }
  html += renderPagination(data.length, bridgePage, 'setBridgePage');
  el.innerHTML = html;
}

function setGuardianPage(p) { guardianPage = p; renderGuardian(); }

async function loadGuardian() {
  const resp = await fetch('/dashboard/api/guardian?date=' + currentDate);
  guardianData = (await resp.json()).reverse();
  guardianPage = 0;
  renderGuardian();
}

function renderGuardian() {
  const data = guardianData;
  const el = document.getElementById('guardian');

  let allows = 0, denies = 0, asks = 0;
  data.forEach(e => {
    if (e.decision === 'allow') allows++;
    else if (e.decision === 'deny') denies++;
    else if (e.decision === 'ask') asks++;
  });
  document.getElementById('guardianCount').textContent = data.length;

  const statsEl = document.getElementById('stats');
  statsEl.innerHTML = '<div class="stat"><strong>' + allows + '</strong> allow</div>'
    + '<div class="stat"><strong>' + denies + '</strong> deny</div>'
    + '<div class="stat"><strong>' + asks + '</strong> ask</div>'
    + '<div class="stat"><strong>' + data.length + '</strong> total</div>';

  if (data.length === 0) { el.innerHTML = '<div class="empty">No guardian logs for this date.</div>'; return; }

  const start = guardianPage * PAGE_SIZE;
  const pageData = data.slice(start, start + PAGE_SIZE);
  let html = renderPagination(data.length, guardianPage, 'setGuardianPage');
  for (const e of pageData) {
    const badge = (e.decision === 'allow' || e.decision === 'deny' || e.decision === 'ask')
      ? '<span class="badge ' + e.decision + '">' + e.decision.toUpperCase() + '</span> ' : '';
    html += '<div class="log-line">'
      + '<span class="ts">' + esc(e.timestamp) + '</span>'
      + '<span class="level ' + esc(e.level) + '">' + esc(e.level) + '</span>'
      + '<span class="msg-text">' + badge + esc(e.message) + '</span>'
      + '</div>';
  }
  html += renderPagination(data.length, guardianPage, 'setGuardianPage');
  el.innerHTML = html;
}

function toggleLogDetail(el) {
  const d = el.querySelector('.log-details');
  if (d) d.classList.toggle('open');
}

async function loadMemory() {
  const [memResp, statusResp] = await Promise.all([
    fetch('/dashboard/api/memory'),
    fetch('/dashboard/api/memory-status')
  ]);
  const data = await memResp.json();
  const status = await statusResp.json();
  const el = document.getElementById('memory');
  let html = '';

  // --- Vector DB Status ---
  html += '<div class="memory-section"><h3>Vector DB (sqlite-vec)</h3>';
  html += '<div class="vector-grid">';
  if (status.vector && status.vector.agents) {
    for (const a of status.vector.agents) {
      const statusCls = a.status === 'ok' ? 'status-ok' : 'status-err';
      html += '<div class="vector-card">'
        + '<div class="agent-name">' + esc(a.agent) + '</div>'
        + '<div class="metric"><strong>' + a.chunks + '</strong> chunks / <strong>' + a.files + '</strong> files</div>'
        + '<div class="metric">Size: <strong>' + a.size_kb + ' KB</strong></div>'
        + '<div class="metric">Status: <span class="' + statusCls + '">' + esc(a.status) + '</span></div>'
        + '</div>';
    }
  }
  html += '</div>';
  if (status.state) {
    const ext = status.state.extract;
    const dist = status.state.distill;
    html += '<div style="font-size:11px;color:#666;margin-bottom:12px;">';
    if (ext) html += 'Last extract: <strong style="color:#8b5cf6;">' + esc(ext.last_run_iso || '?') + '</strong> (' + (ext.events_written || 0) + ' events) &nbsp;&nbsp;';
    if (dist) html += 'Last distill: <strong style="color:#ec4899;">' + esc(dist.last_distill_iso || '?') + '</strong> (' + (dist.before_chars || 0) + ' -> ' + (dist.after_chars || 0) + ' chars)';
    html += '</div>';
  }
  html += '</div>';

  // --- Memory Logs ---
  html += '<div class="memory-section"><h3>Extract / distill history</h3>';
  if (status.logs && status.logs.length > 0) {
    for (const log of status.logs) {
      const typeCls = log.type || 'extract';
      const label = typeCls === 'distill' ? 'DISTILL' : 'EXTRACT';
      const time = (log.start || '').substring(11, 19);
      const endTime = (log.end || '').substring(11, 19);
      const dur = log.start && log.end ? ' (' + time + ' -> ' + endTime + ')' : '';
      const statusIcon = log.status === 'ok' ? '[OK]' : '[...]';
      html += '<div class="mem-log ' + typeCls + '" onclick="toggleLogDetail(this)">'
        + '<div class="log-header">'
        + '<span class="log-type ' + typeCls + '">' + label + ' ' + statusIcon + dur + '</span>'
        + '<span class="log-time">' + esc(log.start || '') + '</span>'
        + '</div>'
        + '<div class="log-summary">' + esc(log.summary || '') + '</div>';
      if (log.details && log.details.length > 0) {
        html += '<div class="log-details">';
        for (const d of log.details) {
          html += '<div>' + esc(d) + '</div>';
        }
        html += '</div>';
      }
      html += '</div>';
    }
  } else {
    html += '<div class="empty">No memory logs found.</div>';
  }
  html += '</div>';

  // --- Daily memory files ---
  html += '<div class="memory-section"><h3>Daily memory files</h3>';
  html += '<div class="memory-files">';
  if (data.files) {
    data.files.forEach(f => {
      html += '<div class="memory-file"><span class="name">' + esc(f.name) + '</span><span class="size">' + Math.round(f.size/1024) + 'K</span></div>';
    });
  }
  html += '</div></div>';

  // --- MEMORY.md content ---
  html += '<div class="memory-section"><h3>MEMORY.md (current)</h3>';
  html += '<div class="memory-content">' + esc(data.content || '') + '</div>';
  html += '</div>';

  el.innerHTML = html;
}

async function refresh() {
  await Promise.all([loadBridge(), loadGuardian(), loadMemory()]);
}

function startAutoRefresh() {
  if (autoTimer) clearInterval(autoTimer);
  const cb = document.getElementById('autoRefresh');
  if (cb.checked) {
    autoTimer = setInterval(refresh, 30000);
  }
  cb.onchange = startAutoRefresh;
}

(async () => {
  await loadDates();
  await refresh();
  startAutoRefresh();
})();
</script>

<div class="footer">
  <span>OpenClaw Toolkit -- github.com/easylab-ai/openclaw-toolkit</span>
</div>

</body>
</html>"""


class DashboardHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Suppress default logging

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        # Strip /dashboard prefix if present (Tailscale Serve routes /dashboard -> here)
        if path.startswith("/dashboard"):
            path = path[len("/dashboard"):] or "/"

        if path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_PAGE.encode())

        elif path == "/api/dates":
            self.json_response(available_dates())

        elif path == "/api/bridge":
            date = params.get("date", [None])[0]
            self.json_response(read_bridge_logs(date))

        elif path == "/api/guardian":
            date = params.get("date", [None])[0]
            self.json_response(read_guardian_logs(date))

        elif path == "/api/memory":
            self.json_response({
                "content": read_memory(),
                "files": read_memory_files(),
            })

        elif path == "/api/memory-status":
            self.json_response({
                "vector": read_vector_status(),
                "logs": read_memory_logs(),
                "state": read_memory_state(),
            })

        else:
            self.send_response(404)
            self.end_headers()

    def json_response(self, data):
        body = json.dumps(data, ensure_ascii=False, default=str).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)


def main():
    server = HTTPServer(("127.0.0.1", PORT), DashboardHandler)
    print(f"OpenClaw Dashboard running on http://127.0.0.1:{PORT}")
    print(f"Tailscale Serve: tailscale serve --bg --set-path /dashboard http://127.0.0.1:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.shutdown()


if __name__ == "__main__":
    main()
