#!/usr/bin/env python3
"""
exec-guardian.py -- Exec approval daemon for OpenClaw.

Listens on a Unix socket. When the OpenClaw gateway sends a command that
is not in its own allowlist (ask: on-miss), this daemon decides:
auto-allow, auto-deny, or ask a human via iMessage.

Protocol (JSONL over Unix socket, one request per connection):
  Request:  {"id":"...","command":"/usr/bin/git","commandArgv":["push","origin","main"],"agentId":"main"}
  Response: {"id":"...","decision":"approve"} or {"id":"...","decision":"deny"}

Stdlib only. Python 3.9+. No external dependencies.
"""

import json
import logging
import os
import secrets
import signal
import socket
import sqlite3
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
HOME = Path.home()
GUARDIAN_DIR = HOME / ".openclaw" / "guardian"
SOCK_PATH = HOME / ".openclaw" / "exec-approvals.sock"
POLICIES_PATH = GUARDIAN_DIR / "policies.json"
LOG_DIR = GUARDIAN_DIR / "logs"
CHAT_DB = HOME / "Library" / "Messages" / "chat.db"
IMSG_CLI = HOME / ".local" / "bin" / "imsg"

# ---------------------------------------------------------------------------
# Config -- edit these for your setup
# ---------------------------------------------------------------------------
APPROVER_IMESSAGE = os.environ.get(
    "GUARDIAN_APPROVER_IMESSAGE", "your.appleid@icloud.com"
)
APPROVAL_TIMEOUT = 120   # seconds to wait for a response
POLL_INTERVAL = 3        # seconds between chat.db polls

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------
running = True
policies = {}


# ---------------------------------------------------------------------------
# Logging  (daily file in LOG_DIR)
# ---------------------------------------------------------------------------
def setup_logging():
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    today = datetime.now().strftime("%Y-%m-%d")
    handler = logging.FileHandler(str(LOG_DIR / f"guardian-{today}.log"))
    handler.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    )
    logger = logging.getLogger("guardian")
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    stderr_h = logging.StreamHandler(sys.stderr)
    stderr_h.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    )
    logger.addHandler(stderr_h)
    return logger


log = setup_logging()


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------
def load_policies():
    try:
        with open(POLICIES_PATH) as f:
            p = json.load(f)
        log.info(
            "Policies loaded: auto_allow=%d, auto_deny=%d, ask_human=%d",
            len(p.get("auto_allow", [])),
            len(p.get("auto_deny", [])),
            len(p.get("ask_human", [])),
        )
        return p
    except Exception as e:
        log.error("Failed to load policies: %s -- denying everything", e)
        return {"auto_allow": [], "auto_deny": [], "ask_human": []}


# ---------------------------------------------------------------------------
# Request parsing
# ---------------------------------------------------------------------------
def parse_request(raw_line):
    """Parse the gateway's JSONL into (id, binary, args, raw_cmd, agent_id).

    The gateway may send different fields depending on how the exec was
    triggered. We handle three cases:
      - command + commandArgv (standard exec)
      - resolvedPath (resolved binary path)
      - systemRunPlanV2 (rich execution plan with argv and rawCommand)
    """
    req = json.loads(raw_line)

    req_id = req.get("id", "")
    command = req.get("command", "") or req.get("resolvedPath", "")
    command_argv = req.get("commandArgv") or []
    agent_id = req.get("agentId", "unknown")

    plan = req.get("systemRunPlanV2") or {}
    if plan:
        if not command_argv:
            command_argv = plan.get("argv") or []
        if not command and command_argv:
            command = command_argv[0]

    raw_cmd = (plan.get("rawCommand") or "") if plan else ""

    binary = os.path.basename(command) if command else ""

    if command_argv:
        first = command_argv[0]
        if first == command or os.path.basename(first) == binary:
            args = command_argv[1:]
        else:
            args = list(command_argv)
    else:
        args = []

    if not raw_cmd:
        raw_cmd = " ".join([binary] + args) if binary else ""

    return req_id, binary, args, raw_cmd, agent_id


# ---------------------------------------------------------------------------
# Policy checks
# ---------------------------------------------------------------------------
def check_auto_deny(raw_cmd):
    """String containment against full command. Returns (matched, pattern)."""
    for rule in policies.get("auto_deny", []):
        if rule["pattern"] in raw_cmd:
            return True, rule["pattern"]
    return False, None


def check_auto_allow(binary, args):
    """Binary + argument constraints. Returns True if auto-allowed."""
    for rule in policies.get("auto_allow", []):
        if rule["bin"] != binary:
            continue
        if "args_match" in rule:
            if args and args[0] in rule["args_match"]:
                return True
            return False
        if "args_deny" in rule:
            for denied in rule["args_deny"]:
                if denied in args:
                    return False
            return True
        return True
    return False


def check_ask_human(binary, args):
    """Binary + argument constraints. Returns True if human must approve."""
    for rule in policies.get("ask_human", []):
        if rule["bin"] != binary:
            continue
        if "args_match" in rule:
            return any(a in rule["args_match"] for a in args)
        return True
    return False


# ---------------------------------------------------------------------------
# iMessage: send + poll
# ---------------------------------------------------------------------------
def send_imessage(text):
    """Send via the imsg CLI. Falls back to osascript if imsg fails."""
    try:
        r = subprocess.run(
            [str(IMSG_CLI), "send", "--to", APPROVER_IMESSAGE, "--text", text],
            timeout=45,
            capture_output=True,
            text=True,
        )
        if r.returncode != 0:
            log.error("imsg send failed (rc=%d): %s", r.returncode, r.stderr.strip())
            return send_imessage_osascript(text)
        log.info("iMessage sent via imsg CLI")
        return True
    except FileNotFoundError:
        log.warning("imsg CLI not found at %s, trying osascript", IMSG_CLI)
        return send_imessage_osascript(text)
    except Exception as e:
        log.error("imsg send error: %s", e)
        return send_imessage_osascript(text)


def send_imessage_osascript(text):
    """Fallback: send via osascript / Messages.app."""
    escaped = text.replace("\\", "\\\\").replace('"', '\\"')
    script = (
        f'tell application "Messages"\n'
        f'  set targetBuddy to "{APPROVER_IMESSAGE}"\n'
        f'  set targetService to id of 1st account whose service type = iMessage\n'
        f'  set theBuddy to participant targetBuddy of account id targetService\n'
        f'  send "{escaped}" to theBuddy\n'
        f'end tell'
    )
    try:
        r = subprocess.run(
            ["osascript", "-e", script],
            timeout=15,
            capture_output=True,
            text=True,
        )
        if r.returncode != 0:
            log.error("osascript send failed: %s", r.stderr.strip())
            return False
        return True
    except Exception as e:
        log.error("osascript send error: %s", e)
        return False


def poll_response(code, timeout=APPROVAL_TIMEOUT):
    """Poll chat.db for OUI-{code} or NON-{code} from incoming messages."""
    deadline = time.time() + timeout
    oui = f"OUI-{code}".upper()
    non = f"NON-{code}".upper()

    while time.time() < deadline:
        try:
            db = sqlite3.connect(f"file:{CHAT_DB}?mode=ro", uri=True)
            cur = db.cursor()
            cur.execute("""
                SELECT text FROM message
                WHERE is_from_me = 0
                  AND text IS NOT NULL
                  AND datetime(date/1000000000 + 978307200, 'unixepoch')
                      > datetime('now', '-3 minutes')
                ORDER BY date DESC
                LIMIT 30
            """)
            for (text,) in cur.fetchall():
                t = (text or "").strip().upper()
                if oui in t:
                    db.close()
                    return "approve"
                if non in t:
                    db.close()
                    return "deny"
            db.close()
        except Exception as e:
            log.error("chat.db poll error: %s", e)
        time.sleep(POLL_INTERVAL)

    log.info("Timeout waiting for response (code=%s)", code)
    return "deny"


def ask_human(raw_cmd):
    """Send iMessage with approval code, poll for response."""
    code = secrets.token_hex(2)  # e.g. "a7f3"
    msg = (
        f"[EXEC] Agent wants to run:\n"
        f"{raw_cmd}\n"
        f"Reply OUI-{code} to approve or NON-{code} to deny.\n"
        f"(timeout 2 min = deny)"
    )
    log.info("Asking human (code=%s): %s", code, raw_cmd)

    if not send_imessage(msg):
        log.warning("Could not send iMessage, denying by default")
        return "deny"

    decision = poll_response(code)
    log.info("Human responded (code=%s): %s", code, decision)
    return decision


# ---------------------------------------------------------------------------
# Decision engine
# ---------------------------------------------------------------------------
def decide(req_id, binary, args, raw_cmd, agent_id):
    """4-step decision chain. Returns a JSON-serializable response dict."""

    # 1. Auto-deny (most dangerous patterns, always checked first)
    denied, pattern = check_auto_deny(raw_cmd)
    if denied:
        log.warning("DENY [auto-deny '%s'] agent=%s cmd=%s", pattern, agent_id, raw_cmd)
        return {"id": req_id, "decision": "deny"}

    # 2. Auto-allow (safe commands with known argument patterns)
    if check_auto_allow(binary, args):
        log.info("ALLOW [auto-allow] agent=%s cmd=%s", agent_id, raw_cmd)
        return {"id": req_id, "decision": "approve"}

    # 3. Ask human (sensitive commands requiring explicit approval)
    if check_ask_human(binary, args):
        log.info("ASK [ask-human] agent=%s cmd=%s", agent_id, raw_cmd)
        decision = ask_human(raw_cmd)
        return {"id": req_id, "decision": decision}

    # 4. Default: allow (unknown but not in deny list)
    log.info("ALLOW [default] agent=%s cmd=%s", agent_id, raw_cmd)
    return {"id": req_id, "decision": "approve"}


# ---------------------------------------------------------------------------
# Connection handler (runs in a thread)
# ---------------------------------------------------------------------------
def handle_connection(conn):
    try:
        conn.settimeout(200)  # 2 min approval + buffer
        data = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
            if b"\n" in data:
                break

        if not data:
            return

        line = data.split(b"\n")[0].decode("utf-8", errors="replace")
        log.info("Request: %s", line[:1000])

        req_id, binary, args, raw_cmd, agent_id = parse_request(line)
        response = decide(req_id, binary, args, raw_cmd, agent_id)

        out = json.dumps(response) + "\n"
        conn.sendall(out.encode("utf-8"))
        log.info("Response: %s", out.strip())

    except json.JSONDecodeError as e:
        log.error("JSON parse error: %s", e)
        try:
            conn.sendall(json.dumps({"decision": "deny"}).encode() + b"\n")
        except Exception:
            pass
    except Exception as e:
        log.error("Connection error: %s", e)
    finally:
        try:
            conn.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    global running, policies

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    policies = load_policies()

    if SOCK_PATH.exists():
        SOCK_PATH.unlink()

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(SOCK_PATH))
    os.chmod(str(SOCK_PATH), 0o600)  # owner-only access
    server.listen(5)
    server.settimeout(1.0)

    log.info("exec-guardian started, listening on %s", SOCK_PATH)

    def shutdown(signum, _frame):
        global running
        log.info("Signal %d received, shutting down", signum)
        running = False

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    while running:
        try:
            conn, _ = server.accept()
            t = threading.Thread(target=handle_connection, args=(conn,), daemon=True)
            t.start()
        except socket.timeout:
            continue
        except OSError as e:
            if running:
                log.error("Accept error: %s", e)
            break

    server.close()
    try:
        SOCK_PATH.unlink()
    except Exception:
        pass
    log.info("exec-guardian stopped")


if __name__ == "__main__":
    main()
