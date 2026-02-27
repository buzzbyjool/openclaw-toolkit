#!/usr/bin/env python3
"""
bridge-incoming-logger.py -- Log incoming bridge messages from bridge-reader sessions.

Scans bridge-reader session JSONL files for new incoming webhook messages
and logs them to the same bridge log directory as bridge-send.py.

Usage:
  bridge-incoming-logger.py              # Process new sessions since last run
  bridge-incoming-logger.py --all        # Reprocess all sessions
  bridge-incoming-logger.py --watch      # Run continuously (poll every 10s)

State file: ~/.openclaw/bridge/incoming-state.json
Logs to:    ~/.openclaw/bridge/logs/YYYY-MM-DD.jsonl
"""

import json
import os
import re
import signal
import sys
import time
from datetime import datetime
from pathlib import Path

SESSIONS_DIR = Path.home() / ".openclaw" / "agents" / "bridge-reader" / "sessions"
LOG_DIR = Path.home() / ".openclaw" / "bridge" / "logs"
STATE_FILE = Path.home() / ".openclaw" / "bridge" / "incoming-state.json"

# Regex to extract content between EXTERNAL_UNTRUSTED_CONTENT tags
CONTENT_RE = re.compile(
    r'<<<EXTERNAL_UNTRUSTED_CONTENT[^>]*>>>\s*Source:\s*Webhook\s*---\s*(.*?)\s*<<<END_EXTERNAL_UNTRUSTED_CONTENT',
    re.DOTALL,
)

running = True


def signal_handler(sig, frame):
    global running
    running = False


signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)


def load_state() -> dict:
    if STATE_FILE.exists():
        with open(STATE_FILE) as f:
            return json.load(f)
    return {"processed": {}}


def save_state(state: dict):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def log_entry(entry: dict):
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    ts = entry.get("timestamp", datetime.now().isoformat())
    try:
        date_str = ts[:10]
    except Exception:
        date_str = datetime.now().strftime("%Y-%m-%d")
    log_file = LOG_DIR / f"{date_str}.jsonl"
    with open(log_file, "a") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def extract_sender(message_text: str) -> str:
    """Extract sender from bridge prefix like [BRIDGE:AGENT-A]."""
    m = re.match(r'\[BRIDGE:(\w+(?:-\w+)*)\]', message_text.strip())
    if m:
        return m.group(1).lower()
    return "unknown"


def process_session(session_file: Path) -> list:
    """Parse a bridge-reader session JSONL and extract incoming messages."""
    entries = []

    with open(session_file) as f:
        lines = f.readlines()

    user_message = None
    user_timestamp = None
    assistant_response = None
    assistant_timestamp = None

    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue

        msg = obj.get("message", {})
        role = msg.get("role", "")
        ts = obj.get("timestamp", "")

        if role == "user":
            content = msg.get("content", "")
            if isinstance(content, list):
                texts = []
                for c in content:
                    if isinstance(c, dict) and c.get("type") == "text":
                        texts.append(c["text"])
                content = "\n".join(texts)

            match = CONTENT_RE.search(content)
            if match:
                user_message = match.group(1).strip()
                user_timestamp = ts

        elif role == "assistant":
            content = msg.get("content", "")
            if isinstance(content, list):
                texts = []
                for c in content:
                    if isinstance(c, dict) and c.get("type") == "text":
                        texts.append(c["text"])
                content = "\n".join(texts)
            assistant_response = content.strip()
            assistant_timestamp = ts

    if user_message:
        sender = extract_sender(user_message)
        entry = {
            "timestamp": user_timestamp or datetime.now().isoformat(),
            "direction": "IN",
            "source": sender,
            "session_id": session_file.stem,
            "raw_message": user_message,
            "bridge_reader_rewrite": assistant_response,
            "bridge_reader_timestamp": assistant_timestamp,
        }
        entries.append(entry)

    return entries


def process_all(reprocess: bool = False):
    """Scan all bridge-reader sessions and log new ones."""
    state = load_state()
    processed = state.get("processed", {})

    if not SESSIONS_DIR.exists():
        print(f"Sessions directory not found: {SESSIONS_DIR}")
        return 0

    session_files = sorted(SESSIONS_DIR.glob("*.jsonl"), key=lambda f: f.stat().st_mtime)
    new_count = 0

    for sf in session_files:
        session_id = sf.stem
        mtime = sf.stat().st_mtime

        if not reprocess and session_id in processed:
            if processed[session_id] >= mtime:
                continue

        entries = process_session(sf)
        for entry in entries:
            log_entry(entry)
            new_count += 1
            sender = entry.get("source", "?")
            ts = entry.get("timestamp", "?")
            msg_preview = entry.get("raw_message", "")[:80]
            print(f"[{ts}] IN from {sender}: {msg_preview}")

        processed[session_id] = mtime

    state["processed"] = processed
    state["last_run"] = datetime.now().isoformat()
    save_state(state)

    return new_count


def watch_mode():
    """Continuously poll for new sessions."""
    print(f"Watching {SESSIONS_DIR} for incoming bridge messages (Ctrl+C to stop)")
    while running:
        n = process_all()
        if n > 0:
            print(f"  -> {n} new incoming message(s) logged")
        time.sleep(10)
    print("Stopped.")


def main():
    reprocess = "--all" in sys.argv
    watch = "--watch" in sys.argv

    if watch:
        process_all(reprocess=reprocess)
        watch_mode()
    else:
        n = process_all(reprocess=reprocess)
        if n == 0:
            print("No new incoming messages.")
        else:
            print(f"\n{n} incoming message(s) logged to {LOG_DIR}/")


if __name__ == "__main__":
    main()
