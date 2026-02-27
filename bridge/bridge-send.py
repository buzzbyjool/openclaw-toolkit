#!/usr/bin/env python3
"""
bridge-send.py -- Bridge message sender with full logging.
Sends a message to a target agent via webhook and logs everything.

Usage:
  bridge-send.py --to agent-b --message "message content"
  bridge-send.py --to agent-b --file /tmp/message.txt

Configuration: ~/.openclaw/bridge/config.json
  See bridge-config-example.json for the format.

Logs to: ~/.openclaw/bridge/logs/YYYY-MM-DD.jsonl
Each line is a JSON object with: timestamp, direction, target, message,
http_status, response_body, duration_ms
"""

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

# --- Config ---

CONFIG_FILE = Path.home() / ".openclaw" / "bridge" / "config.json"
LOG_DIR = Path.home() / ".openclaw" / "bridge" / "logs"
TIMEOUT_SECONDS = 60


def load_targets() -> dict:
    """Load target configuration from config file."""
    if not CONFIG_FILE.exists():
        print(f"ERROR: Config file not found: {CONFIG_FILE}", file=sys.stderr)
        print(
            "Copy bridge-config-example.json to ~/.openclaw/bridge/config.json and edit it.",
            file=sys.stderr,
        )
        sys.exit(1)
    with open(CONFIG_FILE) as f:
        config = json.load(f)
    return config.get("targets", {})


def log_entry(entry: dict):
    """Append a JSON line to today's log file."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_file = LOG_DIR / f"{datetime.now().strftime('%Y-%m-%d')}.jsonl"
    with open(log_file, "a") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def send_message(target_name: str, message: str, targets: dict) -> dict:
    """Send message via curl, log everything, return result."""
    target = targets[target_name]

    body = {
        "message": f"{target['prefix']} {message}",
        "agentId": target["agent_id"],
        "timeoutSeconds": TIMEOUT_SECONDS,
    }

    body_json = json.dumps(body, ensure_ascii=False)

    entry = {
        "timestamp": datetime.now().isoformat(),
        "direction": "OUT",
        "target": target_name,
        "url": target["url"],
        "message": message,
        "body": body,
        "http_status": None,
        "response_body": None,
        "duration_ms": None,
        "error": None,
    }

    cmd = [
        "curl", "-s",
        "-w", "\n%{http_code}",
        "-X", "POST", target["url"],
        "-H", f"Authorization: Bearer {target['token']}",
        "-H", "Content-Type: application/json",
        "-d", body_json,
    ]

    t0 = time.time()
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=90,
        )
        duration_ms = int((time.time() - t0) * 1000)

        output_lines = result.stdout.strip().rsplit("\n", 1)
        if len(output_lines) == 2:
            response_body = output_lines[0]
            http_status = int(output_lines[1])
        elif len(output_lines) == 1:
            try:
                http_status = int(output_lines[0])
                response_body = ""
            except ValueError:
                response_body = output_lines[0]
                http_status = -1
        else:
            response_body = result.stdout
            http_status = -1

        entry["http_status"] = http_status
        entry["response_body"] = response_body[:2000]
        entry["duration_ms"] = duration_ms

        if result.returncode != 0:
            entry["error"] = f"curl exit code {result.returncode}: {result.stderr[:500]}"

    except subprocess.TimeoutExpired:
        duration_ms = int((time.time() - t0) * 1000)
        entry["duration_ms"] = duration_ms
        entry["error"] = "curl timeout (90s)"

    except Exception as e:
        duration_ms = int((time.time() - t0) * 1000)
        entry["duration_ms"] = duration_ms
        entry["error"] = str(e)

    log_entry(entry)

    return entry


def main():
    targets = load_targets()

    parser = argparse.ArgumentParser(description="Send bridge message with logging")
    parser.add_argument(
        "--to", required=True, choices=list(targets.keys()), help="Target agent"
    )
    parser.add_argument("--message", help="Message content")
    parser.add_argument("--file", help="Read message from file")
    args = parser.parse_args()

    if args.file:
        with open(args.file) as f:
            message = f.read().strip()
    elif args.message:
        message = args.message
    else:
        print("ERROR: --message or --file required", file=sys.stderr)
        sys.exit(1)

    result = send_message(args.to, message, targets)

    status = result["http_status"]
    duration = result["duration_ms"]
    error = result["error"]

    if error:
        print(f"ERROR: {error}")
        sys.exit(1)
    elif status == 202:
        print(f"OK (HTTP {status}, {duration}ms)")
        if result["response_body"]:
            print(f"Response: {result['response_body'][:500]}")
    else:
        print(f"HTTP {status} ({duration}ms)")
        if result["response_body"]:
            print(f"Response: {result['response_body'][:500]}")

    log_file = LOG_DIR / f"{datetime.now().strftime('%Y-%m-%d')}.jsonl"
    print(f"Log: {log_file}")


if __name__ == "__main__":
    main()
