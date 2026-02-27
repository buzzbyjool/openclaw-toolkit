# Bridge Logging

Inter-agent communication tools with full JSONL logging. Designed for OpenClaw agents that communicate via webhooks (e.g. through Tailscale Serve).

## Components

### bridge-send.py -- Outgoing messages

Sends a message to a target agent via webhook and logs the full exchange (request body, HTTP status, response, duration).

```bash
# Send a message
python3 bridge-send.py --to agent-b --message "Hello from agent A"

# Send a long message from file
python3 bridge-send.py --to agent-b --file /tmp/message.txt
```

### bridge-incoming-logger.py -- Incoming messages

Scans bridge-reader session files for incoming webhook messages and logs them in the same JSONL format. Can run as a one-shot scan or as a continuous watcher.

```bash
# One-shot: process new sessions since last run
python3 bridge-incoming-logger.py

# Reprocess all sessions
python3 bridge-incoming-logger.py --all

# Continuous watch (poll every 10s)
python3 bridge-incoming-logger.py --watch
```

## Setup

### 1. Create directories

```bash
mkdir -p ~/.openclaw/bridge/logs
```

### 2. Configure targets

Copy the example config and edit it with your webhook URLs and tokens:

```bash
cp bridge-config-example.json ~/.openclaw/bridge/config.json
```

Edit `~/.openclaw/bridge/config.json`:

```json
{
  "targets": {
    "agent-b": {
      "url": "https://your-agent-b.tailXXXXX.ts.net/hooks/agent",
      "token": "your-webhook-token-here",
      "prefix": "[BRIDGE:AGENT-A]",
      "agent_id": "bridge-reader"
    }
  }
}
```

- **url**: The target agent's webhook endpoint
- **token**: Bearer token for authentication
- **prefix**: Tag prepended to messages so the receiver knows the sender
- **agent_id**: Which agent on the target should handle the message

### 3. Deploy scripts

```bash
cp bridge-send.py ~/.openclaw/bridge/
cp bridge-incoming-logger.py ~/.openclaw/bridge/
```

### 4. Install the incoming logger as LaunchAgent (optional)

Edit `../launchd/com.openclaw.bridge-incoming-logger.plist` to fix paths, then:

```bash
cp ../launchd/com.openclaw.bridge-incoming-logger.plist ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/com.openclaw.bridge-incoming-logger.plist
```

This runs the logger every 60 seconds via launchd's `StartInterval`.

## Log format

All logs go to `~/.openclaw/bridge/logs/YYYY-MM-DD.jsonl`. Each line is a JSON object.

### Outgoing (direction: OUT)

```json
{
  "timestamp": "2026-02-27T15:17:45.123456",
  "direction": "OUT",
  "target": "agent-b",
  "url": "https://...",
  "message": "Hello from agent A",
  "body": {"message": "[BRIDGE:AGENT-A] Hello from agent A", "agentId": "bridge-reader", "timeoutSeconds": 60},
  "http_status": 202,
  "response_body": "...",
  "duration_ms": 125,
  "error": null
}
```

### Incoming (direction: IN)

```json
{
  "timestamp": "2026-02-27T14:52:51.789012",
  "direction": "IN",
  "source": "agent-a",
  "session_id": "abc123-def456",
  "raw_message": "[BRIDGE:AGENT-A] Hello",
  "bridge_reader_rewrite": "Agent A says hello.",
  "bridge_reader_timestamp": "2026-02-27T14:52:55.123456"
}
```

## How it works

### Sending

`bridge-send.py` reads targets from `~/.openclaw/bridge/config.json`, constructs the webhook payload, sends it via `curl`, and logs the full exchange before returning.

### Receiving

OpenClaw routes incoming webhook messages to a `bridge-reader` agent, which processes them and writes session JSONL files. `bridge-incoming-logger.py` scans these session files, extracts the incoming message (from the `EXTERNAL_UNTRUSTED_CONTENT` wrapper) and the agent's response, and writes a unified log entry.

### Dashboard integration

The [dashboard](../dashboard/) reads these JSONL logs and displays them in the Bridge panel. Both outgoing and incoming messages appear in chronological order with all metadata.

## Prerequisites

- **Python 3.9+** (stdlib only)
- **curl** (for sending)
- **OpenClaw** with webhook hooks and a `bridge-reader` agent configured
- **Tailscale** (recommended for secure agent-to-agent communication)
