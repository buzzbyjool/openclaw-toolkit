# OpenClaw Dashboard

Lightweight web monitoring dashboard for OpenClaw agents. Displays bridge communication logs, exec-guardian security decisions, and memory status in a dark-themed UI.

**Stack**: Python 3.9+ stdlib only (zero dependencies). Single file serves both the JSON API and the HTML/CSS/JS.

## Panels

### Bridge
- Incoming (blue) and outgoing (green) inter-agent messages with timestamps
- Bridge-reader rewrites (how the agent reformulated the incoming message)
- HTTP status and duration for outgoing messages
- Click any message to see the full JSON payload
- Pagination (25 items/page)

### Security
- exec-guardian log entries with colored badges: ALLOW (green), DENY (red), ASK (yellow)
- Summary stats: allow/deny/ask/total counts
- Standard Python logging format

### Memory
- Vector DB status per agent (chunks, files, size, health)
- Extract/distill history with expandable details
- Daily memory files listing
- Current MEMORY.md content

## Setup

### 1. Create directories

```bash
mkdir -p ~/.openclaw/dashboard
mkdir -p ~/.openclaw/bridge/logs
```

### 2. Deploy

```bash
cp openclaw-dashboard.py ~/.openclaw/dashboard/
```

### 3. Configure paths

The script uses `Path.home()` to resolve all paths. Default structure:

```
~/.openclaw/bridge/logs/         # Bridge JSONL logs
~/.openclaw/guardian/logs/       # exec-guardian logs
~/.openclaw/workspace/MEMORY.md  # Agent memory
~/.openclaw/workspace/memory/    # Memory files
~/.openclaw/memory/              # Vector DB (sqlite)
```

Edit the path constants at the top of the script if your layout differs.

### 4. Run

```bash
python3 ~/.openclaw/dashboard/openclaw-dashboard.py
# Dashboard available at http://127.0.0.1:18790
```

### 5. Expose via Tailscale Serve (optional)

```bash
tailscale serve --bg --set-path /dashboard http://127.0.0.1:18790
# Dashboard available at https://<hostname>.tail<xxx>.ts.net/dashboard
```

### 6. Install as LaunchAgent (macOS)

Edit `../launchd/com.openclaw.dashboard.plist` to fix paths, then:

```bash
cp ../launchd/com.openclaw.dashboard.plist ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/com.openclaw.dashboard.plist
```

For Linux, use a systemd user unit with `Restart=always`.

## Log formats

### Bridge JSONL

Outgoing:
```json
{"timestamp":"2026-02-27T15:17:45","direction":"OUT","target":"agent-b","message":"content","http_status":202,"duration_ms":125}
```

Incoming:
```json
{"timestamp":"2026-02-27T14:52:51","direction":"IN","source":"agent-a","raw_message":"[BRIDGE:AGENT-A] Hello","bridge_reader_rewrite":"Message received."}
```

### Guardian log

Standard Python logging:
```
2026-02-27 11:47:31,725 [INFO] ALLOW [auto-allow] agent=main cmd=git status
2026-02-27 11:47:40,725 [WARNING] DENY [auto-deny 'rm -rf /'] agent=main cmd=sudo rm -rf /
```

## Customization

- **Port**: change `PORT = 18790` at the top of the script
- **URL prefix**: if not using `/dashboard`, update the JS API paths and the prefix strip in `do_GET()`
- **Branding**: the header uses the OpenClaw SVG logo and Clash Display / Satoshi fonts. Replace with your own identity if needed.
- **Auto-refresh interval**: default is 30 seconds, configurable via the checkbox in the header
