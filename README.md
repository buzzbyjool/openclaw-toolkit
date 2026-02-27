# OpenClaw Toolkit

Security and monitoring tools for [OpenClaw](https://openclaw.ai) agents.

[![License: CC BY-NC-SA 4.0](https://img.shields.io/badge/License-CC%20BY--NC--SA%204.0-lightgrey.svg)](https://creativecommons.org/licenses/by-nc-sa/4.0/)

---

## What's inside

### [guardian/](guardian/) -- Runtime exec enforcement

A Python daemon that sits between the OpenClaw gateway and the shell. It applies graduated policies (auto-deny, auto-allow, ask-human) and requests human approval for sensitive commands via iMessage. The agent never sees the approval flow.

### [dashboard/](dashboard/) -- Monitoring web UI

A single-file Python web server (zero dependencies) that displays bridge logs, exec-guardian decisions, and memory status in a dark-themed dashboard. Designed for Tailscale Serve exposure.

### [bridge/](bridge/) -- Inter-agent communication logging

Scripts for sending messages between OpenClaw agents via webhooks, with full JSONL logging of every exchange (direction, timestamps, HTTP status, response body, duration).

### [launchd/](launchd/) -- macOS service templates

LaunchAgent plist files for running the above tools as background services on macOS.

### [docs/](docs/) -- Technical articles

In-depth write-ups on architecture, design decisions, and implementation details.

---

## Requirements

- **Python 3.9+** (stdlib only, zero pip dependencies)
- **macOS** (for iMessage integration and `chflags` immutability; see docs for Linux adaptation)
- **OpenClaw 2026.2.24+** with exec-approvals support

---

## Quick start

### 1. exec-guardian

```bash
# Create directories
mkdir -p ~/.openclaw/guardian/logs

# Copy files
cp guardian/exec-guardian.py ~/.openclaw/guardian/
cp guardian/policies.json ~/.openclaw/guardian/

# Edit the approver iMessage address
# In exec-guardian.py, set APPROVER_IMESSAGE or export the env var:
export GUARDIAN_APPROVER_IMESSAGE="your.appleid@icloud.com"

# Configure the gateway
# Edit guardian/exec-approvals-example.json with your token, then:
openclaw approvals set --file exec-approvals-example.json

# Install the LaunchAgent
cp launchd/com.openclaw.exec-guardian.plist ~/Library/LaunchAgents/
# Edit the plist to fix paths, then:
launchctl load ~/Library/LaunchAgents/com.openclaw.exec-guardian.plist
```

### 2. Dashboard

```bash
mkdir -p ~/.openclaw/dashboard
cp dashboard/openclaw-dashboard.py ~/.openclaw/dashboard/

# Run directly
python3 ~/.openclaw/dashboard/openclaw-dashboard.py

# Or install as LaunchAgent (edit plist paths first)
cp launchd/com.openclaw.dashboard.plist ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/com.openclaw.dashboard.plist

# Expose via Tailscale Serve
tailscale serve --bg --set-path /dashboard http://127.0.0.1:18790
```

### 3. Bridge logging

```bash
mkdir -p ~/.openclaw/bridge/logs

# Copy and configure
cp bridge/bridge-send.py ~/.openclaw/bridge/
cp bridge/bridge-config-example.json ~/.openclaw/bridge/config.json
# Edit config.json with your webhook URLs and tokens

# Send a message
python3 ~/.openclaw/bridge/bridge-send.py --to agent-b --message "Hello from agent A"

# Install the incoming logger (edit plist paths first)
cp bridge/bridge-incoming-logger.py ~/.openclaw/bridge/
cp launchd/com.openclaw.bridge-incoming-logger.plist ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/com.openclaw.bridge-incoming-logger.plist
```

---

## Security model

All three tools follow the same principles:

- **Fail-closed**: every error path defaults to deny or safe behavior
- **Out-of-band approval**: human decisions go through iMessage, outside the agent's control
- **Tamper-resistant**: critical files are locked with `chflags uchg` (macOS) or `chattr +i` (Linux)
- **Zero trust in agent output**: the agent cannot modify its own enforcer
- **Stdlib only**: no supply-chain risk from third-party packages

See [docs/exec-guardian-deep-dive.md](docs/exec-guardian-deep-dive.md) for the full security analysis.

---

## Who we are

**[Easylab AI](https://easylab.ai)** is a Luxembourg-based company building AI-powered tools for business operations. We run an autonomous OpenClaw agent in production -- handling emails, calendars, infrastructure monitoring, client projects, and inter-agent communication -- 24/7, with no manual intervention on routine tasks.

These tools are extracted from that deployment. We built them because the default security model wasn't enough for real business use: we needed graduated exec policies, human-in-the-loop approval for sensitive commands, and full audit trails on everything the agent does.

We document the full architecture, the 12 security layers, the incidents we've had, and the behavioral scoring system on our dedicated site:

**[openclaw.easylab.ai](https://openclaw.easylab.ai)** -- Case study, security architecture, behavioral trust scoring, and more.

---

## License

[CC BY-NC-SA 4.0](LICENSE) -- Attribution to [Easylab AI](https://easylab.ai) required. Non-commercial use only.

---

Built by [Easylab AI](https://easylab.ai) -- [easylab.ai](https://easylab.ai) | [openclaw.easylab.ai](https://openclaw.easylab.ai) -- Luxembourg.
