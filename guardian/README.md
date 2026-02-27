# exec-guardian

Runtime exec enforcement daemon for OpenClaw agents. Applies graduated security policies and routes sensitive commands to a human approver via iMessage.

## How it works

```
Agent exec request
       |
       v
OpenClaw Gateway
       |
       |-- Binary in allowlist? --> auto-execute (gateway handles this)
       |-- Not in allowlist, ask: on-miss --> Unix socket
       v
exec-guardian.py (daemon)
       |
       |-- Match auto-deny pattern? --> DENY
       |-- Match auto-allow rule? --> APPROVE
       |-- Match ask-human rule? --> iMessage notification
       |       |
       |       |-- OUI-{code} reply --> APPROVE
       |       |-- NON-{code} reply or timeout --> DENY
       |
       |-- No rule matched --> APPROVE (default)
```

### Three tiers

1. **auto-deny** -- Substring match against the full command string. Catches destructive patterns like `rm -rf /`, `sudo`, `chmod 777`. Evaluated first, always wins.

2. **auto-allow** -- Matches on binary name plus optional argument constraints (`args_match` for allowed subcommands, `args_deny` for blocked flags). Example: `git status` is auto-allowed, `git push` is not.

3. **ask-human** -- Same matching as auto-allow but triggers iMessage approval instead of auto-approving. The daemon sends a message with a random approval code, polls `chat.db` for the response. Timeout = deny.

## Prerequisites

- **OpenClaw 2026.2.24+** with exec-approvals support
- **macOS** (for iMessage integration and `chflags` immutability)
- **Python 3.9+** (stdlib only)
- **`imsg` CLI** for sending iMessages. Source: https://github.com/steipete/imsg
- **Full Disk Access** granted to `/usr/bin/python3` (required to read `chat.db`)

## Setup

### 1. Create directories

```bash
mkdir -p ~/.openclaw/guardian/logs
```

### 2. Copy files

```bash
cp exec-guardian.py ~/.openclaw/guardian/
cp policies.json ~/.openclaw/guardian/
```

### 3. Configure the approver

Edit `exec-guardian.py` and set `APPROVER_IMESSAGE` to your Apple ID, or export the environment variable:

```bash
export GUARDIAN_APPROVER_IMESSAGE="your.appleid@icloud.com"
```

### 4. Configure the gateway

Generate a socket token:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(24))"
```

Edit `exec-approvals-example.json` with your token, then apply:

```bash
openclaw approvals set --file exec-approvals-example.json
```

### 5. Install the LaunchAgent

Edit `../launchd/com.openclaw.exec-guardian.plist` to fix paths for your home directory, then:

```bash
cp ../launchd/com.openclaw.exec-guardian.plist ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/com.openclaw.exec-guardian.plist
```

### 6. Verify

```bash
# Check the daemon is running
launchctl list | grep exec-guardian

# Check the socket exists
ls -la ~/.openclaw/exec-approvals.sock

# Check the logs
tail -f ~/.openclaw/guardian/logs/guardian-$(date +%Y-%m-%d).log
```

### 7. Lock the files (recommended)

```bash
chflags uchg ~/.openclaw/guardian/exec-guardian.py
chflags uchg ~/.openclaw/guardian/policies.json
```

This prevents the agent from modifying its own enforcer. To update policies later:

```bash
chflags nouchg ~/.openclaw/guardian/policies.json
# ... edit ...
chflags uchg ~/.openclaw/guardian/policies.json
launchctl kickstart -k gui/$(id -u)/com.openclaw.exec-guardian
```

## Testing

### Auto-allow test

```bash
python3 -c "
import socket, json
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect('$HOME/.openclaw/exec-approvals.sock')
req = {'id': 'test-1', 'command': '/usr/bin/git', 'commandArgv': ['git', 'status'], 'agentId': 'main'}
s.sendall(json.dumps(req).encode() + b'\n')
print(s.recv(4096).decode())
s.close()
"
# Expected: {"id": "test-1", "decision": "approve"}
```

### Auto-deny test

```bash
python3 -c "
import socket, json
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect('$HOME/.openclaw/exec-approvals.sock')
req = {'id': 'test-2', 'command': '/usr/bin/sudo', 'commandArgv': ['sudo', 'rm', '-rf', '/'], 'agentId': 'main'}
s.sendall(json.dumps(req).encode() + b'\n')
print(s.recv(4096).decode())
s.close()
"
# Expected: {"id": "test-2", "decision": "deny"}
```

## Files

| File | Purpose |
|------|---------|
| `exec-guardian.py` | The daemon (copy to `~/.openclaw/guardian/`) |
| `policies.json` | Policy template (copy to `~/.openclaw/guardian/`) |
| `exec-approvals-example.json` | Gateway config template |

## Adapting for Linux

Replace `chflags uchg` / `nouchg` with `chattr +i` / `-i` (requires root). Replace the LaunchAgent plist with a systemd user unit. See [../docs/exec-guardian-deep-dive.md](../docs/exec-guardian-deep-dive.md) for details.

## Security properties

- **Fail-closed**: every error defaults to deny
- **Out-of-band approval**: iMessage is outside the agent's control
- **Tamper-resistant**: daemon and policies locked with filesystem immutability
- **Socket isolation**: Unix socket with 0600 permissions (owner-only)
- **No supply chain**: stdlib only, zero pip dependencies
