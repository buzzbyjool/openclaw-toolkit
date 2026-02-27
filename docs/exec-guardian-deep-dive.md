# Runtime Exec Enforcement for OpenClaw: A Python Daemon for Human-in-the-Loop Command Approval

**Author:** Julien Doussot, Easylab AI (Luxembourg)
**OpenClaw version:** 2026.2.24+
**Platform:** macOS (adaptable to Linux, see notes at the end)

---

## The problem

OpenClaw's built-in exec security model gives you two options: allowlist (only whitelisted binaries can run) and permissive (everything runs). The allowlist is good for locking down sub-agents like `mail-reader` where you know exactly which commands are needed. But for a general-purpose agent that needs to do real work (git operations, file manipulation, package management, SSH), a static allowlist is either too restrictive or too permissive.

What we wanted was a third path: a daemon that sits between the gateway and the shell, applies graduated policies, and asks a human for approval on sensitive commands via an out-of-band channel. The agent never sees the approval flow. The human gets an iMessage, replies with a code, and the daemon forwards the decision.

This post documents the full implementation. Everything here is reproducible with Python 3.9+ stdlib, the `imsg` CLI, and an OpenClaw instance with exec-approvals support.

---

## Architecture overview

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
       |       |
       |-- No rule matched --> APPROVE (default)
```

The key design decisions:

1. **Gateway handles the fast path.** Common safe binaries (`ls`, `cat`, `grep`, `python3`) are in the gateway's own allowlist and never hit the daemon. Zero latency for routine operations.

2. **Daemon handles the gray area.** Commands that pass the gateway but need policy evaluation go through the Unix socket to `exec-guardian.py`.

3. **Three tiers in the daemon.** Auto-deny for destructive patterns (evaluated first, always wins). Auto-allow for known-safe command+argument combinations. Ask-human for sensitive operations that need explicit approval.

4. **Human approval is out-of-band.** The agent cannot intercept, modify, or forge the approval. iMessage goes through the OS-level Messages framework, and the response is read directly from `chat.db` via SQLite.

---

## Prerequisites

- **OpenClaw 2026.2.24+** with `exec-approvals` support (the socket-based approval protocol)
- **macOS** (for `chflags` filesystem immutability and iMessage integration)
- **Python 3.9+** (stdlib only, no pip dependencies)
- **`imsg` CLI** compiled for your architecture. Source: https://github.com/steipete/imsg. On Intel Macs you need to build from source since the release binary is arm64 only:
  ```bash
  cd /tmp && git clone https://github.com/steipete/imsg.git && cd imsg
  swift build -c release
  cp .build/release/imsg ~/.local/bin/imsg
  ```
- **Full Disk Access** granted to `/usr/bin/python3` in System Preferences (required to read `chat.db`)

---

## Step 1: Filesystem protection

Before anything else, lock down the files that define the agent's identity, rules, and configuration. macOS `chflags uchg` sets the user immutable flag. Even the file owner cannot write to these files until the flag is removed.

```bash
chflags uchg ~/.openclaw/workspace/SOUL.md \
  ~/.openclaw/workspace/SECURITY.md \
  ~/.openclaw/workspace/AGENTS.md \
  ~/.openclaw/workspace/IDENTITY.md \
  ~/.openclaw/workspace/TOOLS.md \
  ~/.openclaw/openclaw.json
```

Why this matters: we had an incident where the agent modified `openclaw.json` while creating a sub-agent, changed the default agent routing, and went silent for three days. Everything was being routed to a crippled sub-agent. Filesystem immutability prevents this class of failure entirely.

To make legitimate changes later:

```bash
chflags nouchg ~/.openclaw/openclaw.json
# ... make your edit ...
chflags uchg ~/.openclaw/openclaw.json
```

---

## Step 2: Create the guardian directory

```bash
mkdir -p ~/.openclaw/guardian/logs
```

---

## Step 3: Gateway exec-approvals configuration

This tells the OpenClaw gateway to use a Unix socket for approval decisions when a command is not in the allowlist.

See `guardian/exec-approvals-example.json` in this repository for a complete template.

Generate your own socket token:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(24))"
```

Apply the configuration:

```bash
openclaw approvals set --file /path/to/exec-approvals.json
```

The `askFallback: "deny"` setting is important: if the daemon is unreachable or crashes, the gateway denies the command rather than allowing it. Safe default.

The allowlist contains only read-only or side-effect-free binaries. Anything that can modify state (`git`, `rm`, `brew`, `npm`, `ssh`, `kill`, etc.) is deliberately excluded so it hits the daemon for policy evaluation.

---

## Step 4: Policy definitions

See `guardian/policies.json` in this repository for a complete template.

### Matching logic

The three policy tiers are evaluated in strict order: auto-deny first, then auto-allow, then ask-human. First match wins.

**auto_deny** -- string containment check against the full reconstructed command string. If the pattern appears anywhere in the command, it is denied. This is intentionally broad. `"sudo"` catches `sudo anything`. `"chflags nouchg"` prevents the agent from unlocking its own protected files.

**auto_allow** -- matches on binary name plus optional argument constraints:

- `args_match`: the first argument (subcommand) must be in the list. Example: `git status` matches because `"status"` is in the list. `git push` does not match, so it falls through to the next tier.
- `args_deny`: the binary is allowed UNLESS any argument matches the deny list. Example: `npm install express` is allowed, but `npm install -g express` is denied because `"-g"` is in `args_deny`.
- No argument constraints: the binary name alone triggers approval. Example: `curl` with any arguments is auto-allowed. Adjust this based on your threat model.

**ask_human** -- same matching as auto_allow but triggers human approval instead of auto-approving:

- `args_match`: any argument (not just the first) must match. Example: for `git`, `"push"` appearing anywhere in the args triggers approval.
- No `args_match`: the binary name alone triggers. Example: any `rm` command, regardless of arguments, requires human approval.

**Default (no match):** if a command does not match any tier, it is approved. This is a pragmatic choice. The auto-deny tier catches the dangerous patterns. Unknown commands that are not in the deny list are unlikely to be destructive. You can change this to deny-by-default if your threat model requires it, but expect a lot of approval requests.

---

## Step 5: The daemon

See `guardian/exec-guardian.py` in this repository for the complete source code.

### Key implementation notes

**parse_request():** The gateway's exec-approval protocol can send command information in multiple formats. The `command` field contains the resolved binary path. `commandArgv` contains the argument vector. `systemRunPlanV2` is an optional richer structure that includes `argv` and `rawCommand`. The parser normalizes all three into a consistent (binary, args, raw_cmd) tuple.

**decide():** The four steps are evaluated strictly in order. Auto-deny always runs first so that dangerous patterns cannot be bypassed by also matching an auto-allow rule. This ordering is critical.

**ask_human():** Generates a random 4-character hex code (e.g. `a7f3`) and includes it in both the approval and denial keywords. This prevents replay attacks: a stale "OUI" from an earlier approval cannot authorize a different command. The code is single-use by design.

**poll_response():** Reads `chat.db` directly via SQLite in read-only mode. It looks at incoming messages (`is_from_me=0`) from the last 3 minutes and checks for the approval code. The macOS Messages database uses Apple's Core Data epoch (2001-01-01) so the timestamp conversion adds `978307200` seconds.

**Socket permissions:** `chmod 0o600` on the socket file means only the user running the daemon can connect to it. Other users on the system cannot send fake approval requests.

**Threading:** Each incoming connection spawns a daemon thread. This is necessary because the ask-human path blocks for up to 2 minutes while polling for a response. Without threading, a pending human approval would block all other exec requests.

**Error handling:** Every failure path defaults to deny. JSON parse error: deny. Socket error: deny. iMessage send failure: deny. Timeout: deny. The daemon never fails open.

---

## Step 6: LaunchAgent

See `launchd/com.openclaw.exec-guardian.plist` in this repository. Edit the paths to match your home directory, then:

```bash
cp com.openclaw.exec-guardian.plist ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/com.openclaw.exec-guardian.plist
```

Verify it is running:

```bash
launchctl list | grep exec-guardian
# Should show PID and exit status 0

ls -la ~/.openclaw/exec-approvals.sock
# Should show the socket file with 0600 permissions
```

Check the log:

```bash
tail -f ~/.openclaw/guardian/logs/guardian-$(date +%Y-%m-%d).log
```

---

## Step 7: Lock the daemon files

Once everything works, make the daemon and its policies immutable:

```bash
chflags uchg ~/.openclaw/guardian/exec-guardian.py \
  ~/.openclaw/guardian/policies.json
```

This prevents the agent from modifying its own enforcer. To update policies later:

```bash
chflags nouchg ~/.openclaw/guardian/policies.json
# ... edit ...
chflags uchg ~/.openclaw/guardian/policies.json
# The daemon reads policies at startup; restart it to pick up changes:
launchctl kickstart -k gui/$(id -u)/com.openclaw.exec-guardian
```

---

## Testing

### Test auto-allow

```bash
python3 -c "
import socket, json
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect('$HOME/.openclaw/exec-approvals.sock')
req = {
    'id': 'test-1',
    'command': '/usr/bin/git',
    'commandArgv': ['git', 'status'],
    'agentId': 'main'
}
s.sendall(json.dumps(req).encode() + b'\n')
print(s.recv(4096).decode())
s.close()
"
```

Expected output:

```json
{"id": "test-1", "decision": "approve"}
```

### Test auto-deny

```bash
python3 -c "
import socket, json
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect('$HOME/.openclaw/exec-approvals.sock')
req = {
    'id': 'test-2',
    'command': '/usr/bin/sudo',
    'commandArgv': ['sudo', 'rm', '-rf', '/'],
    'agentId': 'main'
}
s.sendall(json.dumps(req).encode() + b'\n')
print(s.recv(4096).decode())
s.close()
"
```

Expected output:

```json
{"id": "test-2", "decision": "deny"}
```

### Test ask-human (requires iMessage)

```bash
python3 -c "
import socket, json
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect('$HOME/.openclaw/exec-approvals.sock')
req = {
    'id': 'test-3',
    'command': '/usr/bin/git',
    'commandArgv': ['git', 'push', 'origin', 'main'],
    'agentId': 'main'
}
s.sendall(json.dumps(req).encode() + b'\n')
print('Waiting for iMessage approval (check your phone)...')
print(s.recv(4096).decode())
s.close()
"
```

You should receive an iMessage like:

```
[EXEC] Agent wants to run:
git push origin main
Reply OUI-a7f3 to approve or NON-a7f3 to deny.
(timeout 2 min = deny)
```

Reply `OUI-a7f3` and the test should print `{"id": "test-3", "decision": "approve"}`.

### Check the logs

After running the tests:

```bash
cat ~/.openclaw/guardian/logs/guardian-$(date +%Y-%m-%d).log
```

You should see entries like:

```
2026-02-27 10:15:03,421 [INFO] Request: {"id":"test-1","command":"/usr/bin/git",...}
2026-02-27 10:15:03,422 [INFO] ALLOW [auto-allow] agent=main cmd=git status
2026-02-27 10:15:03,422 [INFO] Response: {"id": "test-1", "decision": "approve"}
```

---

## Security considerations

**Tamper resistance.** The daemon script and policies are protected by `chflags uchg`. The agent cannot modify, replace, or delete them. The `chflags nouchg` command is itself in the auto-deny list, so the agent cannot unlock the files through the daemon either.

**Socket access control.** The Unix socket is created with `0600` permissions (owner read/write only). Other users on the system cannot connect to it. The socket path is inside `~/.openclaw/` which should already be `0700`.

**Fail-closed design.** Every error path in the daemon results in a deny decision. Policy file missing: deny all. JSON parse error: deny. iMessage send failure: deny. Timeout waiting for human: deny. Socket error: deny. The daemon never fails open.

**Out-of-band approval.** The human approval happens through iMessage, which is completely outside the agent's control. The agent does not see the iMessage conversation, cannot intercept the approval code, and cannot forge a response. The approval code is randomly generated per request and checked via direct SQLite read of `chat.db`.

**Agent cannot modify its own enforcer.** The daemon runs as a separate process under launchd. The agent communicates with it only through the structured JSONL protocol over the Unix socket. There is no mechanism for the agent to send arbitrary commands to the daemon.

**Separation of concerns.** The gateway handles the fast-path allowlist (safe binaries). The daemon handles policy decisions for everything else. The human handles the truly sensitive operations. Each layer is independent and cannot be bypassed by compromising another.

---

## Adapting for non-macOS platforms

The core architecture (Unix socket daemon + JSON policies + 3-tier decision engine) is platform-independent. The macOS-specific parts are:

**Filesystem immutability.** Replace `chflags uchg` / `chflags nouchg` with Linux immutable attributes:

```bash
# Lock
sudo chattr +i ~/.openclaw/guardian/exec-guardian.py
sudo chattr +i ~/.openclaw/guardian/policies.json

# Unlock
sudo chattr -i ~/.openclaw/guardian/policies.json
```

Note: `chattr` requires root, while macOS `chflags uchg` works as the file owner. On Linux you may want to run the agent as a non-root user and have a separate privileged process manage the immutable flags.

**Human notification.** Replace iMessage with any messaging system that supports programmatic send + receive:

- **Telegram:** Use the Bot API. `send_imessage()` becomes an HTTP POST to `api.telegram.org/bot.../sendMessage`. `poll_response()` becomes a call to `getUpdates` filtered by chat ID and message text.
- **Signal:** Use `signal-cli` or the Signal REST API.
- **SMS:** Use Twilio or a similar API.
- **Slack/Discord:** Use webhook for send, API polling or websocket for receive.

The critical requirement is that the notification channel is out-of-band: the agent must not be able to intercept or forge responses on that channel.

**LaunchAgent.** Replace the macOS plist with a systemd unit:

```ini
[Unit]
Description=OpenClaw exec-guardian daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /home/YOU/.openclaw/guardian/exec-guardian.py
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
```

Install with `systemctl --user enable --now exec-guardian.service`.

---

## Known limitations

1. **Socket protocol validation.** The JSONL protocol between the gateway and the daemon works in our testing but has not been validated against every edge case the gateway might produce. In particular, `systemRunPlanV2` may contain additional fields in future OpenClaw versions that could affect command reconstruction. Monitor your logs after upgrades.

2. **iMessage latency.** The `imsg` CLI send takes approximately 2-5 seconds. The osascript fallback can take up to 20 seconds. Combined with the polling interval (3 seconds), the minimum round-trip for a human approval is around 8-10 seconds in the best case. The agent's exec call blocks for this entire duration.

3. **Single approver.** There is no delegation or backup approver mechanism. If the designated approver is unreachable, every ask-human command will time out and be denied. For a production multi-user setup, you would want a list of approvers with fallback ordering.

4. **No per-agent policies.** The current implementation applies the same policy file to all agents. In a setup with multiple agents that have different trust levels, you would want per-agent policy overrides keyed on the `agentId` field from the request.

5. **Auto-deny is substring match.** The pattern `"sudo"` would also match a hypothetical binary called `pseudocode`. In practice this has not been an issue because the auto-deny patterns are chosen to be specific enough, but a regex-based matcher would be more precise.

---

## Links

- OpenClaw: https://openclaw.ai
- OpenClaw GitHub: https://github.com/openclaw/openclaw
- `imsg` CLI: https://github.com/steipete/imsg
- Easylab AI: https://openclaw.easylab.ai

---

*Julien Doussot -- Easylab AI, Luxembourg -- February 2026*
