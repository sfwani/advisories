# GHSA-qrjx-72xx-xhmh

*Canonical version: <https://sfwani.github.io/advisories/ghsa-qrjx-72xx-xhmh/>*

**Path Traversal in DiskKnowledgeStore via Incorrect startswith Path Containment Check**

| | |
|:--|:--|
| Advisory | [GHSA-qrjx-72xx-xhmh](https://github.com/ag2ai/ag2/security/advisories/GHSA-qrjx-72xx-xhmh) |
| CVE | not assigned |
| Severity | High (7.5) |
| CVSS vector | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` |
| CWE | CWE-22 (Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')) |
| Published | 2026-09-25 |

### Affected versions

| Package | Ecosystem | Vulnerable | Fixed in |
|:--|:--|:--|:--|
| `ag2` | pip | >= 0.12.2, < 1.1.0 | n/a |
| `autogen` | pip | >= 0.12.2, <= 0.14.1 | n/a |

## Details

## Summary

`DiskKnowledgeStore._resolve()` uses `str(resolved).startswith(str(self._root.resolve()))` to validate that file paths stay within the root directory. This is a well-known anti-pattern: a sibling directory whose name shares a prefix with the root directory bypasses the check, allowing read, write, and delete operations outside the intended root.

## Affected File

- `autogen/beta/knowledge/disk.py:151`

## Steps to Reproduce

```python
import tempfile
from pathlib import Path

# Setup: create root and sibling with shared prefix
tmpdir = tempfile.mkdtemp()
root = Path(tmpdir) / "store"
root.mkdir()
evil = Path(tmpdir) / "store_evil"
evil.mkdir()
(evil / "secret.txt").write_text("API_KEY=sk-1234567890")

# The vulnerable check
traversal_path = "../store_evil/secret.txt"
resolved = (root / traversal_path).resolve()

# startswith check PASSES (bug)
print(str(resolved).startswith(str(root.resolve())))
# True -- because "/tmp/.../store_evil/secret.txt".startswith("/tmp/.../store")

# is_relative_to check CORRECTLY BLOCKS
print(resolved.is_relative_to(root.resolve()))
# False
```

### Standalone Verification Script

```python
import tempfile, asyncio
from pathlib import Path

def _normalize(path):
    return path.replace("\\", "/")

def _resolve_vulnerable(root, path):
    normalized = _normalize(path).lstrip("/")
    resolved = (root / normalized).resolve() if normalized else root.resolve()
    if not str(resolved).startswith(str(root.resolve())):
        raise ValueError(f"Path traversal blocked: {path}")
    return resolved

tmpdir = tempfile.mkdtemp()
root = Path(tmpdir) / "store"
root.mkdir()
evil = Path(tmpdir) / "store_evil"
evil.mkdir()
(evil / "secret.txt").write_text("SENSITIVE DATA")

try:
    result = _resolve_vulnerable(root, "../store_evil/secret.txt")
    print(f"BYPASSED: {result}")
    print(f"Content: {result.read_text()}")
except ValueError as e:
    print(f"Blocked: {e}")
```

## Root Cause

`disk.py:151`:
```python
if not str(resolved).startswith(str(self._root.resolve())):
    raise ValueError(f"Path traversal blocked: {path}")
```

When `root` resolves to `/data/store`, the path `../store_evil/secret.txt` resolves to `/data/store_evil/secret.txt`. The string `"/data/store_evil/secret.txt"` starts with `"/data/store"`, so the check passes.

The correct approach (used elsewhere in the AG2 codebase at `filesystem.py:246` and `apply_patch_tool.py:245`) is:
```python
if not resolved.is_relative_to(self._root.resolve()):
    raise ValueError(f"Path traversal blocked: {path}")
```

## Impact

An LLM agent using the knowledge tool (exposed via `_make_knowledge_tool` at `agent.py:1331`) can read, write, and delete files in sibling directories that share a prefix with the knowledge store root. This can lead to unauthorized data access or modification depending on the filesystem layout.

## Suggested Fix

```python
# Before (vulnerable):
if not str(resolved).startswith(str(self._root.resolve())):

# After (fixed):
if not resolved.is_relative_to(self._root.resolve()):
```

## CVSS

CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N (7.5 High)
