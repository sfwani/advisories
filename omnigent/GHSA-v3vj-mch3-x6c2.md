# GHSA-v3vj-mch3-x6c2

*Canonical version: <https://sfwani.github.io/advisories/ghsa-v3vj-mch3-x6c2/>*

**Sandbox launcher isolation failure permits host-level code execution**

| | |
|:--|:--|
| Advisory | [GHSA-v3vj-mch3-x6c2](https://github.com/omnigent-ai/omnigent/security/advisories/GHSA-v3vj-mch3-x6c2) |
| CVE | not assigned |
| Severity | High (8.8) |
| CVSS vector | `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` |
| CWE | CWE-668 (Exposure of Resource to Wrong Sphere), CWE-732 (Incorrect Permission Assignment for Critical Resource) |
| Published | 2026-10-13 |

### Affected versions

| Package | Ecosystem | Vulnerable | Fixed in |
|:--|:--|:--|:--|
| `omnigent` | pip | < 0.18.0 | n/a |

## Details

## Impact

On affected Linux deployments using the bubblewrap sandbox, helper executors granted access to host temporary files that needed to remain outside the sandbox. Code already running inside the sandbox could compromise the launcher and execute with the privileges of the operating-system account running Omnigent.

This can expose or modify data accessible to that account and disrupt its processes. Exploitation requires code execution inside an affected sandbox; it does not require administrator privileges. Timing requirements differ between executors.

## Patched version

Upgrade Omnigent to **0.18.0 or later** on agent hosts and restart affected helper processes. The fix removes broad temporary-directory write grants and rejects sandbox configurations that expose the launcher's directory.

## Workaround

Until upgraded, run untrusted agents in a separate disposable VM or container without sensitive host credentials or host filesystem mounts.

## References

- [Fix](https://github.com/omnigent-ai/omnigent/pull/9844)
- [Omnigent 0.18.0](https://github.com/omnigent-ai/omnigent/releases/tag/v0.18.0)
