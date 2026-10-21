# GHSA-8p4j-2mm9-rh78

*Canonical version: <https://sfwani.github.io/advisories/ghsa-8p4j-2mm9-rh78/>*

**Registry HTTP actions could reach private network destinations before nsjail egress filtering**

| | |
|:--|:--|
| Advisory | [GHSA-8p4j-2mm9-rh78](https://github.com/TracecatHQ/tracecat/security/advisories/GHSA-8p4j-2mm9-rh78) |
| CVE | not assigned |
| Severity | Medium (6.5) |
| CVSS vector | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` |
| CWE | CWE-918 (Server-Side Request Forgery (SSRF)) |
| Published | 2026-09-20 |

### Affected versions

| Package | Ecosystem | Vulnerable | Fixed in |
|:--|:--|:--|:--|
| `Tracecat` | other | >= 0.41.0, < 1.0.0-beta.52-rc.3 | n/a |

## Details

## Summary

Before the filtered nsjail egress policy, network-enabled registry actions could connect to private, loopback, link-local, or metadata destinations reachable from the action sandbox. The fix applies a default-deny private-network policy to supported nsjail action sandboxes, with narrow operator-owned exceptions.

## Impact

An affected action could return data from a reachable private service through its normal result or attachment output. The confirmed report did not establish internal writes, denial of service, host escape, or unauthenticated access.

## Exploitability

Exploitation requires an authenticated workflow author with permission to execute the relevant HTTP-capable action and a reachable service that returns useful data. This advisory concerns the supported nsjail security boundary; UnsafePid and direct execution are reduced-isolation profiles for trusted workloads.

## Affected Configurations

Tracecat versions from `0.41.0` through versions before `1.0.0-beta.52-rc.3` are affected when actions run with nsjail enabled and without the later filtered egress policy.

## Remediation

Upgrade to Tracecat `1.0.0-beta.52-rc.3` or later, enable nsjail for production isolation, and configure private CIDR exceptions only for destinations explicitly required by trusted actions.

## Credit

Reported by sfwani.
