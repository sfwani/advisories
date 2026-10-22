# Advisories

Security advisories I reported that are published, fixed, and credited in the
[GitHub Advisory Database](https://github.com/advisories?query=credit%3Asfwani).
Each page carries the full root cause analysis, the vulnerable code, reproduction
steps, and the fix, exactly as published in the advisory.

Only published advisories appear here. Reports still in coordinated disclosure are
not listed, named, or hinted at until the maintainer ships a fix and the advisory
goes live.

| Advisory | Project | CVSS | Class | Writeup |
|:--|:--|:--|:--|:--|
| [GHSA-42mf-vpmr-gw5r](https://github.com/ag2ai/ag2/security/advisories/GHSA-42mf-vpmr-gw5r) | `ag2` | 9.8 Critical | Command injection (CWE-78) | [read](ag2/GHSA-42mf-vpmr-gw5r.md) |
| [CVE-2026-49950](https://github.com/xorbitsai/inference/security/advisories/GHSA-2hj6-h88x-mv4j) | `xinference` | 9.3 Critical | Missing authentication (CWE-306) | [read](xinference/CVE-2026-49950.md) |
| [GHSA-v3vj-mch3-x6c2](https://github.com/omnigent-ai/omnigent/security/advisories/GHSA-v3vj-mch3-x6c2) | `omnigent` | 8.8 High | Resource exposure (CWE-668) | [read](omnigent/GHSA-v3vj-mch3-x6c2.md) |
| [CVE-2026-57516](https://github.com/advisories/GHSA-hhrp-gw25-jr43) | `ray` | 8.8 High | Code injection (CWE-94) | [read](ray/CVE-2026-57516.md) |
| [CVE-2026-45675](https://github.com/advisories/GHSA-h3ww-q6xx-w7x3) | `open-webui` | 8.1 High | Privilege escalation (CWE-269) | [read](open-webui/CVE-2026-45675.md) |
| [GHSA-jc26-22qp-cgqj](https://github.com/triggerdotdev/trigger.dev/security/advisories/GHSA-jc26-22qp-cgqj) | `trigger.dev` | 7.9 High | Missing authentication (CWE-306) | [read](trigger.dev/GHSA-jc26-22qp-cgqj.md) |
| [GHSA-3c52-v5v2-3r56](https://github.com/Budibase/budibase/security/advisories/GHSA-3c52-v5v2-3r56) | `budibase` | 7.7 High | Server side request forgery (CWE-918) | [read](budibase/GHSA-3c52-v5v2-3r56.md) |
| [GHSA-qrjx-72xx-xhmh](https://github.com/ag2ai/ag2/security/advisories/GHSA-qrjx-72xx-xhmh) | `ag2` | 7.5 High | Path traversal (CWE-22) | [read](ag2/GHSA-qrjx-72xx-xhmh.md) |
| [CVE-2026-59714](https://github.com/advisories/GHSA-x2ff-v5v8-m75m) | `open-webui` | 7.1 High | Missing authorization (CWE-862) | [read](open-webui/CVE-2026-59714.md) |
| [GHSA-8p4j-2mm9-rh78](https://github.com/TracecatHQ/tracecat/security/advisories/GHSA-8p4j-2mm9-rh78) | `Tracecat` | 6.5 Medium | Server side request forgery (CWE-918) | [read](Tracecat/GHSA-8p4j-2mm9-rh78.md) |
| [CVE-2026-53577](https://github.com/kestra-io/kestra/security/advisories/GHSA-r6v3-xxwj-9h42) | `kestra` | 6.5 Medium | Incorrect authorization (CWE-863) | [read](kestra/CVE-2026-53577.md) |
| [CVE-2026-63342](https://github.com/advisories/GHSA-g26x-m427-f48f) | `hatchet` | 6.3 Medium | Incorrect authorization (CWE-863) | [read](hatchet/CVE-2026-63342.md) |
| [GHSA-59h8-w5q6-mfmp](https://github.com/advisories/GHSA-59h8-w5q6-mfmp) | `trigger.dev` | 5.3 Medium | Missing authentication (CWE-306) | [read](trigger.dev/GHSA-59h8-w5q6-mfmp.md) |
| [CVE-2026-73301](https://github.com/advisories/GHSA-4qcj-m5wp-jmf4) | `@budibase/server` | 4.3 Medium | Missing authorization (CWE-862) | [read](budibase/CVE-2026-73301.md) |
| [GHSA-xf86-hfpm-92xr](https://github.com/directus/directus/security/advisories/GHSA-xf86-hfpm-92xr) | `directus` | 3.1 Low | Incorrect authorization (CWE-863) | [read](directus/GHSA-xf86-hfpm-92xr.md) |
| [CVE-2026-59715](https://github.com/advisories/GHSA-gmfw-g93r-vg53) | `open-webui` | 3.1 Low | Missing authentication (CWE-306) | [read](open-webui/CVE-2026-59715.md) |
| [GHSA-pqxw-g93w-hj9x](https://github.com/advisories/GHSA-pqxw-g93w-hj9x) | `trigger.dev` | 0.0 High | Improper isolation (CWE-653) | [read](trigger.dev/GHSA-pqxw-g93w-hj9x.md) |

Reported by [@sfwani](https://github.com/sfwani). Rebuilt with `python scripts/build.py`.
