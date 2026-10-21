# GHSA-xf86-hfpm-92xr

*Canonical version: <https://sfwani.github.io/advisories/ghsa-xf86-hfpm-92xr/>*

**AI Chat route exposes admin-only tools to non-admin users**

| | |
|:--|:--|
| Advisory | [GHSA-xf86-hfpm-92xr](https://github.com/directus/directus/security/advisories/GHSA-xf86-hfpm-92xr) |
| CVE | not assigned |
| Severity | Low (3.1) |
| CVSS vector | `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N` |
| CWE | CWE-863 (Incorrect Authorization) |
| Published | 2026-10-19 |

### Affected versions

| Package | Ecosystem | Vulnerable | Fixed in |
|:--|:--|:--|:--|
| `directus` | npm | >= 11.14.0, < 12.3.0 | n/a |

## Details

### Summary

The AI Chat endpoint (`POST /ai/chat`) did not enforce the admin-only restriction on AI tools. Any authenticated user with app access could request the `collections`, `fields`, `relations`, `flows` and `operations` tools, which are reserved for administrators. The MCP endpoint enforced this restriction correctly.

### Impact

The tools ran with the requesting user's own accountability, so they did not grant permissions beyond what the user already had:

- `collections`, `fields` and `relations` are still guarded by the admin checks in their underlying services.
- `flows` and `operations` are subject to the regular permission system. A non-admin user could only read or modify flows and operations their policies already allow, the same as through the REST API.

The issue is that the admin-only tool boundary was not applied consistently. Instances where non-admin policies grant access to `directus_flows` or `directus_operations` are most affected. We recommend keeping those collections admin-only, as described in the [security best practices](https://directus.io/docs/configuration/security-best-practices).

Exploitation requires an AI provider to be configured on the instance.

### Workarounds

- Disable the AI Chat feature by removing the configured AI provider.
- Make sure non-admin policies have no permissions on `directus_flows` and `directus_operations`.
