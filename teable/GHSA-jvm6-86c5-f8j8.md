# GHSA-jvm6-86c5-f8j8

*Canonical version: <https://sfwani.github.io/advisories/ghsa-jvm6-86c5-f8j8/>*

**SSRF via AI provider baseUrl — bypasses safeFetch, reachable by space|updat**

| | |
|:--|:--|
| Advisory | [GHSA-jvm6-86c5-f8j8](https://github.com/teableio/teable/security/advisories/GHSA-jvm6-86c5-f8j8) |
| CVE | not assigned |
| Severity | Medium (6.5) |
| CVSS vector | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` |
| CWE | CWE-918 (Server-Side Request Forgery (SSRF)) |
| Published | 2026-10-13 |

### Affected versions

| Package | Ecosystem | Vulnerable | Fixed in |
|:--|:--|:--|:--|
| `teableio/teable` | other | < release.2026-10-12T12-45-53Z.3331 | n/a |

## Details

Hi

I'm an independent security researcher. Following your security policy, I'm
privately reporting a server-side request forgery (SSRF) bug I found reviewing
the open-source code. A space admin can point an AI integration's provider
baseUrl at an internal address; the server then fetches it with a plain fetch
that bypasses Teable's own safeFetch SSRF protection, and streams the response
back. Full write-up, with the safeFetch inconsistency that proves it's an
oversight, a PoC, and a one-line fix, below.

# SSRF: AI provider `baseUrl` fetch bypasses Teable's own SSRF-safe fetch

**Target:** Teable — GitHub Security Advisories (github.com/teableio/teable/security/advisories/new)
**Commit reviewed:** `5ef2238` (cloned HEAD, main)
**Class:** CWE-918 Server-Side Request Forgery
**Severity (self-assessed):** Medium — CVSS ~5–6.5, higher on multi-tenant/cloud
`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` (PR:L = requires a `space|update` role; response-returning)

---

## Summary

A space administrator (`space|update`) can register an AI integration whose
LLM provider `baseUrl` points at an internal address. When any base member
triggers AI generation, the server fetches that `baseUrl` with a **plain
`fetch`** — bypassing Teable's own SSRF-safe fetch (`safeFetch`) that is
applied to imports and external-DB connections. The upstream response is
streamed back to the caller, making this a response-returning SSRF into the
server's internal network (and cloud metadata) in multi-tenant deployments.

## The inconsistency (why this is a bug, not a feature)

Teable already ships centralized SSRF protection and uses it elsewhere:

- `apps/nestjs-backend/src/utils/ssrf-http.ts` → `safeFetch` — *"SSRF-safe
  node-fetch; trust is re-evaluated for every redirect."*
- Imports use it: `import/open-api/import-open-api-v2.service.ts`,
  `import/open-api/import.class.ts` (`import { safeFetch } from '.../ssrf-http'`).
- External DB connections enforce it: `space/data-db-preflight.service.ts`
  (`TEABLE_SSRF_PROTECTION_DISABLED`, `isPrivateNetworkAllowed`).
- v2 wires `createSsrfSafeFetch()` via `setSafeFetch()`.

The **AI provider path does not**. `apps/nestjs-backend/src/features/ai/util.ts`:

```ts
const createFixingFetch = (): typeof fetch => {
  return async (input, init) => {
    const response = await fetch(input, init);   // <-- plain global fetch, no safeFetch
    ...
  };
};

const createOpenAICompatibleWrapper = (options) =>
  createOpenAICompatible({ ...options, fetch: createFixingFetch() });
```

The other provider factories in `modelProviders` (createOpenAI, createAnthropic,
…) use the AI SDK's default fetch — also unfiltered. None route through
`safeFetch`.

## Reachability

1. `POST /api/space/:spaceId/integration` and
   `PATCH /api/space/:spaceId/integration/:integrationId`
   (`space/space.controller.ts`) are both `@Permissions('space|update')` and
   accept an `AI` integration whose config carries `llmProviders[].baseUrl`
   (`packages/openapi/src/space/integration-get-list.ts`).
   → A **space admin** (a *customer* role in cloud, not a server admin) sets
   `baseUrl` to e.g. `http://169.254.169.254/`, `http://localhost:<port>`, or
   any internal host.
2. `POST .../generate-stream` (`ai/ai.controller.ts`, `@Permissions('base|read')`)
   → `ai.service.ts` merges the space integration's `llmProviders`
   (`aiIntegrationConfig.llmProviders`, ai.service.ts ~L420) and calls the
   provider with `baseURL: baseUrl` and `createFixingFetch`.
3. The server connects to `baseUrl` with no private-IP/metadata filtering, and
   `createFixingFetch` streams the upstream response body back to the caller.

## Impact

Authenticated, response-returning SSRF from a space-admin customer:
- Reach internal-only HTTP services (internal APIs, admin panels, databases
  exposing HTTP), and port-scan the internal network via timing/error
  differences.
- Reach cloud metadata endpoints (e.g. `169.254.169.254`). Note: providers POST
  to `${baseUrl}/chat/completions`, so clean IMDSv1 credential paths are
  awkward, but the model-listing path (`ai-gateway-models.service.ts` does a
  `GET`) and any service that returns a readable body on POST leak content back
  through the stream.
- On multi-tenant/cloud (teable.io) this crosses the tenant→infrastructure
  boundary. On single-tenant self-hosted the space admin ≈ the operator, so the
  boundary is weaker — severity is deployment-dependent, hence the honest
  Medium.

## Proof of Concept (validate locally — never against a third-party host)

1. Run Teable locally. Start a listener on an "internal" port, e.g.
   `python3 -m http.server 9000`.
2. As a space admin, create an AI integration (OpenAI-compatible) with
   `baseUrl = http://127.0.0.1:9000/v1` and any `apiKey`.
3. In a base of that space, trigger AI generation (`.../generate-stream`).
4. Observe the request arriving at your `:9000` listener (server-side fetch to
   an internal address). Point `baseUrl` at other internal hosts/ports to
   confirm reachability and response streaming. Compare with the same attempt
   against the **import** feature, which is blocked by `safeFetch`.

## Remediation

Route all AI provider requests through the existing SSRF-safe fetch, exactly
as imports and DB connections already do:

```ts
import { safeFetch } from '../../utils/ssrf-http';

const createFixingFetch = (): typeof fetch => async (input, init) => {
  const response = await safeFetch(input, init);   // was: fetch(input, init)
  ...
};
```

…and pass a `safeFetch`-based `fetch` to every entry in `modelProviders`, not
only the OpenAI-compatible wrapper. Honor the same
`TEABLE_SSRF_PROTECTION_DISABLED` escape hatch used by the DB-connection path so
self-hosted operators keep parity.

Credit: if you publish an advisory or assign a CVE, I'd appreciate being credited
as Marcel Koza. Recognition is all I'm after; no compensation needed.

Thanks for building in the open,
Marcel Koza
