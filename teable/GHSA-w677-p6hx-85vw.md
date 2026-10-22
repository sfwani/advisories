# GHSA-w677-p6hx-85vw

*Canonical version: <https://sfwani.github.io/advisories/ghsa-w677-p6hx-85vw/>*

**Share password bypass: the share access token is never bound to the share it is presented for, so a token minted for one share opens any other password-protected share (plus cleartext password disclosure)**

| | |
|:--|:--|
| Advisory | [GHSA-w677-p6hx-85vw](https://github.com/teableio/teable/security/advisories/GHSA-w677-p6hx-85vw) |
| CVE | not assigned |
| Severity | High (7.1) |
| CVSS vector | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N` |
| CWE | CWE-287 (Improper Authentication), CWE-522 (Insufficiently Protected Credentials), CWE-863 (Incorrect Authorization) |
| Published | 2026-10-13 |

### Affected versions

| Package | Ecosystem | Vulnerable | Fixed in |
|:--|:--|:--|:--|
| `teableio/teable` | other | < release.2026-10-12T12-45-53Z.3331 | n/a |

## Details

# Share password protection can be bypassed with a token minted for a different share

A share access token is never checked against the share it is presented for. The cookie is *selected*
by the requested shareId, but the password is *verified* against the shareId inside the JWT payload.
So a token you legitimately minted for your own share opens anyone else's password-protected share —
you just store it under their cookie name.

Verified end to end on `ghcr.io/teableio/teable:latest` (build `release.2026-09-05T15-06-03Z.2943`),
self-hosted from `dockers/examples/standalone`. The same code is at develop HEAD (5ef2238) and has
been there since PR #272 (2023-11-29).

CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N = 7.1. If you accept that no account is needed (below),
PR:N gives 8.2.

## The split

`apps/nestjs-backend/src/features/share/strategies/jwt.strategy.ts`:

```ts
public static fromAuthCookieAsToken(req: Request): string | null {
  const shareId = req.params.shareId || (req.headers['tea-share-id'] as string);
  const cookieObj = cookie.parse(req.headers.cookie ?? '');
  return cookieObj?.[shareId] ?? null;          // requested share picks a COOKIE NAME
}

async validate(req, payload: IJwtShareInfo) {
  const { shareId, password } = payload;        // ...and the PAYLOAD picks what gets authenticated
  const authShareId = await this.shareAuthService.authShareView(shareId, password, ...);
  if (!authShareId) throw new UnauthorizedException();
  return authShareId;
}
```

The requested shareId and the payload's shareId are never compared. `authShareView` returns the
*payload's* shareId, and that return value is discarded — nothing in `features/share` or
`features/base-share` reads `req.user`. Meanwhile `ShareAuthGuard` has already resolved the response
data from the requested share (`auth.guard.ts:63`, `:66`), so the data served and the credential
verified come from two different shares. `features/base-share/strategies/jwt.strategy.ts:24-37` is the
same code.

You already wrote the check this is missing, twice, for the header-based path:

```ts
// permission.service.ts:1054 (validateShareViewPasswordToken)  and :590 (base twin)
if (payload.shareId !== shareId) { return false; }
```

Those run inside `PermissionGuard`, which returns early for `@Public()` handlers — and
`ShareController` is `@Public()` (`share.controller.ts:76`). So on `/api/share/*` the bound validator
never runs and the unbound strategy is the only gate. I confirmed that asymmetry empirically: the same
relabelled base token gets 200 on `GET /api/share/:id/base` and 401 on `GET /api/base/:id/table` with
`X-Tea-Base-Share`.

## Reproduction

Two ordinary accounts created through the normal signup API; the attacker is *not* the instance admin.
Each password-protects a share of their own.

```
attacker mints a token for THEIR OWN share (no session cookie needed at all):
  POST /api/share/shrJWCgs6tKOC8bTBDC/view/auth  {"password":"attackerpass1"}   -> 200
  payload: {"shareId":"shrJWCgs6tKOC8bTBDC","password":"attackerpass1",...}

against the victim's password-protected share:
  C1  no cookie                                               -> 401 unauthorized_share
  C2  that token under its OWN cookie name                    -> 401
  C3  garbage JWT under the victim's cookie name              -> 401
  --  that token under the VICTIM's cookie name               -> 200

  GET /api/share/shrDvlfZAbDm34y0jLw/view/records?take=100
  Cookie: shrDvlfZAbDm34y0jLw=<the attacker's own token>
  -> {"records":[{"id":"recIZrkjIhkaXT6bOMe",
                  "fields":{"fldQlNK2L6hZxJBdfpW":"VICTIM_SECRET_ROW_9f3a"},...}]}
```

C2 and C3 are the interesting controls: the token has to be cryptographically valid *and* relabelled.
The signature check works fine; the binding is what's missing.

## What it reaches

Read, all 401 → 200 with the relabelled cookie: `/view`, `/view/records`, `/view/row-count`,
`/view/group-points`, `/view/aggregations`, `/view/search-count`, `/view/search-index`, and the socket
endpoints (`/socket/view/doc-ids`, `/socket/field/snapshot-bulk`, `/socket/field/doc-ids`,
`/socket/record/snapshot-bulk`, `/socket/record/doc-ids`).

Three things make it worse than a one-off read:

**The victim's password comes back in cleartext.** `GET /api/share/:shareId/view` returns
`"shareMeta":{"password":"VictimSecretPass1",...}` (in both `shareMeta` and `view.shareMeta`). Post
that password to `/view/auth` and you get a *correctly bound* token — so the attacker ends up with
legitimate access that survives any fix to the strategy. Base shares don't leak it (they return
`password: true` via `hasPassword()`).

**Rotating the password does not evict the attacker.** The victim rotating to a new password was
verified: the old password is correctly rejected at `/view/auth`, but the attacker's unchanged token
still returns records, because `authShareView` is evaluated against the *attacker's* share and
password — the victim's password is never consulted. That defeats the eviction behaviour your own
comment at `permission.service.ts:1005-1013` describes.

**Attachments come out with no credentials.** Records returned through the bypass carry
`presignedUrl` values; fetching one returned the file contents with no cookie and no token.

Writes, where the victim's share config allows them: `POST /:shareId/view/form-submit` created a record
in a victim's password-protected form view (401 → 201), and on a whole-base share with `allowSave`,
`POST /:shareId/base/copy` produced a permanent, attacker-owned copy of the victim's base — including
a table outside the shared node. `button-click`'s gate is bypassed too, but I couldn't drive execution
without an active workflow, so I'm not claiming that one.

## Bounds, so you don't have to find them yourself

- The token must be from the same family: a view token is rejected against a base share and vice versa.
- The base-share leg is **metadata only** (`GET /api/share/:id/base` → baseId, nodeId, allow* flags).
  Every base *data* route goes through `PermissionGuard` and the bound validator, verified with a
  positive control. Only the view leg reaches records.
- The header paths (`X-Tea-Share-View`, `X-Tea-Base-Share`) are **not** affected — they use the bound
  validator. Record CRUD through the share-view write sandbox is not reachable this way.
- `base/copy` needs `allowSave` and a whole-base share; on a node-scoped share the copy came out empty
  for the attacker and for the legitimate control alike.
- The attacker needs the victim's shareId. It's `shr` + a 16-char nanoid, not enumerable — they need
  the link. That's the point: the link is the thing that circulates in chat, email and referrers, and
  the password is the control that's supposed to still hold when it does.
- They also need one valid share token. Either they create their own share and password it (free
  signup is open by default on self-host — every lab account was made through the normal signup API),
  or they know the password of any single share on the instance, which needs no account at all —
  `/view/auth` takes no session. A passwordless share can't mint a token ("Password restriction is not
  enabled").

Your docs at help.teable.ai/en/basic/security say "recipients must enter the correct password before
accessing the shared content", which is the guarantee this breaks.

## Fix

One line, mirroring what you already do at `permission.service.ts:1054` — inside `validate`, compare
the payload's shareId to the requested one and reject on mismatch. The base-share strategy needs
`passReqToCallback: true` first; it doesn't currently have the request available.

Worth knowing: PR #3011 does **not** fix this. I pulled its head branch — `fromAuthCookieAsToken` is
byte-identical, the new `validate(payload)` drops `passReqToCallback` so it can't compare even in
principle, and its nonce branch returns `payload.shareId` unchecked on the reasoning that "the JWT
signature proves the token was issued after a successful password check". The signature proves a
password check for *some* share, not this one. The same PR keeps `payload.shareId !== shareId` in
`validateBaseSharePasswordToken`, so the check was clearly considered necessary and just wasn't
carried into the strategies.

While you're there: the cleartext password in the `/view` response and in the DB is worth closing too
(that half is issue #3006's territory, not mine).

## Notes on the evidence

Everything above was executed against a local instance on the current release, per your SECURITY.md.
I did not touch app.teable.ai — the "free signup is open on the hosted service" point is inferred from
your public signup and pricing pages, not tested. The shipped image is built from the private EE repo,
so I verified the vulnerable code in `/app/enterprise/backend-ee/dist/index.js` as well as in the OSS
tree, but I can't dedup against EE source.

Happy to re-test a patch. Please credit Elias Hasas (zer0d4y5).
