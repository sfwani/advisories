# GHSA-57mf-wqwq-6g6x

*Canonical version: <https://sfwani.github.io/advisories/ghsa-57mf-wqwq-6g6x/>*

**Hardcoded Default Fernet Encryption Key Exposes All Stored OAuth Credentials**

| | |
|:--|:--|
| Advisory | [GHSA-57mf-wqwq-6g6x](https://github.com/Significant-Gravitas/AutoGPT/security/advisories/GHSA-57mf-wqwq-6g6x) |
| CVE | not assigned |
| Severity | High (8.2) |
| CVSS vector | `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N` |
| CWE | CWE-321 (Use of Hard-coded Cryptographic Key), CWE-798 (Use of Hard-coded Credentials) |
| Published | 2026-10-05 |

### Affected versions

| Package | Ecosystem | Vulnerable | Fixed in |
|:--|:--|:--|:--|
| `autogpt-platform-backend` | other | >= 0.6.23, <= 0.7.4 | n/a |

## Details

AutoGPT Platform ships with a hardcoded default Fernet symmetric encryption key (`ENCRYPTION_KEY=dvziYgz0KSK8FENhju0ZYi8-fRTfAdlz6YLhdB_jhNw=`) committed to the public repository in `backend/.env.default`. This key encrypts all user OAuth tokens, API keys, and integration credentials stored in the `User.integrations` database column. Any attacker with database read access can decrypt the entire credential store using this publicly known key.

### Impact

Any self-hosted AutoGPT Platform deployment using the default `.env` is affected. An attacker who obtains database contents (via the companion ts-ag3-001 auth bypass, SQL injection, or a backup leak) can:
1. Decrypt all OAuth access/refresh tokens for every connected service (GitHub, Google, Notion, Twitter/X, Linear, Discord, etc.) and act on behalf of all users
2. Extract OpenAI, Anthropic, and other LLM API keys and use them at victims' expense
3. Silently exfiltrate the complete integration credential store for every user in the system

### Details

**Details**

`autogpt_platform/backend/backend/util/encryption.py`:

```python
ENCRYPTION_KEY = Settings().secrets.encryption_key

class JSONCryptor:
    def __init__(self, key: Optional[str] = None):
        self.key = key or ENCRYPTION_KEY
        self.fernet = Fernet(
            self.key.encode() if isinstance(self.key, str) else self.key
        )
```

`autogpt_platform/backend/backend/data/user.py`:

```python
async def update_user_integrations(user_id: str, data: UserIntegrations):
    encrypted_data = JSONCryptor().encrypt(data.model_dump(exclude_none=True))
    await PrismaUser.prisma().update(
        where={"id": user_id},
        data={"integrations": encrypted_data},
    )
```

`backend/.env.default` ships:
```
ENCRYPTION_KEY=dvziYgz0KSK8FENhju0ZYi8-fRTfAdlz6YLhdB_jhNw=
```

This is a valid Fernet key committed to the public repository. Any deployment using the default `.env` stores all user credentials encrypted with a key any attacker already knows.

Note: this same key is used as the HMAC key fallback in the Redis cache (ts-ag2-001), compounding the risk.

Affected commit: `94ebce7f633f40af8fd59e5cdaea75159cf2e6d1`

**🤖 Carried from GHSA-x7fr-7grv-gqxc, closed as a duplicate of this report**

Two remediation-relevant facts the duplicate stated and this record did not. Both verified against `dev` at `c91105ff36`.

1. **There is no way to rotate off the compromised key.** `encryption.py:8` binds `ENCRYPTION_KEY` to a module-level constant and `scoped_credentials.py:20` builds one process-wide `JSONCryptor()` from it; `IntegrationCredential` carries no key-version column, and the repository contains no rotation or re-encryption code. Changing `ENCRYPTION_KEY` therefore makes existing ciphertext undecryptable rather than re-keying it, and `JSONCryptor.decrypt` swallows the failure and returns `{}`. Remediating this needs a re-encryption migration, not just a new key.

2. **The public default key is what a deployment actually runs, even when setup was followed correctly.** `docker-compose.platform.yml:42-46` always loads `backend/.env.default` as the base env file, with `backend/.env` only an optional override, and `autogpt_platform/.env.default` — the file the setup documentation has operators copy — defines no `ENCRYPTION_KEY` at all. "Deployments using the default .env" understates the exposure.



---

### Proof of concept

```python
from cryptography.fernet import Fernet
import json

KNOWN_KEY = "dvziYgz0KSK8FENhju0ZYi8-fRTfAdlz6YLhdB_jhNw="
fernet = Fernet(KNOWN_KEY.encode())

# ciphertext obtained from User.integrations database column
ciphertext = "<base64_fernet_token_from_db>"
plaintext = fernet.decrypt(ciphertext.encode())
credentials = json.loads(plaintext)
# → { "oauth_tokens": { "github": { "access_token": "gho_..." }, ... }, "api_keys": { "openai": "sk-..." } }
```
Full reproduction: `python3 poc_ts_ag3_002.py --demo` [reproduce.zip](https://github.com/user-attachments/files/27853509/reproduce.zip)

### Fix

Fixed in `8da6c931be` (2026-09-17, [#14518](https://github.com/Significant-Gravitas/AutoGPT/pull/14518)) and first shipped in `autogpt-platform-beta-v0.8.0`: `ENCRYPTION_KEY` ships blank and the backend refuses to boot on the retired default. A key-rotation command was added in `ef3c9c6967` ([#14712](https://github.com/Significant-Gravitas/AutoGPT/pull/14712)). Upgrade to v0.8.0 or later and rotate the key if the default was ever used.

### Workarounds

None.

### References

- Fix commit `8da6c931be` ([#14518](https://github.com/Significant-Gravitas/AutoGPT/pull/14518), in v0.8.0)
- Key rotation: `ef3c9c6967` ([#14712](https://github.com/Significant-Gravitas/AutoGPT/pull/14712))
- CWE-321, CWE-798

### Timeline

Reported 2026-05-16 · Triaged 2026-09-07 · Fixed 2026-09-17 (released in v0.8.0) · Published pending
