# GHSA-jc26-22qp-cgqj

**Supervisor workload API lacks cross-tenant authentication**

| | |
|:--|:--|
| Advisory | [GHSA-jc26-22qp-cgqj](https://github.com/triggerdotdev/trigger.dev/security/advisories/GHSA-jc26-22qp-cgqj) |
| CVE | not assigned |
| Severity | High (7.9) |
| CVSS vector | `CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:L` |
| CWE | CWE-306 (Missing Authentication for Critical Function) |
| Published | 2026-09-14 |

### Affected versions

| Package | Ecosystem | Vulnerable | Fixed in |
|:--|:--|:--|:--|
| `trigger.dev` | npm | <= 4.6.0 | n/a |

## Details

## Summary

The supervisor workload server accepts critical run-lifecycle requests without cryptographically authenticating the caller or verifying ownership of the targeted run. A workload with network access and knowledge of a valid run/snapshot pair can target runs belonging to another deployment.

## Vulnerability Details

**File:** `apps/supervisor/src/workloadServer/index.ts`

The HTTP server created at lines 157-470 exposes these endpoints with NO authentication:

- `POST /api/v1/workload-actions/runs/:runId/snapshots/:snapshotId/attempts/start` 
- `POST /api/v1/workload-actions/runs/:runId/snapshots/:snapshotId/attempts/complete`
- `POST /api/v1/workload-actions/runs/:runId/snapshots/:snapshotId/heartbeat`
- `GET /api/v1/workload-actions/runs/:runId/snapshots/:snapshotId/suspend`
- `GET /api/v1/workload-actions/runs/:runId/snapshots/:snapshotId/continue`

The supervisor forwards these requests upstream using its privileged worker credentials, creating a confused-deputy path. In particular, attempts/start can return resolved environment variables and a newly issued run JWT.

The /workload Socket.IO namespace checks only for caller-supplied identity headers and allows callers to bind known run IDs without verifying that the run belongs to the claimed deployment.

## Steps to Reproduce

```bash
# Requires network access and a known current run/snapshot pair.
curl -X POST \
     http://supervisor:8020/api/v1/workload-actions/runs/run_XXXX/snapshots/snap_XXXX/attempts/start \
     -H "Content-Type: application/json" \
     -H "x-trigger-workload-runner-id: attacker" \
     -d '{"isWarmStart":false}'
```

## Impact

Targeted cross-deployment and potentially cross-tenant run manipulation. An attacker with network access and a valid run/snapshot pair may start or complete another run, interfere with its lifecycle, or obtain its resolved environment variables and run JWT. Run and snapshot IDs have high entropy, and the workload API does not provide a working enumeration primitive.

## Resolution
The managed service now authenticates workloads using signed deployment-scoped tokens and scopes sensitive worker actions to the verified environment. Requests targeting runs in another environment are rejected. The obsolete deployment-scoped dequeue proxy has also been removed.
