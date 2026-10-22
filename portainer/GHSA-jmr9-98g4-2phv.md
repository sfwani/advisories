# GHSA-jmr9-98g4-2phv

*Canonical version: <https://sfwani.github.io/advisories/ghsa-jmr9-98g4-2phv/>*

**Non-admin bind-mount restriction bypass via Docker local-driver volumes and automatic Git redeploy (incomplete fix of CVE-2026-44849 and CVE-2026-44850)**

| | |
|:--|:--|
| Advisory | [GHSA-jmr9-98g4-2phv](https://github.com/portainer/portainer/security/advisories/GHSA-jmr9-98g4-2phv) |
| CVE | not assigned |
| Severity | Critical (9.4) |
| CVSS vector | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H` |
| CWE | CWE-284 (Improper Access Control) |
| Published | 2026-10-08 |

### Affected versions

| Package | Ecosystem | Vulnerable | Fixed in |
|:--|:--|:--|:--|
| `github.com/portainer/portainer` | go | >= 2.40.0, < 2.45.2 | n/a |
| `github.com/portainer/portainer` | go | >= 2.39.0 | n/a |

## Details

## Summary

Portainer provides a security setting, shown in the interface as **Hide bind mounts for non-administrators** and enabled by default, that is intended to stop non-administrator users from mounting host filesystem paths into containers on a managed Docker environment. The control is incompletely enforced: a non-administrator who can create containers, volumes, or — on Swarm — services can still bind-mount arbitrary host paths by routing the mount through Docker's `local` volume driver rather than a literal bind mount, or by varying the case of the mount type. Any authenticated standard user with rights to one of those operations on an environment where bind mounts are disabled can exploit it.

The interface hides the bind-mount option from standard users, but the restriction is not interface-only: Portainer also enforces it on the server, rejecting a non-administrator's request to create a bind mount through its Docker API proxy and its Compose/stack validation with an HTTP 403. This advisory concerns that server-side denial, which could be bypassed by a request the interface never offers. It is not a claim that Portainer limits what Docker itself permits an authorised user to do; it is that, where Portainer has been configured to deny a request, the denial must hold. Portainer has treated a bypass of this denial as a vulnerability in CVE-2026-44849 and CVE-2026-44850, and does so here for the same reason.

Docker's `local` volume driver materialises the option set `{type: "none", o: "bind", device: "<host path>"}` as a real bind mount of `<host path>` — the canonical `mount -t none -o bind` syntax. Portainer's request filters block only the literal forms: container creation rejects mounts whose `Type` is `"bind"` but never inspects a `volume`-typed mount's driver options; the Swarm-service and volume-creation filters reject driver options where `type == "bind"` but never the documented `type=none, o=bind` shape. A related weakness compounds the gap: every one of these checks compares the mount type case-sensitively against the lowercase literal `"bind"`, while the Docker daemon treats the type case-insensitively — so a mount typed `"Bind"` or `"BIND"` passes the filter and is still honoured by the daemon. Each path forwards the option set to the daemon unchanged.

A further path reaches the same primitive without touching the Docker API at all. Portainer supports deploying stacks from Git repositories and redeploying them automatically, either when a stack webhook is invoked or on a polling interval. The interactive stack create, update and Git-redeploy operations validate the Compose file against the environment's security settings for a non-administrator, but the automatic redeploy path deployed the freshly pulled file with no security-setting validation of any kind. A standard user who controls the repository backing their own stack can therefore deploy a benign stack, commit a host bind mount — or `privileged: true`, `pid: host`, added capabilities, `devices`, `sysctls` — and have Portainer deploy it on the next webhook call or poll. This path is closed in 2.45.2; the Docker API and interactive stack paths were closed in 2.39.7 and 2.45.0.

This extends two earlier fixes that proved incomplete: CVE-2026-44849 (GHSA-5fxq-qcf3-244w, Swarm service create/update) and CVE-2026-44850 (GHSA-7fw3-x4r2-g7wc, container `HostConfig.Mounts`). The CVE-2026-44849 fix added driver-option checks to the Swarm-service and volume-creation paths but gated them on the wrong key and never covered the container-creation path at all; neither fix normalised the mount type for case or inspected inline `VolumeOptions.DriverConfig`. The same filter gaps also apply to Compose/stack validation, so the bypass is reachable through stack deployment as well as the raw Docker API.

## Severity

**Critical**

Exploitation requires no special timing or preconditions (attack complexity low) and only a low privilege level: any authenticated non-administrator holding container-, volume-, or service-create rights on an affected environment, which is default-enabled in Portainer CE. No administrator interaction is required; on the automatic-redeploy path the deployment is performed by Portainer's own scheduler or webhook handler with no further request from the attacker. The vulnerable-system impact is total — an attacker reads and writes the host filesystem of the managed Docker node from inside a container. Because Portainer is a control plane and that node typically runs the Docker daemon (and frequently the Portainer server itself), the subsequent-system impact is load-bearing: writing host cron or SSH primitives, or relaying the Docker socket, yields root code execution on the host and onward control of every workload, secret, and credential it manages.

## Affected Versions

The container-creation variant has existed since `HostConfig.Mounts` validation was introduced; the volume- and service-path variants have existed since the CVE-2026-44849 fix added the driver-option checks — those checks shipped incomplete and remained so through 2.39.6 (LTS) and 2.44.0 (STS). The case-insensitive variant affects every checkpoint that compares the mount type against the lowercase literal.

Portainer Community Edition and Portainer Business Edition share release version numbering; the table below applies to both editions.

The fix shipped in two stages. Portainer 2.39.7 (LTS) and 2.45.0 (LTS), released 2026-08-27, closed the Docker API proxy paths (container create, volume create, Swarm service create and update) and the interactive Compose/stack deployment path. The automatic Git redeploy path (stack webhook and polling interval) remained unvalidated in those releases and in 2.39.8 and 2.45.1; the fix ships in 2.45.2, released 2026-10-08.

| Branch              | First vulnerable | Fixed in        |
|---------------------|------------------|-----------------|
| 2.45.x (LTS)        | 2.45.0           | **2.45.2**      |
| 2.40.x–2.44.x (STS) | all prior        | **2.45.2**      |
| 2.39.x (LTS)        | 2.39.0           | not yet patched |

Portainer 2.45.2 contains the fix. Remediation differs by edition, per Portainer's security policy:

- **Portainer Community Edition** is provided as-is, and only the latest CE release receives security fixes — earlier CE releases are not backported. CE users on any line should upgrade to **2.45.2**.
- **Portainer Business Edition** follows its own lifecycle policy with backports. The fix is in 2.45.2; a dedicated 2.39.x Business Edition patch may follow but has not been released as of this advisory.

The 2.40.x–2.44.x STS lines reached end of life on the release of 2.45.0. Users on 2.39.7, 2.39.8, 2.45.0 or 2.45.1 are protected on the Docker API and interactive stack paths but remain exposed on the automatic redeploy path until they move to 2.45.2. Releases prior to 2.39.0, including the 2.33.x LTS line, are end-of-life and will not receive a fix.

## Workarounds

Administrators who cannot immediately upgrade can reduce exposure by:

- **Restrict create permissions for non-admin users.** The bypass requires container-, volume-, or service-create rights on the environment; tightening RBAC so standard users cannot create these resources removes the attack surface entirely.
- **Disable automatic Git updates for stacks owned by non-administrators, or restrict stack management.** Until you are on a release that validates the automatic redeploy path, remove webhooks and polling intervals from Git-backed stacks created by standard users, or turn off `AllowStackManagementForRegularUsers` for the environment. The latter also disables interactive stack deployment for those users.
- **Audit for prior exploitation.** Inspect existing volumes for `local`-driver options containing `o=bind`/`rbind`, `type=none`/`auto`, or an absolute `device`, and inspect existing containers and Swarm services for `volume`-typed mounts carrying a `DriverConfig` options map (in any letter case). Review Git-backed stacks owned by non-administrators for recent automatic redeploys and inspect the deployed containers for `Privileged`, `PidMode: host`, host binds or added capabilities. Treat any host-path mount created by a non-admin as a potential compromise.
- **Run managed Docker nodes with reduced host privilege.** User-namespace remapping or a non-root daemon limits what a host mount yields, narrowing the blast radius of a successful bypass.

The **Hide bind mounts for non-administrators** setting being enabled is assumed throughout the above — it is the control being bypassed, not a workaround. None of these replace the fix.

## Affected Code

The container-creation filter inspects only the literal mount type and never looks at a volume's driver options:

```go
// api/http/proxy/factory/docker/containers.go — decorateContainerCreationOperation
if !securitySettings.AllowBindMountsForRegularUsers && len(partialContainer.HostConfig.Mounts) > 0 {
    for _, mount := range partialContainer.HostConfig.Mounts {
        if mount.Type == "bind" {
            return forbiddenResponse, ErrBindMountsForbidden
        }
    }
}
```

A `volume`-typed mount carrying `VolumeOptions.DriverConfig.Options{type:"none", o:"bind", device:"…"}` is never examined, so it passes; a mount typed `"Bind"` passes the same check on case alone. The Swarm-service and volume-creation filters do inspect driver options, but gate on the wrong key:

```go
// api/http/proxy/factory/docker/services.go — CheckServiceBodyRestrictions
if mount.VolumeOptions.DriverConfig.Options["type"] == "bind" {
    return ErrBindMountsForbidden
}

// api/http/proxy/factory/docker/volumes.go — CheckVolumeBodyRestrictions
if volumeCreateBody.DriverOpts["type"] == "bind" {
    return ErrBindMountsForbidden
}
```

Both compare `type` against `"bind"`, but the canonical Docker bind shape is `type=none, o=bind` — a bind mount keys off `o`, not `type` — so neither check matches the documented payload. A second host-path route bypasses the container filter without any driver options at all: a non-admin creates a `local`-driver volume backed by a host path, then references it by name in `HostConfig.Binds` (e.g. `"host_vol:/host"`), which the `Binds` filter admits because the source does not begin with `/`. The equivalent Compose validation in `api/stacks/stackutils/validation.go` shares the same literal, case-sensitive `type == "bind"` gap.

The fix introduces a single shared bind-detection helper in `api/docker/bindmount.go` and routes every mount-creating path through it: container creation, volume creation, Swarm service create and update, and Compose/stack validation, in both editions — the Business Edition container-creation copy now delegates to the same helper rather than carrying its own inline checks. The helper treats a mount as a host bind when the declared type is `bind` or `npipe` compared case-insensitively, when `local`-driver options set `type=bind`, when the `o` option list contains `bind` or `rbind`, or when a `device` is set on the `local` driver. Host-path recognition covers POSIX absolute paths, Windows drive-letter paths, and Windows UNC and named-pipe paths, so a Windows equivalent of the Docker socket cannot be smuggled through as a volume name.

Container and service creation additionally resolve named-volume references — both `HostConfig.Binds` sources without a leading path separator and `Mounts[].Source` — and inspect the referenced volume's own driver options, closing the create-volume-then-mount-by-name chain. On Swarm, that resolution queries every node in the cluster rather than a single targeted node, so a bind-backed volume that exists only on another node is still rejected. `HostConfig.VolumesFrom` is rejected outright for non-administrators while the setting is off, because mounts inherited from another container cannot be filtered field by field. Compose validation walks the top-level `volumes:` block in addition to each service's `volumes:` list, and now fails closed rather than skipping the check when a referenced volume cannot be inspected. The 2.39.7 backport carries the same change with no divergence from the 2.45.0 fix.

The automatic Git redeploy path sits outside all of the above. In `api/stacks/deployments/deploy.go`, the function that redeploys a stack when its Git repository has changed — reached from both the public stack-webhook handler and the server-side polling scheduler — called the stack deployer directly:

```go
// api/stacks/deployments/deploy.go — redeployWhenChangedSecondStage
redeployStack := func(stack *portainer.Stack) error {
    switch stack.Type {
    case portainer.DockerComposeStack:
        err = deployer.DeployComposeStack(ctx, stack, endpoint, registries, true, true, false)
    case portainer.DockerSwarmStack:
        err = deployer.DeploySwarmStack(ctx, stack, endpoint, registries, true, true)
    ...
```

The interactive create, update and Git-redeploy handlers build a deployment configuration that calls `ValidateStackFiles` for a non-administrator before deploying; this path never did, so the newly pulled file was deployed exactly as committed. The second-stage fix runs the same validation, against the current security settings of the environment and the current role of the stack's author, before every automatic redeploy, and applies the same check to the stack start handler. It applies to both editions and is carried identically on both LTS lines.

## Impact

- **Host filesystem disclosure.** A non-admin can mount and read sensitive host paths — for example `/etc/shadow`, TLS private keys, or the Portainer database — from inside a container.
- **Host code execution as root.** Writable host mounts such as `/etc/cron.d` or `/root/.ssh/authorized_keys` escalate directly to root code execution on the Docker host.
- **Docker daemon takeover.** Mounting `/var/run/docker.sock` grants full control of the daemon and every container, stack, and service it runs.
- **Deferred, attacker-free trigger.** On the automatic Git redeploy path the host mount is applied by Portainer's own webhook handler or scheduler after a repository commit, so the privileged deployment happens without a further authenticated request and with no security-setting check on that release.
- **Control-plane pivot.** From the compromised host and daemon, an attacker reaches all workloads, secrets, and mounted credentials Portainer manages on that environment.

## Timeline

- 2026-05-14: Reported via GitHub Security Advisory by **s3np41k1r1t0**.
- 2026-05-17: Reported via GitHub Security Advisory by **kah-ja**.
- 2026-05-18: Reported via email by **omegacore-research**.
- 2026-05-18: Reported via email by **tsug0d**.
- 2026-05-21: Reported via GitHub Security Advisory by **AndyAnh174**.
- 2026-05-22: Reported via GitHub Security Advisory by **sfwani**, **BenTheCyberOne**, and **oduoke567**.
- 2026-05-26: Reported via GitHub Security Advisory by **Yanchon918s**.
- 2026-06-04: Reported via GitHub Security Advisory by **alcls01111**.
- 2026-06-08: Reported via GitHub Security Advisory by **5ud0er** and **hkm67**.
- 2026-06-09: Reported via email by **Eyodav (Mike G.A)**.
- 2026-06-14: Duplicate report received via email from **Causal Security** (GitHub **cipher-creator**); merged into this advisory with credit.
- 2026-06-19: Reported via GitHub Security Advisory by **CyberKareem**.
- 2026-07-03: Reported via GitHub Security Advisory by **sec-reex**.
- 2026-07-08: Reported via GitHub Security Advisory by **SaifSalah**.
- 2026-07-17: Reported via email by **boboboboo** (BoGeun Jang).
- 2026-07-18: Duplicate report received via GitHub Security Advisory by **Shahid-BugB**; merged into this advisory with credit.
- 2026-07-22: Duplicate report received via email from **wpframe**; merged into this advisory with credit.
- 2026-08-06: Duplicate report received via GitHub Security Advisory by **zenniskayy2k4**; merged into this advisory with credit.
- 2026-08-06: Duplicate report received via GitHub Security Advisory by **Jerry080401**; merged into this advisory with credit.
- 2026-08-07: Duplicate report received via email from **Nir Yehoshua (Cipher Security Labs)**; merged into this advisory with credit.
- 2026-08-15: Fix merged to `develop`.
- 2026-08-19: Follow-up hardening merged to `develop`; fix backported to `release/2.39`.
- 2026-08-20: Follow-up hardening backported to `release/2.39`.
- 2026-08-27: 2.39.7 (LTS) and 2.45.0 (LTS) released with the fix for the Docker API and interactive stack-deployment paths.
- 2026-09-01: Report received via GitHub Security Advisory by **danieltk76** identifying the unvalidated automatic Git redeploy path; merged into this advisory with credit.
- 2026-09-28: Duplicate report received via GitHub Security Advisory by **jdleaf96**; merged into this advisory with credit.
- 2026-10-04: Duplicate report received via GitHub Security Advisory by **huynvi**; merged into this advisory with credit.
- 2026-10-05: Fix for the automatic Git redeploy path backported to `release/2.45`.
- 2026-10-06: Fix for the automatic Git redeploy path merged to `develop` and backported to `release/2.39`.
- 2026-10-08: 2.45.2 released.
- 2026-10-08: Advisory published.

## Credit

- **s3np41k1r1t0** — reported that the restriction blocklist rejects only the literal `"bind"` type across the volume, container, and service paths, and that the container path never parses `VolumeOptions.DriverConfig`; noted the earlier service-path tightening left the container path uncovered.
- **kah-ja** — reported the volume-create → named-volume → container `Binds` chain with a complete runtime proof-of-concept, and that CE routes every non-administrator into the restricted branch.
- **omegacore-research** — reported the Host filesystem access via the Docker local volume driver.
- **tsug0d** — independently reported the bind-mount restriction bypass by email as part of a multi-issue submission, alongside separate Edge Stack findings tracked elsewhere.
- **AndyAnh174** — reported the case-sensitivity bypass (`Type: "Bind"`) across all five checkpoints, including the Compose/stack validator, alongside the `VolumeOptions.DriverConfig` parser differential; established that the proxy security layer performs no case normalisation.
- **sfwani**, **BenTheCyberOne**, **oduoke567** — reported the container-create `VolumeOptions.DriverConfig` bypass (the field is silently dropped by the partial-struct unmarshal), the named-volume `Binds` path, and that Compose stack validation shares the gap.
- **Yanchon918s** — identified that the CVE-2026-44849 fix gated on the wrong option key, leaving the documented `type=none, o=bind` bypass exploitable on Swarm `service create/update` and `POST /volumes/create`, and reported the container-create `VolumeOptions` variant.
- **alcls01111** — independently reported the container-creation mount-type bypass, where a `volume`-typed mount is not inspected at all.
- **5ud0er** — independently reported the volume-creation to named-volume-mount chain via the `local` driver.
- **hkm67** — independently reported the same volume-creation to named-volume-mount chain, observing that the container-creation `HostConfig.Binds` check rejects only sources beginning with `/` while the volume check gates on `DriverOpts["type"]`; supplied a complete PoC and framed it as an incomplete fix of CVE-2026-44850.
- **Eyodav (Mike G.A)** — independently reported (via email) the container-creation inline `VolumeOptions` variant and flagged all three filter sites; prefers credit as GitHub **eyodav**.
- **CyberKareem** — independently reported the most complete form, combining the container-creation variant with the wrong-key gaps on the volume and Swarm-service paths.
- **sec-reex** — reported the volume-create `o=bind` bypass and the missing container-path `VolumeOptions` inspection as part of an incomplete-patch measurement study (responsible disclosure).
- **SaifSalah** — independently reported all three filter sites (volume-creation, container-creation inline `VolumeOptions`, and Swarm service) with a full Web-UI and API proof-of-concept, framing it as an incomplete fix of the earlier bind-mount restriction (GHSA-7fw3-x4r2-g7wc).
- **boboboboo** (BoGeun Jang) — independently reported and reproduced the container-create leg on Portainer CE 2.39.5: a `Type:"volume"` mount backed by the `local` driver with `type=none, o=bind, device=/` is accepted because the container-create filter rejects only `Mounts[].Type == "bind"` and never inspects `Mounts[].VolumeOptions.DriverConfig`; identified that the equivalent driver-options check added to the service-create filter for CVE-2026-44849 was never carried across to container create. Supplied a self-contained Docker proof-of-concept logging every request and response.
- **Shahid-BugB** — independently reported the container-create bypass, identifying that the guard is a denylist matching only the literal `"bind"` while the canonical `local`-driver spelling is `type=none, o=bind, device=<host path>`, and that the container-create request model never parses `Mounts[].VolumeOptions` at all; classed it alongside the earlier host-namespace coverage gaps but with host filesystem write as the outcome.
- **wpframe** — independently reported and reproduced the volume-create leg of the bypass on Portainer CE 2.43.0: created a `local`-driver volume with driver options `type=none, o=bind, device=/`, which the `DriverOpts["type"] == "bind"` check in `volumes.go` (`CheckVolumeBodyRestrictions`) fails to reject, then mounted the resulting host-backed volume into a container to read host files as root; confirms the CE volume-creation sink remains unpatched on the 2.4x line.
- **Causal Security** (GitHub **cipher-creator**) — independently reported and reproduced the volume-create leg on Portainer CE 2.42.0: a `local`-driver volume with `type=none, o=bind, device=/` defeats the `DriverOpts["type"] == "bind"` check in `volumes.go` (`CheckVolumeBodyRestrictions`), after which the resulting host-backed named volume, referenced from container-create via `HostConfig.Binds` (a source with no leading `/`), passes the container-create guard — yielding host-root read/write; verified end-to-end with negative controls.
- **Nir Yehoshua (Cipher Security Labs)** — independently reported and reproduced the container-create leg on Portainer CE 2.39.5-LTS and 2.44.0-STS: a `Type: "volume"` entry in `HostConfig.Mounts` carrying inline `local`-driver options (`device=<host path>, o=bind`) in `VolumeOptions.DriverConfig.Options` is accepted and materialised as a host bind, while absolute `HostConfig.Binds` and `Type: "bind"` mounts are correctly rejected with HTTP 403 — isolating the residual to the driver-options path the container-create validation never inspects.
- **zenniskayy2k4** — independently reported all four validation surfaces with runtime confirmation on Portainer CE 2.39.5-LTS and 2.44.0-STS: the `local`-driver form `type=none, o=bind, device=/` defeats the `DriverOpts["type"]` check on volume-create and then passes the container-create guard when mounted by name through `HostConfig.Binds` (no leading `/`); the same options supplied inline in `Mounts[].VolumeOptions.DriverConfig` reach host root in a single container-create call, never touching `/volumes/create`; and a Compose **top-level** `volumes:` block carrying the same `driver_opts` is accepted by `IsValidStackFile`, which walks `service.Volumes` only. Proposed deciding on the mount options rather than the declared type — `o` containing `bind`, or an absolute `device` — and observed that Docker's `local` driver lower-cases option keys, so even a literal `{"Type":"bind"}` slips past the current comparison.
- **Jerry080401** — independently reported and reproduced the full set of driver-options bypasses on Portainer CE 2.39.5-LTS and 2.44.0-STS, mapping each to its validation surface (`volumes.go` and `services.go` comparing `type` while `o` is where the bind semantics live, `containers.go` never parsing `Mounts[].VolumeOptions`, and `IsValidStackFile` never walking the Compose top-level `volumes:` block), and established that `type=bind` is not a working form at all — a volume created with it fails at mount time with `failed to mount local volume: no such device` — so the existing checks reject only the spelling that cannot work and accept the one that does. Verified against six negative controls and documented the per-surface preconditions, noting the Compose path needs only `AllowStackManagementForRegularUsers`, which defaults to `true`.
- **danieltk76** — reported and runtime-confirmed on 2.45.0 that the automatic Git redeploy path (stack webhook and polling interval) deploys the pulled Compose file with no security-setting validation, so a standard user who controls their own stack's repository reintroduces host bind mounts, privileged mode and the host PID namespace after the Docker API and interactive stack paths were fixed; demonstrated with negative controls that the identical commit is rejected via direct create and manual Git redeploy. Extended the scope of the fix to the automatic redeploy path.
- **jdleaf96** — independently reported and reproduced on Portainer CE 2.45.1 that the automatic Git redeploy path (stack webhook and polling interval) deploys the pulled Compose or Swarm file without the environment's security-setting validation, which runs only on the interactive create and manual redeploy paths; supplied a self-contained proof-of-concept with a negative control showing the identical commit is rejected on direct create, and noted that the Swarm and polling variants share the same unvalidated call path.
- **huynvi** — independently reported that a standard user could deploy a privileged container with a full host bind mount and the host PID namespace by pushing a malicious commit to the repository behind a Git-backed stack and invoking its webhook; traced the cause to the validation living only in the deployment-configuration wrapper that the automatic redeploy path never constructs, and showed the same file refused on direct create.
