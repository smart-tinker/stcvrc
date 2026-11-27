# STCVRC CI and network labs

The current workflow topology, required checks and draft-RC gate are documented in [RELEASING.md](../../docs/RELEASING.md). Work is tracked through [issue #6](https://github.com/smart-tinker/stcvrc/issues/6), Windows compatibility [#3](https://github.com/smart-tinker/stcvrc/issues/3), Linux maintenance [#4](https://github.com/smart-tinker/stcvrc/issues/4), license/source evidence [#7](https://github.com/smart-tinker/stcvrc/issues/7) and protocol integration [#25](https://github.com/smart-tinker/stcvrc/issues/25).

All pull requests against main, including drafts and fork PRs, run all required checks without path filters. The exact PR source SHA is fetched and verified before use. Main pushes and manual dispatch follow the triggers in each workflow; a skipped job is not PASS.

Only standard public GitHub-hosted `ubuntu-24.04` and `windows-2022` runners are used. New jobs do not create Actions artifacts or persistent cache. The built-in `github.token` is scoped to metadata collection and the explicitly gated draft writer. Application builds and tests run in separate steps without it; public source and binary downloads do not receive an Authorization header. No private profiles or custom secrets are required.

## Fresh builds and acceptance

Tests do not download previous STCVRC release executables. Production source revisions, toolchains, flags and dependency inputs are pinned in the scripts. Each job builds its required core in temporary directories with fresh compiler/module caches.

There are two distinct build paths:

- [The Linux loopback helper](ci.sh) builds the pinned MIT-LZO comparison source and checks its expected digest. This is a narrow regression reference; it is not acceptance of a newer RC core or regenerated WASM.
- [The RC source builder](../source-build/ci.sh) builds the selected current core, regenerates EasyTier Rust/WASM and Go bindings from exact public source, tests the actual dependency graph, and records source/input/output hashes in `build.json`. A [separate collector step](../source-build/collect.sh) inventories the recorded build and prepares its notices. The Windows native job tests the EXE built in that same job. The manual assembler must rebuild matching native EXE/WASM bytes before it may create a draft.

Official pinned CVR installers, Xray and toolchains are test dependencies. Their verification does not establish that an STCVRC core works; the functional checks below do that.

## What the Linux loopback job proves

[stcvrc-network-lab.yml](../../.github/workflows/stcvrc-network-lab.yml) runs one Ubuntu job with read-only contents permission and a 20-minute limit:

1. Validate fixture contracts and build the pinned comparison core.
2. Run real VLESS/TLS HTTP traffic through two native loopback Xray processes.
3. Stop A, require new connections through B, restore A and require return to A.
4. Stop both endpoints, require three HTTP 502 responses from the still-running core, and reject a DIRECT bypass.
5. Require explicit TLS hostname rejection and a live core.
6. Verify negotiated loopback MPTCP socket state.
7. Run the isolated Linux maintenance transaction and recovery.

Socket errors, a dead core, a missing baseline or a DIRECT result cannot satisfy the negative tests. The ten-second negative-request timeout includes the core's retry budget; failing scenarios are not silently retried.

The loopback fixture uses distinct ephemeral ports, test-only certificates and a DIRECT sentinel. It does not change host routes, DNS, firewall, trust store or TUN. The small bind/start race is not a cross-process port reservation, so the fixture requires a disposable runner.

## Other checks use separate isolation

The protocol module runs real pinned server fixtures, including the individual issue-25 comparisons. OpenVPN comparison and patch-ablation evidence remain linked from [issue #12](https://github.com/smart-tinker/stcvrc/issues/12); a Linux comparison does not establish Windows behavior.

The Windows job installs the verified stock CVR pair on its disposable runner and exercises GUI/service startup, core identity, generic profile/routing variants, DNS override, TUN traffic, application REJECT with positive controls, and recovery. The harness must identify the actual runtime DNS listener and verify the intended resolver path. Fixture checks or cross-compilation cannot replace a successful native run on the final source-built core.

The Linux maintenance helper uses runner-owned processes and an isolated namespace without default routes. Its intent/receipt and process-identity checks are described in [the helper source](../linux-maintenance/). It does not maintain an installed user machine.

The Windows idle Preflight capture and plan writers require the caller's exact stage root and externally pinned `source-manifest.json` SHA-256. They recheck every manifest-listed staged file before writing, bind that stage identity into the protected receipt and plan, and reject path traversal or staged-file drift. The pin must come from the trusted package record outside the staged tree. The portable `windows_idle_preflight_package_writer.ps1 -Mode Capture|Plan` entrypoint reads one strict UTF-8 JSON document from redirected stdin through EOF; the caller writes UTF-8 bytes and closes stdin. The shared Windows fixture exercises that process path with synthetic files and records no operational pins.

## Read-only Windows Preflight

Use the operator and helper files from the exact verified release stage. The external
`source-manifest.json` SHA-256 comes from the verified package record; keep it
outside the stage and pass it separately. The stage manifest must list the
operator and its five required helper files. Keep the stage root and its
`local` directory protected with the ACL enforced by the helpers.

Prepare `local\capture-seed.json` under the protected stage-local directory.
It contains the existing Capture inputs (`Capture`, `ExpectedTargetIdentity`,
and all nine `ExpectedPins`) plus `Observer` with the expected current owner
SID, interactive session ID, and service account SID. Capture.targetIdentity matches `ExpectedTargetIdentity`; it includes pinned
GUI/service/core paths, both protected core preimages and strict false
`coreShouldBeRunning`. Do not include
`capturedAtUtc` or `idleObservation`: the operator rejects those fields and
collects them afresh. The seed and any machine paths remain local.

Run the public operator from the verified stage in Windows PowerShell 5.1:

~~~powershell
$powershell51 = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
& $powershell51 -NoLogo -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File (Join-Path $stageRoot 'tools\network-lab\windows_idle_capture_operator.ps1') -StageRoot $stageRoot -ExpectedPackageManifestSha256 $manifestSha256 -RequestPath (Join-Path $stageRoot 'local\capture-seed.json') -TimeoutSeconds 30
$operatorExitCode = $LASTEXITCODE
~~~

Before writing, the operator verifies the external stage binding and helper
hashes, reads the service and matching GUI/core process owners and sessions,
checks service image and PID, resolves TCP/UDP listener ownership, and hashes
both current core files. An unavailable or ambiguous probe, wrong owner/session,
stale input, non-idle process/listener, or changed pin stops the command before
Capture, Plan, or Preflight output. It then invokes the staged Capture/Plan
writer and public read-only Preflight CLI with the verified stage root and
manifest digest.

The public JSON response contains status, reason, result, process exit code,
timeout/child-stop evidence and (on completed Preflight) receipt and digest
identifiers. It does not print target paths, PIDs, owner IDs or target identity.
A successful command returns `COMPLETE/PASS` with exit 0; Preflight FAIL and
TIMEOUT retain exit 1 and 124 respectively. A refused or incomplete observation
returns exit 2. Treat any missing receipt or non-`COMPLETE` status as UNKNOWN,
never as PASS. Capture, Plan and result records are written only beneath the
protected stage-local directory with owner, SYSTEM and Administrators ACLs.
Preflight does not install, start or stop the service, or change profiles,
routes, TUN or system settings.

The Windows CI fixture invokes this public entrypoint with synthetic
service/process/listener probes and the staged Capture/Plan/Preflight scripts.
It checks a successful bound chain, protected receipts, non-idle core/listener,
unavailable ownership/listener data, stale seed, changed-core pin, wrong stage
root and wrong manifest digest; every refusal must leave outputs unchanged. The
fixture uses no operational pins or host data.
## Failure handling and evidence

Each observation belongs to its exact harness SHA, tested source SHA, executable digest, toolchain and platform. Preserve FAIL, INVALID, UNRUN and skipped outcomes separately.

The Windows driver streams stderr. On timeout it terminates its owned process tree before waiting for the parent; a native regression checks child termination and file release. Cleanup failure fails the job. Abrupt termination and remaining temporary files rely on disposal of the runner.

Outputs stay in temporary directories and job logs/summaries. The separately gated manual draft assembler writes the core, manifest, source-build report, full notices, source inventory, checksums and root license to a new draft release, then reads every asset back. It cannot overwrite an existing mismatching release asset. Draft assembly is separate from publication and deployment.

## Limits

The suites use generic synthetic scenarios rather than named-user sign-off. A canary or 24-hour observation window is not an RC gate.

A passing short synthetic run does not establish corporate authentication/token refresh, prolonged real sessions, every upstream feature or deployment safety. Source/license evidence and unresolved historical binary mappings remain in issue #7. No workflow result by itself authorizes stable publication or production rollout.
