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

## Failure handling and evidence

Each observation belongs to its exact harness SHA, tested source SHA, executable digest, toolchain and platform. Preserve FAIL, INVALID, UNRUN and skipped outcomes separately.

The Windows driver streams stderr. On timeout it terminates its owned process tree before waiting for the parent; a native regression checks child termination and file release. Cleanup failure fails the job. Abrupt termination and remaining temporary files rely on disposal of the runner.

Outputs stay in temporary directories and job logs/summaries. The separately gated manual draft assembler writes the core, manifest, source-build report, full notices, source inventory, checksums and root license to a new draft release, then reads every asset back. It cannot overwrite an existing mismatching release asset. Draft assembly is separate from publication and deployment.

## Limits

The suites use generic synthetic scenarios rather than named-user sign-off. A canary or 24-hour observation window is not an RC gate.

A passing short synthetic run does not establish corporate authentication/token refresh, prolonged real sessions, every upstream feature or deployment safety. Source/license evidence and unresolved historical binary mappings remain in issue #7. No workflow result by itself authorizes stable publication or production rollout.
