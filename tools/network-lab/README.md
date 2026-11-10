# STCVRC source and network CI

Refs [issue #6](https://github.com/smart-tinker/stcvrc/issues/6). This is a narrow test pilot, not completion of CI/release hardening or permission to publish a release. Inherited release/dispatch workflows are removed. The accepted main/1.19.29 Windows release build contract is unchanged.

## Current source checks

`test.yml` checks the exact PR head or main commit separately from the pinned candidate below. On one standard Ubuntu runner it runs actionlint, fixture tests, OpenVPN/outbound/config/HTTP Go tests and Linux/Windows cross-compilation. Go 1.26.10 and actionlint 1.7.7 are checksum-pinned. The 20-minute job has read-only permissions; outputs stay on the disposable runner. These builds are not releases or proof of Windows runtime behavior.

Both workflows run for relevant same-repository, non-draft PRs against main, relevant main pushes, or manual dispatch. Fork/private jobs are skipped. No scheduled runs, persistent cache, artifacts, paid runners or release writes are configured.

## What runs

Standard `ubuntu-24.04` and `windows-2022` runners, with `contents: read` and 20-minute job limits. No external actions execute: public fixture code is fetched at the exact PR head SHA (or selected manual-run SHA), validated before use. Both platform jobs fetch the selected MIT-LZO candidate into a separate checkout at fixed commit [92107a26](https://github.com/smart-tinker/stcvrc/tree/92107a2605e19df0cb0d8b7bb08aa9ffb6b7ee93) and build it from source on that runner.

The Windows job verifies the official Go 1.26.10 Windows ZIP SHA256 `7ecd2d7260e82c59bcbd7f1077a07cee2dea607295b858df67195a1e4e09629b`, fetches exact candidate source `92107a2605e19df0cb0d8b7bb08aa9ffb6b7ee93`, builds it on the disposable runner, and requires fresh core SHA256 `c00707e061c91fd5bfa5b3a88653597b00ae1ffad39ba33221e5c8cad1eefcbf` before running the HTTP/TCP and negative-TLS fixture. It downloads only the [official Xray Windows ZIP](https://github.com/XTLS/Xray-core/releases/download/v26.10.31/Xray-windows-64.zip), verifies its SHA256, and extracts only `xray.exe`. No previous STCVRC release binary is used.

The Linux helper verifies official Go 1.26.10, official Xray 26.10.31, and the fresh Linux candidate hash. The Windows runner independently downloads the pinned Go toolchain and rebuilds the same source revision. Both jobs run fixture tests, real VLESS/TLS HTTP traffic through two native Xray processes, A→B→A, three actual HTTP 502 responses with both endpoints down, and an explicit wrong-TLS-hostname rejection. Core liveness is checked before and after every both-down request. The ten-second negative-request timeout accounts for the core's five-second retry budget; socket errors do not count as a pass.

All application addresses are IPv4 loopback. There is no TUN, Docker, admin elevation, host routing/firewall/DNS/trust-store change, production profile or stored credential. A same-host DIRECT sentinel detects bypass; this is not a security sandbox for hostile binaries. Test CA/certificate/UUID and logs exist only in temporary directories and are cleaned after normal completion or exceptions. Abrupt job termination relies on the disposable runner's lifetime.

Each CLI invocation selects four distinct ephemeral loopback ports to avoid TIME_WAIT from preceding runs, including on Windows. Port preflight still rejects a live listener and never terminates a pre-existing process. Use a dedicated runner; the short bind/start race is not a cross-process reservation guarantee.

No Actions cache or artifacts are used. Go's temporary compiler/module directories are deleted at the end; they are not persisted between jobs. There are no repository writes, releases, deployments or external service credentials. Only compact results and checksums enter the job log/summary. Standard public-repository hosted compute is [free](https://docs.github.com/en/billing/concepts/product-billing/github-actions); this does not guarantee a zero bill for unrelated account usage/storage.

## Review and activation

On Windows, fixture stderr streams to the job log. A fixture timeout invokes `taskkill.exe /PID <owned-parent> /T /F` before waiting for the parent, so its core/Xray descendants are included. Termination errors fail the job. A Windows-only regression forces a timeout with a live child and checks its termination and release of an open temporary file; Linux skips that native check.

The workflow is limited to this public repository. Fork PRs and draft PRs skip the job. Publish a **draft PR**, review its exact diff and checksums, then mark it ready for review to trigger the first eligible run. Subsequent relevant commits to a non-draft PR also run it. A draft publication can create a skipped workflow record, not a protocol test result.

`workflow_dispatch` is provided for later manual runs. GitHub only exposes a new manual workflow after it exists on the default branch. PR runs validate the change before integration; merging merely to obtain a run is unnecessary. Relevant pushes to `main` also run checks. Release publication is not automated; license and source-distribution checks remain separate.

The owner requested this limited free-runner pilot after the earlier Actions prohibition. That does not enable unrelated workflows, paid runners or repository-setting changes. Kayla remains responsible for STCVRC development/integration; the pilot diff needs review before its first enabled job.

## Run and reproduce

On a disposable Linux x86-64 machine with Bash, Python 3, OpenSSL, Git, curl, tar, timeout and at least 6 GiB free on the build filesystem:

```sh
bash tools/network-lab/ci.sh
```

This downloads only the fixed public inputs and uses temporary build files under `RUNNER_TEMP`, or this fixture folder when run locally. Go build temporaries stay on that same filesystem; the helper does not assume `/tmp` has enough disk space. Go's own cleanup command removes its read-only module cache before the temporary folder is deleted. No binaries or logs are committed. Hash mismatch stops the run; do not update a pin merely to make a failing build pass.

For an already verified binary pair, run `python3 lab.py --help` from this folder. The CLI requires explicit binary SHA256 values. `--check-tls-rejection` performs the separate hostname negative test. The first fixture experiment had a one-second timeout bug; its later correction did not change core source or allow socket errors to pass.

## Pinned evidence and limits

- [Exact candidate source](https://github.com/smart-tinker/stcvrc/tree/92107a2605e19df0cb0d8b7bb08aa9ffb6b7ee93).
- [Official Go archive](https://go.dev/dl/go1.26.10.linux-amd64.tar.gz), SHA256 `ccfe7ae822d2c2f41f4fe7c956199967a4dac22d0ee0d2b2bfdb440aab3b20c5`.
- [Official Xray ZIP](https://github.com/XTLS/Xray-core/releases/download/v26.10.31/Xray-linux-64.zip), SHA256 `e4bd9119f50ae7c41658b1abd0679ae06f98bd864a2907ff33f2f2cf7081b214`; contained executable `cc4b84d3069569f297a61f04b914f2bb37e9d202fd7b84cb50def1fc30fd40e1`.
- Reproduced Linux binary SHA256 `dce11f5ad306e80d4ac768daf744a88a412be06162ed228059b6b084842c2e56`; Windows/amd64 source build SHA256 `c00707e061c91fd5bfa5b3a88653597b00ae1ffad39ba33221e5c8cad1eefcbf`. Both are freshly built from source commit `92107a2605e19df0cb0d8b7bb08aa9ffb6b7ee93`; the network lab does not execute a published STCVRC binary.

Two earlier local Linux protocol runs passed: A→B 1.156/1.131 seconds and B→A 2.852/3.397 seconds. These observations are not latency guarantees or GitHub-hosted results. Every hosted result applies only to its recorded commit.

Confirmed hosted Linux baseline: [run 42459899876](https://github.com/smart-tinker/stcvrc/actions/runs/42459899876), fixture commit `cd9a6b7b243d3cbc9181b612e4d2cc50e1fc83b1`, A→B 1.108 seconds, B→A 2.905 seconds, three both-down HTTP 502 responses, explicit TLS hostname rejection, 21 fixture tests, successful pinned build/module verification and zero artifacts. This predates the Windows job and ephemeral-port change; it does not validate either addition.

[Historical Linux/Windows baseline run 42461850841]

Not covered: OpenVPN/rekey, UDP/DNS, OS TUN, blackhole/latency failures, existing connection migration, sustained operation, CVR GUI/service/recovery, Home/Work or user acceptance. The historical run above used the published RC1 EXE; current source-based candidate evidence is recorded separately.
