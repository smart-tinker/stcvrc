# RC11 Windows acceptance stage

The draft assembler remains manual on `workflow_dispatch` on `main` and waits for the synthetic `rc11-stage-contract` job. It fails before building or creating a draft if the exact-source `tools/network-lab/windows_idle_preflight.ps1` from #86 is absent. This PR does not dispatch the assembler.

The `RC11-WINDOWS-STAGE.zip` asset contains the six allowlisted scripts used by Capture, Plan and Preflight: the public Capture operator, shared path, baseline and transaction helpers, package writer, and Preflight command. It also contains the freshly source-built RC11 core and the pinned CVR 2.5.8 and 2.5.10 installers. Its root `source-manifest.json` uses schema 1 and lists every other archive file by relative path and SHA-256. It does not list itself or `RC-MANIFEST.json`, so the digest chain has no recursive reference. The current expected archive entries are:

- `source-manifest.json`
- `tools/network-lab/windows_idle_capture_operator.ps1`
- `tools/network-lab/windows_core_preimage_paths.ps1`
- `tools/network-lab/windows_idle_baseline_guard.ps1`
- `tools/network-lab/windows_idle_transaction.ps1`
- `tools/network-lab/windows_idle_preflight_package_writer.ps1`
- `tools/network-lab/windows_idle_preflight.ps1`
- `payload/verge-mihomo.exe`
- `payload/Clash.Verge_2.5.8_x64-setup.exe`
- `payload/Clash.Verge_2.5.10_x64-setup.exe`

The draft's `RC-MANIFEST.json` stays outside the archive and records the source commit, core/build identity, installer release pins, archive size/SHA-256, and external source-manifest SHA-256. The existing `SOURCE-BUILD.json`, notices, source inventory and `SHA256SUMS` remain part of the same byte read-back.

## Verify before Capture

1. Read the release record from the exact unpublished RC11 draft. Record its release ID, tag, `target_commitish`, and reviewed workflow/source SHA. Require the RC11 tag/title and `workflowHeadSha` to match that SHA. Confirm the draft is still unpublished.
2. Verify the downloaded release assets with `SHA256SUMS`. Verify `RC11-WINDOWS-STAGE.zip` size and SHA-256 against both `RC-MANIFEST.json` `files` and `preflightStage.archive`. Verify the exact source commit, RC11 core version/source commit/SHA/size, and the 2.5.8 recovery and 2.5.10 update installer identities and SHA-256 values in `preflightStage`.
3. Before using any stage file, verify the archive's `source-manifest.json` bytes against `preflightStage.sourceManifest.sha256`. Require schema version 1, unique safe relative paths, and exactly the expected archive entries. Hash every listed file and compare it with the manifest. Compare tool files with the same paths at `preflightStage.sourceCommit`; do not run files from an unverified extraction.
4. Build the accepted stage under a new local directory. Protect the empty root, each empty subdirectory and each empty file before writing/copying bytes. The ACL must be non-inheriting, owned by the current Windows user, and grant FullControl only to that owner, SYSTEM and local Administrators. `Set-CvrIdleCaptureAcl` in the verified `windows_idle_transaction.ps1` applies and checks this policy. Do not use an extracted tree with inherited or unverified ACLs as the stage root.
5. Create `local\capture-seed.json` outside the archive with the approved owner/session/service pins. Run `tools\network-lab\windows_idle_capture_operator.ps1` from Windows PowerShell 5.1 with the stage root and the externally pinned `sourceManifest.sha256`. The operator verifies the stage and fresh observations, then passes the same digest through Capture, Plan and read-only Preflight. A missing receipt or a rejected digest is not a successful handoff.

The archive contains no target identity, observation, profile, credential, host path or user-machine data. The staged public operator adds no private input to the package; the owner/session seed remains protected under the target-local `local` directory. No real Capture, Preflight or installed-machine acceptance is performed by this package check.
