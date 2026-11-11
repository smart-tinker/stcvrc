# STCVRC release process

This document describes the current GitHub release flow and its gates. It does not authorize publication, deployment, or changes to an installed core. The [CVR 2.5.10 candidate contract](../candidates/cvr-2.5.10/README.md) remains authoritative for that bundle.

## Release states

| Stage | GitHub release flags | Meaning |
| --- | --- | --- |
| Draft candidate | `draft=true`; `prerelease` may be true | Unpublished; not a public download or acceptance result. |
| Published RC | `draft=false`, `prerelease=true`, not Latest | Public test candidate; its manifest and exact assets remain tied to one build. |
| Stable | `draft=false`, `prerelease=false`; intended to be Latest | Separate final release after its own acceptance and explicit publication decision. |

Draft and prerelease are independent flags. A draft can already carry the prerelease flag and remain unpublished. A release's `tag_name` is not proof that a Git tag ref exists: verify the release record and `refs/tags/<tag>` separately. GitHub uses `target_commitish` when creating a new tag; when that Git tag already exists, `target_commitish` is ignored. See [GitHub release management](https://docs.github.com/en/repositories/releasing-projects-on-github/managing-releases-in-a-repository) and the [Create a release API](https://docs.github.com/en/rest/releases/releases#create-a-release).

## Existing naming and current example

Do not rename or move historical tags. The accepted stable release is [`v1.19.29-stcvrc.1`](https://github.com/smart-tinker/stcvrc/releases/tag/v1.19.29-stcvrc.1). The current 1.19.33 candidate uses the repository's existing `stcvrc-1.19.33-rc.N` naming.

As checked on 2026-11-11, RC6 has release tag name `stcvrc-1.19.33-rc.6`, targets main commit `18d853ef19e0b6b06c9dea30cfb1fced6d4bf601`, and is `draft=true`, `prerelease=true`. Its tag string had no Git ref at that check. It contains only `verge-mihomo.exe` and `RC-MANIFEST.json`; the manifest records the exact source, build run, byte digest, and acceptance states. The latest assembly is [run 43057665817](https://github.com/smart-tinker/stcvrc/actions/runs/43057665817).

For future tags, prefer SemVer's `vX.Y.Z-rc.N` form so numeric RC order is explicit. This is a recommendation, not current automation: the draft assembler is hardcoded to RC6. Adopt a new format only in a separately reviewed workflow change and verify its tag/ref behavior. Preserve every existing release and tag. See [Semantic Versioning](https://semver.org/).

## Current CI responsibilities

| Workflow/job | What it verifies | What it does not establish |
| --- | --- | --- |
| `STCVRC source checks` | Exact source tests/builds, module verification, candidate package inputs and the bounded disposable Windows update/recovery smoke. | GUI or service startup, TUN/DNS behavior, real profiles, user acceptance, or deployment. |
| `STCVRC network lab` | Fresh pinned-core loopback A/B failover, both-endpoints-down behavior and TLS hostname rejection on its configured runners. Check its run on the same source/fixture revision; it is a separate workflow. | Windows TUN, OpenVPN rekey, production network behavior, or long-duration acceptance. |
| `assemble-draft-rc` in `.github/workflows/test.yml` | Runs only on manual `workflow_dispatch` from `main`, after `source`, `profile-contract`, `cvr-2-5-10-package`, and `cvr-windows-payload` succeed. It rebuilds the pinned core, writes the executable and manifest to a draft GitHub Release, then reads both assets back and compares exact bytes and manifest fields. | It does not gate on the separate network-lab workflow, issue closure, license sign-off, native acceptance, stable publication, or deployment. Check those separately. |

The release workflow uses standard public GitHub-hosted runners, `contents: read` for checks and scoped `contents: write` for draft assembly. It uses disposable runner-local Go caches and has no Actions cache or artifact-upload step. Release assets are GitHub Release files, not Actions artifacts. The separate CodeQL workflow has its own cache settings; do not infer repository-wide cache state from the release job.

## Draft-to-RC checklist

1. Confirm the target CVR version, recovery version, upstream core revision, downstream candidate revision, and the issue that records the user scenario and upstream gap.
2. Check the candidate input manifest and the exact workflow head. Tests and builds must use fresh source and bind the binary digest to the selected source and toolchain; do not reuse an old release executable.
3. Read the current source, package, profile, vulnerability, dependency, and network-lab results. A skipped job is not a pass. For separate workflows, verify that the tested source and fixture commits match the proposed candidate.
4. Dispatch draft assembly only from `main` after the configured dependencies pass. Read back the release record, actual Git ref state, manifest, asset list, and downloaded asset bytes. Record each SHA-256 and the creating run.
5. Keep the release a draft until its applicable RC gates and independent review are accepted. If source, inputs, or bytes change, use a new RC identity and run; do not replace a published tag or asset.
6. Before publishing an RC, obtain the explicit owner decision. Publish the same verified draft assets without rebuilding, then verify `draft=false`, `prerelease=true`, the intended tag/ref, the asset digests, and that the RC is not Latest.

CI reports each result as PASS, FAIL, UNRUN, BLOCKED, or INVALID. Missing evidence is not PASS. A package smoke or loopback test does not substitute for native/manual gates.

## Stable and deployment gates

There is no automated stable-release or deployment job in the current workflow. Stable requires a separate final version/tag and a fresh verification of the exact bytes if version metadata or source changes. It also requires applicable native startup/TUN/DNS and recovery checks, a qualified observation window, user acceptance, reviewed license/provenance evidence, and an explicit owner publication decision. Mark the intended stable release Latest and verify the release record afterward; do not convert an RC tag by simply clearing its prerelease flag.

Deployment is tracked per target only after stable acceptance and separate authorization. CI success, merging a PR, creating a draft, or publishing an RC does not change an installed host.

## Project gates

- [CVR 2.5.10 candidate and native acceptance](https://github.com/smart-tinker/stcvrc/issues/3)
- [Dependency license and provenance review](https://github.com/smart-tinker/stcvrc/issues/7)
- [GitHub checks and repository protections](https://github.com/smart-tinker/stcvrc/issues/23)
- [Dependency reachability triage](https://github.com/smart-tinker/stcvrc/issues/26)
