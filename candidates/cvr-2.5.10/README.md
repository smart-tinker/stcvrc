# CVR 2.5.10 compatibility candidate

Refs [issue #3](https://github.com/smart-tinker/stcvrc/issues/3).
This preparation checks the official CVR 2.5.10 update and 2.5.8 recovery
installers against a freshly built STCVRC 1.19.33 MIT-LZO Windows core from the
exact source commit pinned in `inputs.json`. CI does not reuse a previously
published core executable or change the accepted release table.
The repository-wide release lifecycle is described in [docs/RELEASING.md](../../docs/RELEASING.md); this file remains the specific CVR bundle contract.

## CI and offline artifact verification

The existing GitHub Actions workflows use standard public Ubuntu and Windows
runners. They build the current source and pinned candidate from exact commits,
verify the CVR installer signatures and hashes, then run a bounded install/update
smoke only on a clean disposable Windows runner. No secrets, Actions cache or
uploaded artifacts are used.

Use Python 3.9+ with the existing `cryptography` package for the offline verifier. This verifier reads the already downloaded files only; it does not download, install or execute them.

Place these public inputs in one directory, for each `VERSION` in `2.5.8`, `2.5.10`:

- `Clash.Verge_VERSION_x64-setup.exe` and `.exe.sig`
- `latest-vVERSION.json` (the release's `latest.json` asset)
- `cvr-vVERSION-release.json` (raw official GitHub release metadata)
- `tauri-vVERSION.conf.json` (source config at the commit pinned in `inputs.json`)

`inputs.json` pins the exact assets, sizes, SHA256, source commits and updater
key. Obtain the public files from those pinned URLs. An altered manifest requires
review; the CLI has no option to substitute another trust manifest.

```sh
python3 -B candidates/cvr-2.5.10/verify-artifacts.py \
  --artifacts /path/to/public-inputs \
  --core /path/to/stcvrc-1.19.33-candidate.exe
python3 -B -m unittest discover -s candidates/cvr-2.5.10 -p 'test_verify_artifacts.py'
```

Success prints one JSON receipt; invalid or missing inputs exit nonzero without
a success receipt. Checks include both installers' SHA256 and Minisign `ED`
signatures over BLAKE2b-512, trusted comments, tagged updater keys/config hashes,
release identities and both Windows updater entries. Synthetic tests use real
Ed25519 signing and cover substitutions and malformed inputs.

The receipt records the verifier and input-manifest hashes and public component
identities. The offline receipt explicitly leaves extracted payloads, Authenticode, native
acceptance and publication unverified. A separate disposable-runner install smoke
is described below; installer integrity alone does not establish the behavior of
the GUI, service, helper or stock core.

## Component provenance and RC freeze

| Component | Source and actual bytes |
| --- | --- |
| CVR 2.5.10 | Official installer/source refs in `inputs.json` |
| Recovery CVR 2.5.8 | Official installer/source refs in `inputs.json` |
| Custom STCVRC core | MIT-LZO source `086a62c3ce9a77f650786ae2eae92b68909d49e1`, upstream `3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8` |
| Fresh Windows executable | SHA256 `d72784d98a44b90e561c701589c50f53074958d7cef656607ee5be1143b36c87`; CI measures and records its size |

The RC manifest must record the clean verifier/docs commit separately from
`coreSourceCommit`. Bind it to the verifier, inputs, measured receipt,
extracted payloads and reviewed operator-package hashes before native acceptance. Any changed package
requires a new RC. Public RC assets require actual byte readback; stable requires
applicable owner acceptance. RC, stable publication and installed state are
separate results. Existing tags/assets must remain immutable.

## Bounded native Windows acceptance

All machine-specific profiles, credentials, deployment state and private evidence
stay out of this public repository. The workflow uses only the verified official
2.5.8 recovery and 2.5.10 update installers on a clean disposable
windows-2022 runner. It freshly builds the pinned STCVRC core from its exact
source commit, checks the measured SHA256, and stages those bytes before use.

The native job first installs 2.5.8 and updates it to 2.5.10. It then starts the
verified installed GUI and requires an actual native window. Through that
window's WebView2 Tauri command channel it installs the CVR service, creates two
generic synthetic local profiles, selects each profile, and reloads A → B → A.
A local UDP DNS responder and HTTP endpoint supply the only test destinations.
The test queries CVR's fake-IP DNS listener and sends HTTP traffic to the
returned synthetic addresses through an explicit 198.18.0.0/16 TUN route. It
checks the allow/reject rules, that the live service-backed core path and SHA256
match the fresh source build, and that the service returns to ready state after
each profile change.

The runner's default routes and DNS servers on physical adapters are snapshotted
before the native test and compared afterward. Broad /1 routes fail the check;
the synthetic route is limited to 198.18.0.0/16 and removed during cleanup. The
test does not enable the system proxy or configure system DNS. It then performs
the pinned 2.5.8 recovery install and verifies the registered version, preserved
synthetic profile marker, and staged fresh core.

A result is valid only for the exact PR head and successful Windows job. A failed
or unavailable assertion remains open with its exact CI evidence. This verifies
the installed GUI/backend start, service mode, synthetic profile reload,
loopback DNS/TUN traffic, core identity and recovery on one hosted Windows
image. It does not establish every GUI interaction, external VPN reachability,
OpenVPN, arbitrary Windows drivers, user profiles or production deployment.
The workflow uses standard public runners, without secrets, paid runners,
Actions cache or artifacts. It has no canary, observation-window, or named-person
acceptance gate. Stable publication still requires a separate explicit owner
decision and reviewed source/license provenance.
