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

## Windows update and recovery contract

Private captures, profiles, credentials, host plans, deployment commands and
receipts stay outside this public repository. Prepare a fresh transaction and
current 2.5.8 preimages rather than replaying an earlier upgrade.

Before switching:

1. Extract the verified installer without executing it; record actual GUI,
   helper, service and stock-core payload hashes. Do not infer service byte
   equality from its source version.
2. Capture current GUI, service, both custom-core copies, owner/run intent,
   profile/generated configuration, selectors, task security, ACL and native TCP
   state. Preserve observer history and a usable current-version baseline.
3. Prepare local verified 2.5.8 recovery, an independent SYSTEM Watch and fresh
   guarded tasks. Verify Watch before Stop. Quiesce GUI/autostart and keep false
   run intent **before NSIS or service-helper execution**: the installer can
   publish/start a stock core and reset TCP settings.
4. Check Python fixtures, Windows PowerShell 5.1 parsing and the existing actual
   function mocks for task security, installer children, TCP and generated-file
   ACL recovery. Use explicit absolute script paths in native mocks. Validate
   the candidate against its intended configuration before releasing run intent.

During the agreed canary window, verify the actual custom core in both validation
and service execution locations before true run intent. Check fresh process
identity, configuration generation, selectors, reload, DNS/TUN/system routes,
TCP/ACL preservation, real consumer behavior and independent fresh SSH before
confirmation. Test recovery to the captured working 2.5.8 bundle, not an older
historical version. Test both untouched upgrade and opening/saving the new TUN
DNS-mode dialog; compare persisted, generated, applied configuration and system
DNS/routes. Follow with startup/reboot verification and the required qualified
24-hour observation and owner acceptance. Gaps or unknown identity do not count
as passing observation.

These checks remain pending until operator-host evidence exists. GitHub Actions runs a bounded Windows install/update smoke on its disposable `windows-2022` runner: it installs the pinned 2.5.8 package, updates to 2.5.10 with `/UPDATE`, checks registry versions and preserves a synthetic profile marker, then stages the freshly built 1.19.33 core with `--install-core`. The NSIS installers reset TCP settings and the service helper adds firewall allow rules, so this is the final step on a clean runner that is discarded after the job. A Windows process-start trace rejects GUI, service or stock-core launches during the smoke. This smoke does not establish user-machine installation, recovery, service startup, TUN/DNS, qualified observation, or owner acceptance. The workflow uses standard public runners and no Actions cache or uploaded artifacts.
