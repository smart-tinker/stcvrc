# CVR 2.5.9 compatibility candidate

Refs [issue #3](https://github.com/smart-tinker/stcvrc/issues/3).
This preparation pairs official CVR 2.5.9 with the **unchanged** STCVRC 1.19.33
executable. It neither rebuilds the core nor changes the accepted release table.
The recovery installer is official CVR 2.5.8.

## Offline artifact verification

Use Python 3.9+ with the existing `cryptography` package. The verifier reads local
files only; it does not download, install or execute artifacts.

Place these public inputs in one directory, for each `VERSION` in `2.5.8`, `2.5.9`:

- `Clash.Verge_VERSION_x64-setup.exe` and `.exe.sig`
- `latest-vVERSION.json` (the release's `latest.json` asset)
- `cvr-vVERSION-release.json` (raw official GitHub release metadata)
- `tauri-vVERSION.conf.json` (source config at the commit pinned in `inputs.json`)

`inputs.json` pins the exact assets, sizes, SHA256, source commits and updater
key. Obtain the public files from those pinned URLs. An altered manifest requires
review; the CLI has no option to substitute another trust manifest.

```sh
python3 -B candidates/cvr-2.5.9/verify-artifacts.py \
  --artifacts /path/to/public-inputs \
  --core /path/to/stcvrc-1.19.33-candidate.exe
python3 -B -m unittest discover -s candidates/cvr-2.5.9 -p 'test_verify_artifacts.py'
```

Success prints one JSON receipt; invalid or missing inputs exit nonzero without
a success receipt. Checks include both installers' SHA256 and Minisign `ED`
signatures over BLAKE2b-512, trusted comments, tagged updater keys/config hashes,
release identities and both Windows updater entries. Synthetic tests use real
Ed25519 signing and cover substitutions and malformed inputs.

The receipt records the verifier and input-manifest hashes and public component
identities. It explicitly leaves extracted payloads, Authenticode, native
acceptance and publication unverified. Installer integrity does not establish
the hashes or behavior of its embedded GUI, service, helper or stock core.

## Component provenance and RC freeze

| Component | Source and actual bytes |
| --- | --- |
| CVR 2.5.9 | Official installer/source refs in `inputs.json` |
| Recovery CVR 2.5.8 | Official installer/source refs in `inputs.json` |
| Custom STCVRC core | Source `d888dfad5e785217778bb7515c931840d5307dd4`, upstream `3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8` |
| Custom executable | 61,148,160 bytes, SHA256 `6a35ab8e2db4c0171f74563aded55949d10a3dcc5ad9c1c1b5e155ab2a2986c7` |

The later immutable RC manifest records `packagingSourceCommit` for the clean,
reviewed verifier/docs checkout separately from `coreSourceCommit` above. Main's
1.19.29 source and `build-windows.ps1` do not produce this 1.19.33 executable.
Bind that manifest to the verifier, inputs, receipt, extracted payloads and
reviewed operator-package hashes before native acceptance. Any changed package
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

These checks remain pending until their native evidence exists. Run required
checks locally. GitHub Actions is unused in this cycle, including downstream
dispatches; check actual workflow triggers before any publication.
