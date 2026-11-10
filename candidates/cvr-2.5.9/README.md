# CVR 2.5.9 compatibility candidate

Refs [issue #3](https://github.com/smart-tinker/stcvrc/issues/3).
This preparation checks the official CVR 2.5.9 update and 2.5.8 recovery
installers against a freshly built STCVRC 1.19.33 MIT-LZO Windows core from the
exact source commit pinned in `inputs.json`. CI does not reuse a previously
published core executable or change the accepted release table.

## CI and offline artifact verification

The existing GitHub Actions workflow downloads the pinned public CVR inputs and
builds the custom core from its exact source commit on a standard Ubuntu runner.
It verifies the build SHA and installer signatures without secrets, Actions
cache or uploaded artifacts. The job uses ephemeral runner storage only.

Use Python 3.9+ with the existing `cryptography` package for the offline verifier. The verifier reads local
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
| Custom STCVRC core | MIT-LZO source `76b7ec3ff9854d32cb3964403c065928ecdc9dd6`, upstream `3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8` |
| Fresh Windows executable | SHA256 `c00707e061c91fd5bfa5b3a88653597b00ae1ffad39ba33221e5c8cad1eefcbf`; CI measures and records its size |

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

These checks remain pending until native evidence exists. GitHub Actions now
runs the pinned fresh-source build and installer-integrity verification on
standard public runners. It does not execute installers, change a Windows host,
publish a release, or create Actions cache/artifacts. Native installation,
recovery and owner acceptance remain separate gates.
