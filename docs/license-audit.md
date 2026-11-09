# STCVRC dependency licenses and source provenance

This record covers only the STCVRC core executable distributed in the accepted 1.19.29 release and the separate 1.19.33 RC2 candidate. The stock Clash Verge Rev UI/installer is not redistributed here. Profiles, credentials, certificates, and runtime/deployment state are out of scope.

The machine-readable pins, reference asset hashes, source commits, toolchains and build flags are in [license-provenance.json](license-provenance.json).

## Source and build mapping

| Line | Public reference | Exact STCVRC source | Upstream base | Fresh build |
| --- | --- | --- | --- | --- |
| Accepted 1.19.29 | [release](https://github.com/smart-tinker/stcvrc/releases/tag/v1.19.29-stcvrc.1); core SHA256 71195c943be67017c5646ea2021734bc122fa83c58a408ab6713a2b25cb6b62b | [release source commit](https://github.com/smart-tinker/stcvrc/tree/7b93ba0e1439e7f27629743bed550d99e7f9c9a4); code delta [9e235082](https://github.com/smart-tinker/stcvrc/commit/9e23508270fed96e346fd4f68447e90401669131) | Mihomo [v1.19.29](https://github.com/MetaCubeX/mihomo/tree/e26714a181ac0e2fa803453c0a8e9a9ce94e31cb) | Go 1.26.5; Windows/amd64; with_gvisor |
| Candidate 1.19.33 RC2 | [release](https://github.com/smart-tinker/stcvrc/releases/tag/stcvrc-1.19.33-rc.2); core SHA256 6a35ab8e2db4c0171f74563aded55949d10a3dcc5ad9c1c1b5e155ab2a2986c7 | [source commit](https://github.com/smart-tinker/stcvrc/tree/d888dfad5e785217778bb7515c931840d5307dd4) | Mihomo [v1.19.33](https://github.com/MetaCubeX/mihomo/tree/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8) | Go 1.26.10; Windows/amd64; with_gvisor |

The accepted .29 code delta changes the OpenVPN adapter/configuration/executor and OpenVPN transport paths, plus the PassRule API-compatibility adapter and focused tests. Exact changed paths are pinned in the JSON and compared with upstream in CI. The .33 source manifest lists 14 patch files and hashes; CI verifies each file and checks that these are exactly the source-code differences from upstream.

The .33 source.json patchSource record needs correction: it names base 88dcbf7f (the v1.19.32 base), while the candidate's declared upstream is 3f27ef39 (v1.19.33). The referenced public commit 9ccecd85 is titled as a .32 candidate evidence update, not a .33 source patch. CI reports this mismatch rather than treating the record as verified. The exact .33 source tree and its 14 file digests can still be checked against upstream; the origin of the patch archive/digest itself remains unproven.

CI fetches each exact source tag and upstream tag, verifies their peeled commits, tests the exact source, builds the Windows executable from scratch, checks the expected binary SHA256, and runs dependency-license inventory against that same source/build target. It never downloads or uses either previously built STCVRC executable. Each line gets an isolated temporary Go module/build cache; no Actions cache or artifact is used.

## Distributed release assets

All released asset names and GitHub API SHA256 digests for both versions are recorded in the JSON manifest. Release sidecars (manifests, build information, and checksum files) are provenance records, not additional executable dependencies. The UI installer is excluded.

## License inventory

For each source line CI records:
- go.mod requirements with direct/indirect annotations and the resolved Go module graph with versions/replacements;
- package-to-license URL and classifier output from pinned go-licenses v2.0.1, using Windows/amd64 with with_gvisor;
- the repository's embedded LICENSE, transport/hysteria/conns/faketcp/LICENSE, and transport/kcptun/LICENSE.md digests;
- hashes of the Go toolchain license and dependency license/notice texts collected by go-licenses save;
- source go:embed directives, so non-Go embedded resources can be reviewed.

The dependency source and notice collection exists only in the disposable runner; Actions artifacts are disabled. The run summary/log retains the report rows and license-file hashes for review. This inventory is evidence for human review, not an automated GPL or legal-compliance conclusion. Non-Go embedded content, any Unknown or ambiguous license result, redistribution obligations, copyright notices and source-offer requirements still require explicit review before claiming compliance or closing issue #7.

## Current evidence

The provenance contract tests first failed as expected on the test-only commit. The complete license job result and dependency inventory will be linked here after the run.
