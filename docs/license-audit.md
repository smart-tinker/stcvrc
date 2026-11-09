# STCVRC dependency licenses and source provenance

This record covers the STCVRC core executable distributed in the accepted 1.19.29 release, the historical 1.19.33 RC2 candidate, and the separate unpublished 1.19.33 MIT-LZO candidate. The stock Clash Verge Rev UI/installer is not redistributed here. Profiles, credentials, certificates, and runtime/deployment state are out of scope.

The machine-readable pins, reference asset hashes, source commits, toolchains and build flags are in [license-provenance.json](license-provenance.json).

## Source and build mapping

| Line | Public reference | Exact STCVRC source | Upstream base | Fresh build |
| --- | --- | --- | --- | --- |
| Accepted 1.19.29 | [release](https://github.com/smart-tinker/stcvrc/releases/tag/v1.19.29-stcvrc.1); core SHA256 71195c943be67017c5646ea2021734bc122fa83c58a408ab6713a2b25cb6b62b | [release source commit](https://github.com/smart-tinker/stcvrc/tree/7b93ba0e1439e7f27629743bed550d99e7f9c9a4); code delta [9e235082](https://github.com/smart-tinker/stcvrc/commit/9e23508270fed96e346fd4f68447e90401669131) | Mihomo [v1.19.29](https://github.com/MetaCubeX/mihomo/tree/e26714a181ac0e2fa803453c0a8e9a9ce94e31cb) | Go 1.26.5; Windows/amd64; with_gvisor |
| Candidate 1.19.33 RC2 | [release](https://github.com/smart-tinker/stcvrc/releases/tag/stcvrc-1.19.33-rc.2); core SHA256 6a35ab8e2db4c0171f74563aded55949d10a3dcc5ad9c1c1b5e155ab2a2986c7 | [source commit](https://github.com/smart-tinker/stcvrc/tree/d888dfad5e785217778bb7515c931840d5307dd4) | Mihomo [v1.19.33](https://github.com/MetaCubeX/mihomo/tree/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8) | Go 1.26.10; Windows/amd64; with_gvisor |
| Candidate 1.19.33 MIT-LZO (unpublished) | No release asset or reference hash | [source commit](https://github.com/smart-tinker/stcvrc/tree/76b7ec3ff9854d32cb3964403c065928ecdc9dd6) | Mihomo [v1.19.33](https://github.com/MetaCubeX/mihomo/tree/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8) | CI fresh Windows/amd64 build; anchore/go-lzo v0.1.1 (MIT) |

The accepted .29 code delta changes the OpenVPN adapter/configuration/executor and OpenVPN transport paths, plus the PassRule API-compatibility adapter and focused tests. Exact changed paths are pinned in the JSON and compared with upstream in CI. The .33 source manifest lists 14 patch files and hashes; CI verifies each file and checks that these are exactly the source-code differences from upstream.

The unpublished MIT-LZO candidate pins source commit 76b7ec3ff9854d32cb3964403c065928ecdc9dd6 and the permissive decoder module github.com/anchore/go-lzo v0.1.1. The existing issue #7 audit job fetches that exact commit, runs OpenVPN tests, builds from a fresh checkout with isolated Go caches, verifies the module checksum and MIT classification, and records the candidate SHA without comparing it to a release asset.

The historical RC2 source.json patchSource record needs correction: it names base 88dcbf7f (the v1.19.32 base), while the candidate's declared upstream is 3f27ef39 (v1.19.33). The referenced public commit 9ccecd85 is titled as a .32 candidate evidence update, not a .33 source patch. CI reports this mismatch rather than treating the record as verified. The exact .33 source tree and its 14 file digests can still be checked against upstream; the origin of the patch archive/digest itself remains unproven.

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

## Manual review status (2026-11-09)

### CI evidence

- [Source and license run 42653348965](https://github.com/smart-tinker/stcvrc/actions/runs/42653348965) passed on `007c28ed49edbab66e39179411803940d97e5ab3`: source tests passed, and the current PR source compiled for Linux and Windows.
- Its `license-audit` job freshly built the accepted .29 and candidate .33 Windows/amd64 cores from the pinned source trees. The resulting SHA256 values matched the public release references: `71195c943be67017c5646ea2021734bc122fa83c58a408ab6713a2b25cb6b62b` and `6a35ab8e2db4c0171f74563aded55949d10a3dcc5ad9c1c1b5e155ab2a2986c7`. `go mod verify` passed for both.
- [Network run 42653349028](https://github.com/smart-tinker/stcvrc/actions/runs/42653349028) passed on the same head in Linux and Windows jobs. It exercised the pinned candidate; it is not a license conclusion.
- Both runs have zero Actions artifacts. The audit uses isolated runner-temporary Go caches only; it does not use Actions cache or previously built STCVRC binaries.

### Manual source-license checks

The pinned source LICENSE files for these MetaCubeX fork modules are identical Git blobs (`3e3e29e359d205307555aa41f19fb2a8415de885`) whose text declares GNU GPL version 3 or later. This resolves the scanner's `Unknown` label for these license files, but does not by itself establish that every required notice is shipped:

- [fswatch v0.1.1](https://github.com/MetaCubeX/fswatch/blob/v0.1.1/LICENSE)
- [sing-mux v0.3.10](https://github.com/MetaCubeX/sing-mux/blob/v0.3.10/LICENSE), [v0.3.12](https://github.com/MetaCubeX/sing-mux/blob/v0.3.12/LICENSE)
- [sing-quic stable pin](https://github.com/MetaCubeX/sing-quic/blob/68e10a6afdc3/LICENSE), [candidate pin](https://github.com/MetaCubeX/sing-quic/blob/1c242664697a/LICENSE)
- [sing-shadowsocks v0.2.12](https://github.com/MetaCubeX/sing-shadowsocks/blob/v0.2.12/LICENSE), [v0.2.13](https://github.com/MetaCubeX/sing-shadowsocks/blob/v0.2.13/LICENSE)
- [sing-shadowsocks2 v0.2.7](https://github.com/MetaCubeX/sing-shadowsocks2/blob/v0.2.7/LICENSE), [v0.2.8](https://github.com/MetaCubeX/sing-shadowsocks2/blob/v0.2.8/LICENSE)
- [sing-tun v0.4.21](https://github.com/MetaCubeX/sing-tun/blob/v0.4.21/LICENSE), [v0.4.28](https://github.com/MetaCubeX/sing-tun/blob/v0.4.28/LICENSE)
- [sing-vmess v0.2.5](https://github.com/MetaCubeX/sing-vmess/blob/v0.2.5/LICENSE)
- [sing v0.5.7](https://github.com/MetaCubeX/sing/blob/v0.5.7/LICENSE), [v0.5.8](https://github.com/MetaCubeX/sing/blob/v0.5.8/LICENSE)

The remaining material gaps are:

- `github.com/metacubex/chacha@v0.1.5`: the root module has no recognized LICENSE, and `chacha/chacha.go` points to a LICENSE file not present at the inspected module/package paths. The MIT files in neighboring `chachapoly1305` and `poly1305` subpackages do not establish the license for `chacha` itself.
- The accepted .29 and historical .33 RC2 builds still use github.com/rasky/go-lzo at 96a758eda86e, classified as GPL-2.0; the pinned [LICENSE.gpl](https://github.com/rasky/go-lzo/blob/96a758eda86e/LICENSE.gpl) is GPL version 2 text. The unpublished .33 MIT-LZO candidate replaces it with github.com/anchore/go-lzo v0.1.1; replacing an already published line still requires acceptance and a new release decision.
- `github.com/easytier/easytier/easytier-go` at `3d0c9c3ca5e2` carries [LGPL-3.0](https://github.com/EasyTier/EasyTier/blob/3d0c9c3ca5e2/easytier-go/LICENSE). Its use in the built executable and the applicable notice/source/relink materials still need human review.
- `go-licenses save` collects dependency license texts only in the disposable runner directory; the workflow records their hashes and creates no artifact. The repository/release still needs a reviewed, publicly accessible notice set for the distributed binaries.
- Candidate `source.json` records patch base `88dcbf7f` (.32), while the checked .33 upstream is `3f27ef39`. CI verifies the 14 .33 files and exact .33 source delta independently, but the declared patch-origin link remains unproven.

Issue #7 remains open. No license violation or overall compliance conclusion is asserted.
