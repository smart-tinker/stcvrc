# STCVRC dependency licenses and source provenance

This record distinguishes the historical 1.19.29, 1.19.33 RC1/RC2 and RC7 core records from the fresh-source RC8 package contract. The stock Clash Verge Rev UI/installer is not redistributed here. Profiles, credentials, certificates, and runtime/deployment state are out of scope.

The machine-readable pins, reference asset hashes, source commits, toolchains and build flags are in [license-provenance.json](license-provenance.json).

## Fresh RC8 inputs and review packet

The current recipe is [tools/source-build/ci.sh](../tools/source-build/ci.sh). It rebuilds
[the selected STCVRC source](https://github.com/smart-tinker/stcvrc/tree/a884ad53a3999dd35acab979e0bb040c47f6dbc9)
against Mihomo v1.19.33 and regenerates EasyTier Go bindings and WASM from
[EasyTier 3463190](https://github.com/EasyTier/EasyTier/tree/3463190838eb642ba8324c6a4011acdea52495a8).
The actual core graph is tested with that local module replacement. No previous
STCVRC executable or embedded WASM is a build input.

The manual main-branch assembler targets a new `stcvrc-1.19.33-rc.8` draft only.
Its review packet contains the fresh Windows EXE, `RC-MANIFEST.json`,
`SOURCE-BUILD.json`, `THIRD-PARTY-NOTICES.txt`,
`THIRD-PARTY-SOURCES.json`, `LICENSE` and `SHA256SUMS`.
The manifest records measured bytes, exact sources, changed source blobs,
toolchains, flags and the successful native-job identity. A second fresh native
Windows build must match that EXE/WASM before assembly. The tag metadata and
actual Git tag ref are checked separately. See [the CI layout and assembly
contract](RELEASING.md).

The MIT decoder and CVR 2.5.10 choices were already approved. Human acceptance of
the resulting exact notice/source packet is separate from those implementation
choices. Historical GPL-2.0-only LZO and unavailable RC7 WASM-source evidence are
recorded limitations, not facts retroactively cleared by a fresh RC8 build.
The actual successful run and draft-asset readback are linked from
[issue #7](https://github.com/smart-tinker/stcvrc/issues/7) when available.

## Source and build mapping

| Line | Public reference | Exact STCVRC source | Upstream base | Fresh build |
| --- | --- | --- | --- | --- |
| Accepted 1.19.29 | [release](https://github.com/smart-tinker/stcvrc/releases/tag/v1.19.29-stcvrc.1); core SHA256 71195c943be67017c5646ea2021734bc122fa83c58a408ab6713a2b25cb6b62b | [release source commit](https://github.com/smart-tinker/stcvrc/tree/7b93ba0e1439e7f27629743bed550d99e7f9c9a4); code delta [9e235082](https://github.com/smart-tinker/stcvrc/commit/9e23508270fed96e346fd4f68447e90401669131) | Mihomo [v1.19.29](https://github.com/MetaCubeX/mihomo/tree/e26714a181ac0e2fa803453c0a8e9a9ce94e31cb) | Go 1.26.5; Windows/amd64; with_gvisor |
| Candidate 1.19.33 RC2 | [release](https://github.com/smart-tinker/stcvrc/releases/tag/stcvrc-1.19.33-rc.2); core SHA256 6a35ab8e2db4c0171f74563aded55949d10a3dcc5ad9c1c1b5e155ab2a2986c7 | [source commit](https://github.com/smart-tinker/stcvrc/tree/d888dfad5e785217778bb7515c931840d5307dd4) | Mihomo [v1.19.33](https://github.com/MetaCubeX/mihomo/tree/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8) | Go 1.26.10; Windows/amd64; with_gvisor |
| Candidate 1.19.33 RC7 draft (MIT-LZO) | Draft release 442680453; core SHA256 d72784d98a44b90e561c701589c50f53074958d7cef656607ee5be1143b36c87 | [source commit](https://github.com/smart-tinker/stcvrc/tree/086a62c3ce9a77f650786ae2eae92b68909d49e1) | Mihomo [v1.19.33](https://github.com/MetaCubeX/mihomo/tree/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8) | Go 1.26.11; Windows/amd64; with_gvisor; anchore/go-lzo v0.1.1 (MIT) |

The accepted .29 code delta changes the OpenVPN adapter/configuration/executor and OpenVPN transport paths, plus the PassRule API-compatibility adapter and focused tests. Exact changed paths are pinned in the JSON and compared with upstream in CI. The .33 source manifest lists its patch files and hashes; CI verifies each file and checks that these are exactly the source-code differences from upstream.

The existing RC7 draft remains a historical candidate: it uses source commit `086a62c3ce9a77f650786ae2eae92b68909d49e1` and the permissive `github.com/anchore/go-lzo v0.1.1` decoder. Its binary is not an input to the fresh source-build or notice collector. The accepted 1.19.29 and historical RC2 `go-lzo` records remain a separate GPL-2.0-only risk.

The current 1.19.33 source.json patchSource record remains unverified: it names base 88dcbf7f (the v1.19.32-era base), while the candidate's declared upstream is 3f27ef39 (v1.19.33). The referenced public commit 9ccecd85 resolves to a STCVRC commit whose changed files are under the v1.19.32 candidate-preparation tree, not a Mihomo source-patch commit. CI reports this mismatch rather than treating the record as verified. The exact RC2 .33 source tree and patch-file digests were checked against upstream; the historical origin claim for the patch archive remains unverified.

For a new candidate, the collector runs after the source-builder in the same disposable GitHub runner. It verifies the exact source checkouts, fresh Windows and Linux core bytes, embedded EasyTier WASM, Cargo.lock and build report before generating notices. It inventories the selected Windows/amd64 `with_gvisor` Go graph, the Rust target/features used for the fresh WASM, their toolchain runtime notices, and build tools in a separate section. It uses runner-temporary caches only; Actions cache and artifacts are not part of this workflow.

## Distributed release assets

All released asset names and GitHub API SHA256 digests for both versions are recorded in the JSON manifest. Release sidecars (manifests, build information, and checksum files) are provenance records, not additional executable dependencies. The UI installer is excluded.

## License inventory

For the generated package the collector uses the exact Go build graph and pinned `go-licenses` output, including module replacements, manual MetaCubeX GPL evidence, and the Go standard-library license. It separately inventories Rust crates selected by Cargo metadata and `cargo-about`, cross-checks the graph against `Cargo.lock`, includes the Rust standard-library license and distribution copyright files, and treats the embedded Wintun DLL's official redistribution terms as a separate notice. Any missing runtime component, unknown license, missing text or source digest fails collection.

The generator does not decide legal compliance. The human review still needs to assess redistribution and source-offer obligations before issue #7 can close. Full generated files are intended for the new candidate's release package; CI logs report only counts and file hashes.

## Historical RC7 evidence — 2026-11-12

The existing draft release is [RC7](https://github.com/smart-tinker/stcvrc/releases/tag/stcvrc-1.19.33-rc.7), GitHub Release ID 442680453. Its release metadata targets `9436a80b8805a6706931ea2fbb8c5311c7767a72`; its core records source commit `086a62c3ce9a77f650786ae2eae92b68909d49e1` and has the core asset with SHA256 `d72784d98a44b90e561c701589c50f53074958d7cef656607ee5be1143b36c87`. Its canonical source, build, and asset records are in [license-provenance.json](license-provenance.json). The RC7 draft predates the notice/source package work in this PR; it does not contain `THIRD-PARTY-NOTICES.txt` or `THIRD-PARTY-SOURCES.json`.

The recorded RC7 EasyTier Go module points to public source commit `3d0c9c3ca5e2c0b680383dedf5898f6c7eef9253`, while its embedded WASM provenance names Rust source commit `63519db2b5f2a6a1b9b7f20905f036dab54eb829` and WASM SHA256 `8b82f37d62fba2ffe8e256386096fddf448d4261d51c495d5bd97cd11bbb24a0`. The named Rust commit is not available from the public EasyTier repository. Clean rebuilds from the available artifact-introduction source and the later Go-module source produced different WASM hashes; those results do not prove the source of the RC7 embedded WASM. This evidence is recorded in [issue #7](https://github.com/smart-tinker/stcvrc/issues/7#issuecomment-6823998078). The old RC7 mapping remains unproven.

The old RC7 mapping cannot be repaired by changing its declared digest: available-source rebuilds did not reproduce its embedded WASM bytes. A subsequent candidate must instead use the freshly generated WASM from an exact public EasyTier source commit, replace the module with that source-built tree, and rebuild/test the core from scratch. The collector binds notices to that new build report; no old binary or WASM is reused.

The required source-built license and native Windows jobs invoke the collector after a fresh build. Draft assembly requires their successful results and reads back every new asset. A passing collector, matching native-tested bytes, and the actual draft readback are separate evidence; the implementation alone proves none of them. RC7 remains outside this generated package.

Issue #7 remains open. The GPL-2.0-only `go-lzo` dependency is recorded as a historical dependency risk for the accepted .29 build and RC2, without a finding of infringement. The RC7 candidate uses the separately pinned MIT decoder. No overall legal-compliance conclusion is asserted.

## Historical manual review status (2026-11-09)

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

- `github.com/metacubex/chacha@v0.1.5`: the pinned tag resolves to `07294f500ca8384015f6cc21311de7b6f093607d`; its `chacha/chacha.go` points to a root `LICENSE` that is absent from that tag. The next upstream commit, [`7b981d42`](https://github.com/MetaCubeX/chacha/commit/7b981d42c3baca5a004e7b0ecfb9b67ee20e583a), is exactly one commit ahead and adds only a root [MIT LICENSE](https://github.com/MetaCubeX/chacha/blob/7b981d42c3baca5a004e7b0ecfb9b67ee20e583a/LICENSE), naming Andreas Auernhammer (2016) and MetaCubeX (2025). The pinned source files retain the pointer and 2016 copyright header; the original [`aead/chacha20` source license](https://github.com/aead/chacha20/blob/master/LICENSE) is MIT under the same 2016 copyright. The pinned tag's automated classification remains `Unknown`. The direct upstream child commit's sole change is the MIT LICENSE file, with the exact pinned tag as its parent; the complete text and links are recorded in `docs/third-party-notices.md` for human review and future distribution packaging. This is evidence, not a legal-compliance conclusion.
- The accepted .29 and historical .33 RC2 builds still use github.com/rasky/go-lzo at 96a758eda86e, classified as GPL-2.0; the pinned [LICENSE.gpl](https://github.com/rasky/go-lzo/blob/96a758eda86e/LICENSE.gpl) is GPL version 2 text. The unpublished .33 MIT-LZO candidate replaces it with github.com/anchore/go-lzo v0.1.1; replacing an already published line still requires acceptance and a new release decision.
- `github.com/easytier/easytier/easytier-go` at `3d0c9c3ca5e2` carries [LGPL-3.0](https://github.com/EasyTier/EasyTier/blob/3d0c9c3ca5e2/easytier-go/LICENSE). Its README says the Go adapter embeds an EasyTier Core WASM. At that exact module commit, [provenance.go](https://github.com/EasyTier/EasyTier/blob/3d0c9c3ca5e2c0b680383dedf5898f6c7eef9253/easytier-go/internal/artifact/provenance.go) names source commit `63519db2b5f2a6a1b9b7f20905f036dab54eb829` and WASM SHA-256 `8b82f37d62fba2ffe8e256386096fddf448d4261d51c495d5bd97cd11bbb24a0`. GitHub's public commit API returned `No commit found for SHA` for that source commit, so the WASM source cannot currently be fetched from the recorded provenance ref for an independent rebuild. The generator at the exact module source builds from a clean EasyTier checkout, but the source input remains unavailable at the recorded ref. Its use in the distributed executable and applicable notice/source/relink terms still need review.
- The old RC7 draft has no generated full notice/source package. The collector added here must pass against the fresh source-built candidate before its output can be assembled into a new draft.
- Candidate `source.json` records patch base `88dcbf7f` (.32), while the checked .33 upstream is `3f27ef39`. CI verifies the 14 .33 files and exact .33 source delta independently, but the declared patch-origin link remains unproven.

Issue #7 remains open. No license violation or overall compliance conclusion is asserted.
