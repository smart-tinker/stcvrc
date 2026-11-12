# Third-party notices — draft and incomplete

> **INCOMPLETE:** This is manual source-license evidence for issue #7, not a complete notice set for any STCVRC distribution and not a legal-compliance conclusion. The existing RC7 draft predates the generated notices package and its embedded WASM source mapping remains unproven. A fresh source-built candidate has a separately pinned WASM source; the complete Go/Rust inventory, successful collector run, package readback, and human review are still required.

## github.com/anchore/go-lzo v0.1.1

Source: [upstream LICENSE](https://github.com/anchore/go-lzo/blob/v0.1.1/LICENSE). The RC7 draft records this module at v0.1.1. Its notice text is reusable for a later candidate only if that exact module and checksum are selected by the fresh build; the presence of this text does not make the RC7 release package complete.

The following is the complete MIT license text from that pinned upstream version:

```text
MIT License

Copyright (c) 2025 Anchore, Inc

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## github.com/metacubex/chacha v0.1.5

Pinned source: [commit 07294f500ca8384015f6cc21311de7b6f093607d](https://github.com/MetaCubeX/chacha/tree/07294f500ca8384015f6cc21311de7b6f093607d). This exact tag has no root LICENSE file; the automated scanner still reports `Unknown` for v0.1.5.

License evidence: [upstream commit 7b981d42c3baca5a004e7b0ecfb9b67ee20e583a](https://github.com/MetaCubeX/chacha/commit/7b981d42c3baca5a004e7b0ecfb9b67ee20e583a) has the exact pinned v0.1.5 commit as its parent and adds only the root `LICENSE` file. The source commit therefore makes no code changes; its license file states MIT and names Andreas Auernhammer (2016) and MetaCubex (2025). This records upstream evidence for human review, not a legal-compliance conclusion.

The exact notice text from that upstream commit is included here for review and future distribution packaging:

```text
MIT License

Copyright (c) 2016 Andreas Auernhammer
Copyright (c) 2025 MetaCubex

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## MetaCubeX source license evidence for candidate 1.19.33

The fresh Windows/amd64 `with_gvisor` inventory for source `086a62c3ce9a77f650786ae2eae92b68909d49e1` reports these root modules as `Unknown`. At the exact upstream commits below, each repository has a root `LICENSE` with the same Git blob SHA `3e3e29e359d205307555aa41f19fb2a8415de885`. The text names nekohasekai (2022) and permits use under GNU GPL version 3 or, at the recipient's option, any later version. The scanner's `Unknown` rows remain recorded in CI; this source-file evidence is for review and is not a legal-compliance conclusion.

| Module version in candidate | Exact upstream commit | Pinned upstream LICENSE |
| --- | --- | --- |
| `github.com/metacubex/sing v0.5.8` | `1dd5bcee2b112766b8f030eb51f3db2f245996ed` | [LICENSE](https://github.com/MetaCubeX/sing/blob/1dd5bcee2b112766b8f030eb51f3db2f245996ed/LICENSE) |
| `github.com/metacubex/sing-mux v0.3.12` | `714fc2e099f227b7b4bc5a62880bcb5d3c8d5b2f` | [LICENSE](https://github.com/MetaCubeX/sing-mux/blob/714fc2e099f227b7b4bc5a62880bcb5d3c8d5b2f/LICENSE) |
| `github.com/metacubex/sing-quic v0.0.0-20260904234848-1c242664697a` | `1c242664697a441b01cfaf67bdbb7bb0d532745e` | [LICENSE](https://github.com/MetaCubeX/sing-quic/blob/1c242664697a441b01cfaf67bdbb7bb0d532745e/LICENSE) |
| `github.com/metacubex/sing-shadowsocks v0.2.13` | `028e27cf15b05d39a96ae78c5b21e6d7c3b4b740` | [LICENSE](https://github.com/MetaCubeX/sing-shadowsocks/blob/028e27cf15b05d39a96ae78c5b21e6d7c3b4b740/LICENSE) |
| `github.com/metacubex/sing-shadowsocks2 v0.2.8` | `706d31e8c9a7f1d9ab94c58b326abde7026fd9cc` | [LICENSE](https://github.com/MetaCubeX/sing-shadowsocks2/blob/706d31e8c9a7f1d9ab94c58b326abde7026fd9cc/LICENSE) |
| `github.com/metacubex/sing-tun v0.4.28` | `a128d0c3c8001e041725fa67ff3b521502298f17` | [LICENSE](https://github.com/MetaCubeX/sing-tun/blob/a128d0c3c8001e041725fa67ff3b521502298f17/LICENSE) |
| `github.com/metacubex/sing-vmess v0.2.5` | `9b7fdbf462a5cf6366628631ef426c1a91f5df82` | [LICENSE](https://github.com/MetaCubeX/sing-vmess/blob/9b7fdbf462a5cf6366628631ef426c1a91f5df82/LICENSE) |
| `github.com/metacubex/fswatch v0.1.1` | `6aacc3bbe574cb676e7e1348cc7722da3420bfe1` | [LICENSE](https://github.com/MetaCubeX/fswatch/blob/6aacc3bbe574cb676e7e1348cc7722da3420bfe1/LICENSE) |

## Remaining review

This manual record does not cover the full runtime inventory, Rust dependencies embedded in EasyTier WASM, or human review of distribution and source-offer obligations. The old RC7 WASM source mapping remains unproven: rebuilding from available public EasyTier commits did not reproduce the embedded digest recorded for RC7. A future candidate must use a fresh WASM build from a pinned, available source and inventory the actual Go and Rust runtime graphs before its notices can be marked complete.

The historical RC2 `.33` patch-origin field remains unverified. CI independently checks the exact .33 source tree, source delta, and matching binary; it does not turn the old patch-origin claim into a fact or reuse it as provenance for a new candidate.

## Generated distribution package contract

For a future source-built candidate, CI must generate `THIRD-PARTY-NOTICES.txt` with the complete license texts and `THIRD-PARTY-SOURCES.json` with exact source links and digests. The runtime inventory includes the selected Windows/amd64 `with_gvisor` Go graph, the freshly built EasyTier WASM and its selected Rust target/features/dependency graph, the EasyTier Go adapter, and the Go standard-library license. Build tools and toolchains are listed in a separate appendix so they are not presented as runtime dependencies.

The generator rejects a missing dependency from the independently computed runtime graph, missing/changed license text, unresolved license IDs, or absent source directions. Release assembly must use a new candidate identity, package and hash these outputs with the freshly built core, then read back and verify the draft assets. This contract is not yet evidence that the old RC7 is complete, and no new release is created by this PR.


## Fresh candidate notice package

The source-build collector is intended to generate `THIRD-PARTY-NOTICES.txt` and `THIRD-PARTY-SOURCES.json` from the exact Windows/amd64 `with_gvisor` Go dependency graph and the Rust dependency graph used to build EasyTier's embedded WASM. It binds the output to the fresh core SHA, source commits, WASM SHA, Rust target/features, Go target/build tags, and toolchain inputs. It does not use previously published core or WASM bytes as build inputs.

The eight selected MetaCubeX modules have short root `LICENSE` headers that identify GPL version 3 or later; those headers are preserved as per-module supplemental notices. The package also includes the complete pinned GPL-3.0-or-later license text, so a short header is not misrepresented as the full license terms. [Canonical GPL-3.0-or-later text](https://raw.githubusercontent.com/spdx/license-list-data/v3.29.0/text/GPL-3.0-or-later.txt).

The Windows Go graph embeds `wintun.dll` from [MetaCubeX/sing-tun](https://github.com/MetaCubeX/sing-tun/tree/a128d0c3c8001e041725fa67ff3b521502298f17). The collector compares the selected module's embedded DLL byte-for-byte with the AMD64 DLL in the official [Wintun 0.14.1 distribution](https://www.wintun.net/builds/wintun-0.14.1.zip), verifies the archive SHA256, and includes that archive's own license/redistribution terms as a separate notice. The binding's GPL license does not substitute for the signed DLL's distribution terms.

The Rust package includes full MIT and Apache-2.0 standard-library texts and the pinned Rust toolchain's `COPYRIGHT` and `COPYRIGHT-library.html` files as supplemental notices. `go-licenses` and `cargo-about` are listed separately as build-time tools. The generated files are not currently part of the old RC7 draft. This PR adds the collector implementation; its CI run and a new candidate's draft-asset readback are still required before distribution.
