# Third-party notices — draft and incomplete

> **INCOMPLETE:** This is a partial record for issue #7, not the complete notice set for any STCVRC distribution and not a legal-compliance conclusion. Keep issue #7 open until the remaining dependencies and source obligations are reviewed.

## github.com/anchore/go-lzo v0.1.1

Source: [upstream LICENSE](https://github.com/anchore/go-lzo/blob/v0.1.1/LICENSE). The current draft RC6 candidate pins this module at v0.1.1 and verifies its Go module checksum in GitHub Actions.

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

This draft does not cover the full dependency inventory, EasyTier LGPL/WASM source mapping, the .33 patch-origin discrepancy, or human review of distribution and source-offer obligations.