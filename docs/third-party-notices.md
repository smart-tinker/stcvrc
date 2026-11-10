# Third-party notices — draft and incomplete

> **INCOMPLETE:** This is a partial record for issue #7, not the complete notice set for any STCVRC distribution and not a legal-compliance conclusion. Keep issue #7 open until the remaining dependencies and source obligations are reviewed.

## github.com/anchore/go-lzo v0.1.1

Source: [upstream LICENSE](https://github.com/anchore/go-lzo/blob/v0.1.1/LICENSE). The unpublished 1.19.33 candidate pins this module at v0.1.1 and verifies its Go module checksum in GitHub Actions.

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

## Remaining review

This draft does not cover the full dependency inventory, EasyTier LGPL/WASM source mapping, the .33 patch-origin discrepancy, or human review of distribution and source-offer obligations.