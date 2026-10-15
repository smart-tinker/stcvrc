<h1 align="center">STCVRC</h1>

<h3 align="center">Smart Tinker Clash Verge Rev Core</h3>

STCVRC is a replaceable core for the unmodified
[Clash Verge Rev](https://github.com/clash-verge-rev/clash-verge-rev) desktop
application. It is a downstream of
[MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) focused on OpenVPN
session continuity required by our Clash Verge Rev runtime.

STCVRC is an independent project and is not affiliated with MetaCubeX or Clash
Verge Rev.

## Architecture

- Clash Verge Rev remains the stock upstream UI, service, installer, and update
  channel. This repository does not contain a UI fork.
- STCVRC builds only `verge-mihomo.exe`, the core binary consumed by Clash
  Verge Rev.
- Local profiles, credentials, certificates, route policy, and deployment state
  are deliberately excluded from this repository.
- The maintained source delta is limited to OpenVPN compatibility, control-plane
  continuity during soft rekey, and the API behavior required by Clash Verge
  Rev.

## Candidate review (not a release)

This branch stages the source of local candidate `792d4c3e` (Mihomo
`v1.19.32`) for review. See [candidate manifest](candidates/v1.19.32-20261007/manifest.json).
The published release below remains unchanged. The candidate is **not accepted
for installation**: the new full-stack laboratory gate has not run.

`build-windows.ps1` still pins the accepted release and deliberately rejects
changed candidate sources. It is not a candidate build recipe. No release tag,
installer, binary, private profile or runtime log is published by this PR.

## Current release line

| Component | Accepted version |
| --- | --- |
| STCVRC | `v1.19.29-stcvrc.1` |
| Mihomo base | `v1.19.29` |
| Clash Verge Rev | `v2.5.2` |
| Go toolchain | `go1.26.5 windows/amd64` |
| Output | `verge-mihomo.exe` |

The release contains the STCVRC core only. Obtain Clash Verge Rev from its
[official v2.5.2 release](https://github.com/clash-verge-rev/clash-verge-rev/releases/tag/v2.5.2).

## Reproducible Windows build

```powershell
git clone https://github.com/smart-tinker/stcvrc.git
cd stcvrc
git checkout v1.19.29-stcvrc.1
.\build-windows.ps1
```

`build-windows.ps1` requires exactly Go `1.26.5`, runs the tests for the changed
OpenVPN and outbound adapter contours, builds with fixed version metadata, and
rejects an output whose SHA-256 differs from:

```text
71195C943BE67017C5646EA2021734BC122FA83C58A408AB6713A2B25CB6B62B
```

The equivalent build command is:

```powershell
$env:GOOS = 'windows'
$env:GOARCH = 'amd64'
$env:GOAMD64 = 'v1'
$env:CGO_ENABLED = '0'
$env:GOFLAGS = '-mod=readonly'
go build -tags with_gvisor -trimpath -buildvcs=false `
  -ldflags '-s -w -buildid= -X "github.com/metacubex/mihomo/constant.Version=1.19.29-STCVRC-openvpn-rekey-9e235082" -X "github.com/metacubex/mihomo/constant.BuildTime=2026-07-20T00:00:00Z"' `
  -o .\dist\verge-mihomo.exe .
```

## Use with Clash Verge Rev

Back up the bundled `verge-mihomo.exe`, stop the Clash Verge Rev service, and
replace only that core binary. The UI package and service helper remain stock.
The release manifest records the accepted UI installer digest and its verified
Tauri updater signature; the UI installer itself is not redistributed here.

## Upstream documentation

Configuration and controller API documentation is maintained by MetaCubeX at
[wiki.metacubex.one](https://wiki.metacubex.one/).

## Credits and license

STCVRC retains the upstream project history and credits. See the upstream
project and source history for the complete contributor record.

This software is released under the GPL-3.0 license. As required by the
upstream license notice, the downstream project name does not contain the word
`mihomo`.
