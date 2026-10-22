# STCVRC 1.19.33 candidate (2026-10-22)

An isolated evaluation build based on exact upstream `v1.19.33`. This is not a
release or a replacement of the current installation. Provenance and source
file digests are in [source.json](source.json).

The maintained delta is the existing OpenVPN keepalive/control continuity,
deferred PUSH_REQUEST retry, teardown/reactivation, and URLTest tolerance
behavior from the previously reviewed candidate. All 14 delta files match that
source byte for byte. Upstream 1.19.33 already includes the P_DATA_V1 AEAD fix.
`go.mod`, `go.sum`, and the upstream WireGuard backend default are unchanged.
In particular, WireGuard auto selects mipstack on this base; the older Home
build selected gvisor. External VLESS checks do not exercise that difference.

The TLS dependency remains `github.com/metacubex/tls v0.1.9`. Build with the
isolated official Go 1.26.10 Linux/amd64 toolchain, whose archive digest is
recorded in source.json. No system toolchain installation is required.

## Build and focused checks

Use a clean, locally committed candidate checkout. Set GO to that Go executable
and BUILD to a private build directory outside the checkout. Cache and output
remain outside source. The original root build-windows.ps1 is retained solely
for the accepted 1.19.29 release; it is not the candidate build procedure.

```sh
export GOENV=off GOWORK=off GOTOOLCHAIN=local CGO_ENABLED=0 GOMAXPROCS=2
export GOFLAGS='-mod=readonly -p=2'
export GOMODCACHE="$BUILD/gomodcache" GOCACHE="$BUILD/gocache" TMPDIR="$BUILD/tmp"
"$GO" test -tags with_gvisor -count=1 -timeout=180s ./transport/openvpn ./adapter/outbound ./adapter/outboundgroup
"$GO" vet -tags with_gvisor ./transport/openvpn ./adapter/outbound ./adapter/outboundgroup
GOOS=windows GOARCH=amd64 GOAMD64=v1 "$GO" build -tags with_gvisor -trimpath -buildvcs=false \
  -ldflags '-s -w -buildid= -X github.com/metacubex/mihomo/constant.Version=1.19.33-STCVRC-candidate-20261022 -X github.com/metacubex/mihomo/constant.BuildTime=2026-10-22T00:00:00Z' \
  -o "$BUILD/dist/stcvrc-1.19.33-candidate.exe" .
```

Record the source commit, binary SHA-256, `go version -m`, test results and VM
acceptance evidence with the build output. Rebuild with the same inputs to
check byte reproducibility. This procedure is a Linux-to-Windows cross-build,
not a Windows-native toolchain acceptance claim.

## userVM boundary

Run beside the installed core under the distinct process name
`stcvrc-1.19.33-candidate.exe`, on separate loopback ports, with candidate TUN and
DNS listener disabled. Reuse only the existing external 4VPS/GC leaf definitions
inside the VM; never export profiles or credentials to this repository. Do not
replace the GUI/service core, alter system proxy/routes/DNS, stop the observer,
or restore earlier monitoring history. Stop only the exact process launched
for the candidate. This check cannot establish GUI/service integration, reboot,
TUN, corporate OpenVPN, WireGuard, or long-term stability acceptance.
