<h1 align="center">
  STCVRC
</h1>

<h3 align="center">Smart Tinker Clash Verge Rev Core</h3>

STCVRC is a replaceable core for the stock
[Clash Verge Rev](https://github.com/clash-verge-rev/clash-verge-rev) desktop
application. It is based on the latest accepted stable release of
[MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo).

## Scope

- Clash Verge Rev is used unmodified; this project does not maintain a UI fork.
- The maintained source delta is limited to OpenVPN compatibility, control-plane
  continuity during soft rekey, and the API surface required by Clash Verge Rev.
- Local profiles, credentials, certificates, and deployment state are not part
  of this repository.
- The Windows amd64 artifact is built as `verge-mihomo.exe` so it can replace
  the stock Clash Verge Rev core without changing the UI package.

STCVRC is an independent downstream project and is not affiliated with
MetaCubeX or Clash Verge Rev.

## Features

- Local HTTP/HTTPS/SOCKS server with authentication support
- VMess, VLESS, Shadowsocks, Trojan, Snell, TUIC, Hysteria protocol support
- Built-in DNS server that aims to minimize DNS pollution attack impact, supports DoH/DoT upstream and fake IP.
- Rules based off domains, GEOIP, IPCIDR or Process to forward packets to different nodes
- Remote groups allow users to implement powerful rules. Supports automatic fallback, load balancing or auto select node
  based off latency
- Remote providers, allowing users to get node lists remotely instead of hard-coding in config
- Netfilter TCP redirecting. Deploy Mihomo on your Internet gateway with `iptables`.
- Comprehensive HTTP RESTful API controller

## Upstream documentation

Configuration and API documentation is maintained by the upstream project at
[wiki.metacubex.one](https://wiki.metacubex.one/).

## For development

Requirements:
[Go 1.20 or newer](https://go.dev/dl/)

Build STCVRC:

```shell
git clone https://github.com/smart-tinker/mihomo.git stcvrc
cd stcvrc
go mod download
go build -tags with_gvisor -o verge-mihomo.exe
```

Set go proxy if a connection to GitHub is not possible:

```shell
go env -w GOPROXY=https://goproxy.io,direct
```

Build with gvisor tun stack:

```shell
go build -tags with_gvisor
```

### IPTABLES configuration

Work on Linux OS which supported `iptables`

```yaml
# Enable the TPROXY listener
tproxy-port: 9898

iptables:
  enable: true # default is false
  inbound-interface: eth0 # detect the inbound interface, default is 'lo'
```

## Debugging

Check [wiki](https://wiki.metacubex.one/api/#debug) to get an instruction on using debug
API.

## Credits

- [Dreamacro/clash](https://github.com/Dreamacro/clash)
- [SagerNet/sing-box](https://github.com/SagerNet/sing-box)
- [riobard/go-shadowsocks2](https://github.com/riobard/go-shadowsocks2)
- [v2ray/v2ray-core](https://github.com/v2ray/v2ray-core)
- [WireGuard/wireguard-go](https://github.com/WireGuard/wireguard-go)
- [yaling888/clash-plus-pro](https://github.com/yaling888/clash)

## License

This software is released under the GPL-3.0 license.

**In addition, any downstream projects not affiliated with `MetaCubeX` shall not contain the word `mihomo` in their names.**
