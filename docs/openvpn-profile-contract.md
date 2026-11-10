# OpenVPN profile contract

This guide documents only the profile subset verified from the exact STCVRC source revisions below. It is not a general OpenVPN directive list, a production profile, or a promise that a remote server accepts a profile.

## Source revisions

| Line | Exact source | Status |
| --- | --- | --- |
| STCVRC 1.19.29 | [`v1.19.29-stcvrc.1` source commit `7b93ba0e1439e7f27629743bed550d99e7f9c9a4`](https://github.com/smart-tinker/stcvrc/tree/7b93ba0e1439e7f27629743bed550d99e7f9c9a4) | Maintained source line |
| STCVRC 1.19.33 | [MIT-LZO candidate `76b7ec3ff9854d32cb3964403c065928ecdc9dd6`](https://github.com/smart-tinker/stcvrc/tree/76b7ec3ff9854d32cb3964403c065928ecdc9dd6), based on upstream [`3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8`](https://github.com/smart-tinker/stcvrc/tree/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8) | Candidate; not a stable release |

The YAML adapter is defined in [1.19.29](https://github.com/smart-tinker/stcvrc/blob/7b93ba0e1439e7f27629743bed550d99e7f9c9a4/adapter/outbound/openvpn.go#L68-L114) and [1.19.33](https://github.com/smart-tinker/stcvrc/blob/76b7ec3ff9854d32cb3964403c065928ecdc9dd6/adapter/outbound/openvpn.go#L40-L90). The lower-level validation is in [1.19.29](https://github.com/smart-tinker/stcvrc/blob/7b93ba0e1439e7f27629743bed550d99e7f9c9a4/transport/openvpn/config.go#L269-L350) and [1.19.33](https://github.com/smart-tinker/stcvrc/blob/76b7ec3ff9854d32cb3964403c065928ecdc9dd6/transport/openvpn/config.go#L269-L350).

## Verified YAML subset

The entries below mean the exact source exposes or validates the field. They do not prove a server handshake or platform routing behavior.

| Profile item | 1.19.29 | 1.19.33 candidate | Evidence and boundary |
| --- | --- | --- | --- |
| `server`, `port` | Required | Required | Adapter fields and `ValidateInstallScriptSubset`; CI parses the synthetic example. |
| `proto` | `udp` or `tcp` | `udp` or `tcp` | Config validation; candidate has a negative unsupported-proto test in [`config_test.go`](https://github.com/smart-tinker/stcvrc/blob/76b7ec3ff9854d32cb3964403c065928ecdc9dd6/transport/openvpn/config_test.go). |
| `dev` | `tun` only | `tun` only | Config validation. The synthetic `tap` fixture must be rejected by parser CI. This does not test OS TUN setup. |
| `cipher`, `data-ciphers`, `data-ciphers-fallback` | Exposed and validated | Exposed and validated | Adapter and config validation; candidate cipher negotiation tests are in [`data_ciphers_test.go`](https://github.com/smart-tinker/stcvrc/blob/76b7ec3ff9854d32cb3964403c065928ecdc9dd6/transport/openvpn/data_ciphers_test.go). Only the enumerated source values are claimed. |
| `auth` | Exposed and validated | Exposed and validated | Adapter and config validation; see candidate [`config_test.go`](https://github.com/smart-tinker/stcvrc/blob/76b7ec3ff9854d32cb3964403c065928ecdc9dd6/transport/openvpn/config_test.go). |
| `ca` | Required inline PEM block | Required inline PEM block | Config validation checks that a PEM block exists. Parser success does not verify trust, dates, server identity, or a TLS handshake. |
| `cert` + `key`, or `username` | Either a complete certificate/key pair or a non-empty username is required | Same | Config validation. The CI example uses explicitly synthetic username/password values and a public test CA fixture; it contains no usable account. |
| `tls-auth`, `tls-crypt`, `tls-crypt-v2` | Exposed; mutually exclusive | Exposed; mutually exclusive | Config validation and candidate [mutual-exclusion test](https://github.com/smart-tinker/stcvrc/blob/76b7ec3ff9854d32cb3964403c065928ecdc9dd6/transport/openvpn/config_test.go). Static-key decoding is exercised by the package tests, not by the placeholder conflict fixture. |
| `key-direction` | Empty, `0`, or `1` | Empty, `0`, or `1` | Config validation. It is relevant to `tls-auth`; no real server pairing is implied. |
| `ping`, `ping-restart`, `tran-window` | Exposed | Exposed | Candidate validation and push merge tests are in [`push_keepalive_test.go`](https://github.com/smart-tinker/stcvrc/blob/76b7ec3ff9854d32cb3964403c065928ecdc9dd6/transport/openvpn/push_keepalive_test.go). These unit tests do not establish every server's timer policy. |
| Server-pushed timers and continued PUSH replies | Parser fields exist; precedence/continuation not established here | Candidate has timer merge, continuation, and deferred-push tests | Candidate tests: [keepalive](https://github.com/smart-tinker/stcvrc/blob/76b7ec3ff9854d32cb3964403c065928ecdc9dd6/transport/openvpn/push_keepalive_test.go), [retry](https://github.com/smart-tinker/stcvrc/blob/76b7ec3ff9854d32cb3964403c065928ecdc9dd6/transport/openvpn/push_retry_test.go). The isolated comparison in [run 42569174128](https://github.com/smart-tinker/stcvrc/actions/runs/42569174128) is candidate/Linux evidence only. |
| `comp-lzo` | Field is exposed; broad runtime compatibility not established here | Field is exposed; isolated candidate scenarios cover selected LZO traffic | Candidate comparison/ablation is recorded in [issue #12](https://github.com/smart-tinker/stcvrc/issues/12). It does not prove all OpenVPN LZO modes or production servers. |
| `tls-version-min`, `reneg-sec` | Exposed by the 1.19.29 adapter | Not exposed as fields by the 1.19.33 OpenVPN adapter | For the candidate, behavior when these YAML keys are supplied is **UNVERIFIED**; absence from the adapter is not evidence that the full config parser rejects them. |

Any option not listed above is outside this verified subset and should be treated as **UNVERIFIED** until source and test evidence are added. In particular, do not infer that a generic OpenVPN directive supported by another core is accepted by a distributed STCVRC binary.

## Parser examples and CI

The files in [`openvpn-profile-examples/`](openvpn-profile-examples/) are synthetic and credential-free. CI freshly builds both exact source revisions above on a standard `ubuntu-24.04` runner, then runs the resulting binary in Mihomo's `-t` configuration-test mode against the valid and invalid examples. The command is equivalent to:

```sh
mihomo -d "$RUNNER_TEMP/profile-home" -f docs/openvpn-profile-examples/valid.yaml -t
```

The negative examples must fail with the expected validation error. CI records the source commit and command in the run summary. No release binary, prior build, Actions artifact, cache, secret, production profile, or network endpoint is used.

A successful `-t` result establishes only YAML/configuration parsing and OpenVPN adapter validation. The CLI path calls the configuration parser and exits; it does not connect to the VPN server or validate certificate trust, credentials, DNS reachability, route installation, TUN availability, Windows service behavior, or application traffic. The underlying CLI flag is visible in [`main.go`](https://github.com/smart-tinker/stcvrc/blob/76b7ec3ff9854d32cb3964403c065928ecdc9dd6/main.go#L76).

## Troubleshooting by stage

1. **Profile parsing:** run the same core with `-t`. A parse error points to YAML shape, required fields, unsupported values, or an invalid option combination. It says nothing about the endpoint.
2. **DNS and transport:** after parsing, separately check whether the configured server name resolves and the selected UDP/TCP path can reach the endpoint. CI examples deliberately use `vpn.example.invalid` and never connect.
3. **TLS and authentication:** verify the server certificate against the intended CA, then check the authentication method and server policy. Redact credentials, auth tokens, private keys, full certificates, real hostnames/IPs, and identifying profile names before sharing logs.
4. **Pushed routes and DNS:** inspect the server's pushed addresses, routes, DNS, and keepalive values; compare them with the platform's actual route and resolver state. Parser/unit tests do not prove those changes were applied by Windows or Linux.
5. **Application traffic:** test the intended application and destination through the selected proxy path, with an independent control and a direct-path negative control. A core health response or synthetic HTTP test is not user acceptance.

Report only the failing stage, timestamp/time zone, core source/version, redacted error, and whether the result is parser-only, isolated Linux, native Windows, or user-observed. Never attach a real profile, password, token, certificate/private key, private endpoint, or raw operational log.

## Stock Clash Verge Rev boundary

STCVRC is consumed as the core by stock Clash Verge Rev; this repository does not implement a separate UI. This guide establishes Mihomo core YAML fields only. It does not claim how every CVR version renders an OpenVPN entry or that a parser-accepted entry is connectable. The selected CVR 2.5.10 installer/update and native Windows acceptance are tracked separately in [issue #3](https://github.com/smart-tinker/stcvrc/issues/3).

## Upstream exit

This is a temporary downstream contract for the exact source pins above. If a stock CVR-shipped core later passes the required scenarios with corresponding acceptance evidence, prefer upstream documentation and remove this downstream guide rather than expanding it into a separate product.
