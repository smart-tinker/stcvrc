# Fresh-source OpenVPN differential experiment

Refs [#10](https://github.com/smart-tinker/stcvrc/issues/10). One standard Ubuntu runner builds both cores from scratch with the same Go/flags, then runs identical scenarios sequentially. No old release binaries, Actions artifacts or persistent cache. Dependency downloads and intra-job compilation cache are temporary. The server is Ubuntu's signed OpenVPN package; its exact installed version is logged. It is not developed by STCVRC.

Inputs: upstream `3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8`, downstream `d888dfad5e785217778bb7515c931840d5307dd4`, harness exact PR head. These are source revisions, not release binary references. Both executable SHA256 values are calculated after fresh builds. Candidate code is .33; main currently retains a different .29 source line.

The comparison intentionally runs on same-repository draft PRs after local review. Existing network/source jobs retain their draft gates: no old Windows release EXE is launched in this experiment. This workflow is an investigation, not a required product acceptance check.

Each runtime scenario executes in a fresh Linux network namespace. Only loopback and the test server's TUN exist there. HTTP backend rejects direct source addresses; the core uses its default userspace IP stack. Test-only CA/client keys are generated at runtime. No production profiles/credentials or host route changes. Do not run this root-capable harness on a working VPN machine; use a disposable runner.

| Delta | Evidence planned in this first experiment |
|---|---|
| Server-pushed keepalive / idle | Baseline HTTP, 14 seconds idle, no server inactivity timeout, resumed HTTP |
| Soft rekey continuity | One 200-line stream over 40 seconds, exact ordered payload, >=2 server soft resets, live core/server |
| URLTest tolerance | Same `TestURLTestTolerance` and lifecycle tests run against both source trees |
| Deferred PUSH_REQUEST retry | NOT TESTED by real server yet |
| Failure teardown/reactivation | NOT TESTED yet |
| LZO/control edge cases/token refresh | NOT TESTED yet |

A setup/initial-connect failure or direct bypass is INVALID, not an upstream defect. Scenario FAIL is printed without suppressing the comparison with the other core. A green comparison job only means the experiment completed with valid observations; read the scenario table. Logs carry stream sample counts, rekeys, inactivity counts and binary hashes. The test does not prove Windows/TUN/GUI/user acceptance. Upstream already contains server-initiated rekey support.
