# Linux maintenance primitives and recovery CI

This package extracts generic restart receipt and Linux process identity primitives for a future replacement of the historical private host-preparation helper. It contains no host names, operational paths, profile data, hashes, or deployment state. The deployed updater is not changed by this PR.

The receipt helper persists a dispatch intent before making a DBus call, persists the returned job path before observing it, and refuses to replay a receipt after an ambiguous outcome. An observer can resume read-only observation from a durable job receipt. Process checks require a stable MainPID, PID start-time identity, and the expected executable SHA256.

The counter classifier does not treat NRestarts as monotonic. On the current Ubuntu hosted runner, an automatic retry incremented it; explicit RestartUnit changed InvocationID and reset it. A counter decrease or unchanged value is accepted only with a matching durable job receipt. Unknown transitions fail closed.

The isolated GitHub job uses standard ubuntu-24.04 only. Its native transient-unit observation is required; missing systemd/sudo/capability is BLOCKED, never a skip. Later steps in this issue add checksum-pinned binary replacement and recovery using only RUNNER_TEMP-owned paths and unique stcvrc-ci-* units. No production units, routes, VPN profiles, Actions artifacts, caches, or secrets are involved.

The experiment's CI result is evidence for this generic helper and the runner environment only. Production integration and user acceptance remain separate gates.