# Idle target candidate traffic contract

## Packaged entry point

After independently checking the Release ZIP digest and the source-manifest digest against values from outside the stage, materialize the protected stage and dot-source `tools/network-lab/windows_idle_preflight_target_operator.ps1`. Invoke `Invoke-CvrIdlePreflightTargetAcceptance` with the protected Capture, Plan and Preflight receipt paths; the externally pinned stage root, manifest digest and plan digest; the explicit target and candidate pins; approved probe names; and both required callback scriptblocks. Accept only a returned `status = 'PASS'`. Keep those caller inputs and callback code in the protected local operation package.

The packaged idle target transaction requires both a `CandidateTrafficScript` and a `RecoveryVerificationScript`. Candidate traffic runs only after the pinned candidate is installed and before rollback; recovery verification runs after restoring the pinned 2.5.8 preimages and before the final idle-state reset. A missing callback, exception, incomplete receipt, false recovery result, or failed probe prevents PASS and starts or reports the existing guarded rollback.

The callback receives only a snapshot request with a fresh challenge, the exact candidate core SHA256, the distinct Program Files and service core paths, the candidate GUI and service executable SHA256 pins, and the required probe names. It cannot change the snapshot used by the verifier. It must exercise every requested probe against the running candidate, verify the responding service-owned core process and executable identity, then return exactly one PASS record per requested probe:

```powershell
[PSCustomObject]@{
    schemaVersion = 1
    status = 'PASS'
    challenge = $request.challenge
    candidateCoreSha256 = $request.candidateCoreSha256
    candidateGuiSha256 = $request.candidateGuiSha256
    candidateServiceExeSha256 = $request.candidateServiceExeSha256
    probes = @(
        [PSCustomObject]@{
            protocol = 'dns' # one entry for each requested probe
            passed = [bool]$true
            observedAtUtcMs = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
            processId = [int]$verifiedCorePid
            coreSha256 = $request.candidateCoreSha256
        }
    )
}
```

Every probe must report its UTC observation time as Unix milliseconds inside the callback interval, a positive PID, and the pinned candidate SHA. All probes must identify the same live service-owned core. Do not turn a failed or unavailable probe into PASS. The returned verification record must also echo the exact candidate GUI and service executable SHA-256 pins. The operator checks those along with the core SHA, challenge, probe names, process identity and observation interval. Keep endpoint, profile, and credential data private.

The public Windows CI callback proves synthetic loopback DNS over UDP and HTTP over TUN on the source-built candidate. It does not claim HTTPS, corporate endpoints, user profiles, or production connectivity.


The public operator validates the callback result and its binding, not the callback code's provenance. Supply reviewed target-local callbacks, keep them within the protected operational package, and do not use a callback that fabricates a PASS record. The Windows CI callback is restricted to disposable GitHub Actions runners; it does not serve as a userVM callback.


The required recovery callback receives the install directory, both restored 2.5.8 core SHA-256 values, and the protected service-core preimage path. It must perform the approved recovery acceptance against the restored candidate and return the literal Boolean `$true`; missing callbacks, thrown errors, or any other return value make restore verification fail. The operator runs it after byte/ACL preimages are restored and before the final idle reset.
