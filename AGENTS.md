# Working on STCVRC

STCVRC is a temporary, minimal downstream core for stock Clash Verge Rev (CVR), not a separate product. Maintain only required functionality missing upstream. When CVR's shipped core satisfies the required scenarios, migrate to it and stop downstream development. Keep the stock UI, service, installer and updater.

## Before changing anything
- Read [README](README.md), applicable existing issue/PR and [network-lab guidance](tools/network-lab/README.md). Recheck current branches, heads and overlapping work; continue the existing task rather than duplicate it.
- State the required user scenario, verified upstream gap and smallest change. Identify upstream version/source, removal or migration condition, in-scope work and non-goals. Do not add speculative features, a GUI fork or opportunistic refactoring.
- For ambiguous or multi-stage work, record a short plan and observable acceptance criteria before implementation. Stop and ask when the required behavior, authority or upstream boundary is unresolved.

## Implement and verify
- Keep one reviewable purpose per PR. Add a regression that fails for the intended behavioral reason, then implement the minimum fix. Setup/import/compile failures are not behavioral RED evidence.
- Include applicable negative and boundary cases. Do not weaken assertions or increase timeouts merely to make a run green.
- Bind evidence to exact harness/fixture SHA, tested core source SHA, binary SHA-256 (when built), toolchain/platform and scenario. Re-run affected checks after the last change; a green workflow may have tested a different pinned core.
- Report PASS, FAIL, UNRUN, BLOCKED and INVALID separately. Missing/malformed evidence is INVALID, never PASS or a product failure. Preserve meaningful failures and explain retries.
- Linux labs, cross-builds, fixture tests and source review do not establish native Windows service/TUN/DNS, long-session, corporate-auth or user acceptance. State untested boundaries explicitly.

## Review and handoff
- Follow the [release process](docs/RELEASING.md); a passing CI job or draft release alone does not authorize publication or deployment.
- Use checkable DoD: criterion → verification method → expected observation → evidence link. Link existing acceptance and license work instead of opening parallel tasks.
- Separate implemented, tested, merged, published, accepted and deployed. Use `Refs` while acceptance gates remain; do not close an issue solely because a PR merged.
- Before handoff re-read actual PR head/status/checks. Maintain one current summary and link historical evidence rather than append conflicting “final” sections.
- No secrets, private profiles or operational data in public issues/logs. No paid runners, settings changes, release, deployment or automatic merge without explicit authorization. Existing bounded free-runner policy is not permission for native rollout.

## Issue handoff checklist
Required scenario and upstream gap; observed vs expected; evidence and exact revisions; scope/non-goals; relevant invariants; dependencies/existing work; DoD and negative tests; stop conditions; patch retirement/migration condition. Mark hypotheses and unverified claims explicitly. Prefer a small executable task over a broad product roadmap.
