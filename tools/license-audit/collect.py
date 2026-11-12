"""Collect exact build outputs and tool reports for distribution notices."""

from pathlib import Path

from generate_notices import AuditIncomplete


def verify_artifact(build, output_dir, name, target):
    """Return the named artifact record after checking its declared target."""
    artifacts = build.get("artifacts")
    if not isinstance(artifacts, list):
        raise AuditIncomplete("missing build artifacts")
    matches = [item for item in artifacts if isinstance(item, dict) and item.get("name") == name]
    if len(matches) != 1 or matches[0].get("target") != target:
        raise AuditIncomplete(f"missing or ambiguous build artifact: {name}")
    artifact_path = Path(output_dir) / name
    if not artifact_path.is_file():
        raise AuditIncomplete(f"build artifact is missing: {name}")
    return matches[0]
