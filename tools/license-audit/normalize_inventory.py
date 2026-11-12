"""Normalize exact Go and Rust tool output into the notice renderer contract."""

from __future__ import annotations


def normalize_inventory(bundle):
    """Return a normalized inventory from an evidence bundle.

    This callable scaffold keeps the fixture test stage valid while the behavior
    is specified. It intentionally returns no package claims.
    """
    return {
        "schema_version": 1,
        "scope": bundle.get("build", {}),
        "components": [],
        "build_tools": bundle.get("build_tools", []),
        "required_components": [],
    }
