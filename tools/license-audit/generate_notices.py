"""Deterministic renderer for reviewed, normalized third-party license inventory."""


class AuditIncomplete(ValueError):
    """The inventory cannot yet support a complete notice/source package."""


def generate_notices(inventory):
    """Return (THIRD-PARTY-NOTICES.txt, source manifest) for an inventory."""
    # Callable surface for the fixture-driven RED stage; behavior is specified
    # by tests before the generator is implemented.
    return "", {"schema_version": 1, "scope": {}, "components": []}
