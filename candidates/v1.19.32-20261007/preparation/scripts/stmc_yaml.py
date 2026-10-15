"""YAML helpers matching the YAML 1.2 scalar semantics used by Mihomo."""

from __future__ import annotations

import copy
import re
from typing import Any

import yaml


class Yaml12SafeLoader(yaml.SafeLoader):
    pass


Yaml12SafeLoader.yaml_implicit_resolvers = copy.deepcopy(yaml.SafeLoader.yaml_implicit_resolvers)
for first_character, resolvers in list(Yaml12SafeLoader.yaml_implicit_resolvers.items()):
    Yaml12SafeLoader.yaml_implicit_resolvers[first_character] = [
        resolver for resolver in resolvers if resolver[0] != "tag:yaml.org,2002:bool"
    ]
Yaml12SafeLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool",
    re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"),
    list("tTfF"),
)


def load(value: bytes | str) -> Any:
    return yaml.load(value, Loader=Yaml12SafeLoader)


def dump(value: Any) -> bytes:
    return yaml.safe_dump(
        value,
        allow_unicode=False,
        default_flow_style=False,
        sort_keys=False,
        width=120,
    ).encode("utf-8")
