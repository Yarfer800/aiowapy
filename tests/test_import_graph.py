"""Automatic check of the dependency rules from spec section 4."""

from __future__ import annotations

import ast
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src" / "wapy"

# Key is a top-level package; value holds prefixes it must not import.
LAYER_RULES: dict[str, set[str]] = {
    "protocol": {
        "wapy.events",
        "wapy.router",
        "wapy.store",
        "wapy.client",
        "wapy.stream",
    },
    "crypto": {
        "wapy.models",
        "wapy.events",
        "wapy.router",
        "wapy.store",
        "wapy.client",
        "wapy.stream",
    },
    "models": {
        "wapy.protocol",
        "wapy.crypto",
        "wapy.store",
        "wapy.client",
        "wapy.router",
        "wapy.stream",
        "wapy.events",
    },
    "router": {"wapy.protocol", "wapy.crypto", "wapy.store", "wapy.client"},
    "store": {"wapy.client", "wapy.router", "wapy.events", "wapy.models", "wapy.stream"},
    # events carry protocol-level types (MediaInfo, Node) by design.
    "events": {"wapy.crypto", "wapy.store", "wapy.client", "wapy.router"},
}


def imported_modules(path: Path) -> set[str]:
    """Absolute module names imported by the file."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module)
            names.update(f"{node.module}.{alias.name}" for alias in node.names)
    return names


def is_violation(module: str, forbidden: str) -> bool:
    return module == forbidden or module.startswith(f"{forbidden}.")


def test_layers_do_not_depend_upwards() -> None:
    violations: list[str] = []
    for path in sorted(SRC.rglob("*.py")):
        top = path.relative_to(SRC).parts[0].removesuffix(".py")
        forbidden = LAYER_RULES.get(top, set())
        for module in sorted(imported_modules(path)):
            for banned in forbidden:
                if is_violation(module, banned):
                    violations.append(f"{path.relative_to(SRC)} -> {module}")
    assert violations == [], "Layer rules violated:\n" + "\n".join(violations)
