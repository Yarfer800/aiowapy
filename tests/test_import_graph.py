"""Automatic check of the dependency rules from spec section 4."""

from __future__ import annotations

import ast
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src" / "aiowapy"

# Key is a top-level package; value holds prefixes it must not import.
LAYER_RULES: dict[str, set[str]] = {
    "protocol": {
        "aiowapy.events",
        "aiowapy.router",
        "aiowapy.store",
        "aiowapy.client",
        "aiowapy.stream",
    },
    "crypto": {
        "aiowapy.models",
        "aiowapy.events",
        "aiowapy.router",
        "aiowapy.store",
        "aiowapy.client",
        "aiowapy.stream",
    },
    "models": {
        "aiowapy.protocol",
        "aiowapy.crypto",
        "aiowapy.store",
        "aiowapy.client",
        "aiowapy.router",
        "aiowapy.stream",
        "aiowapy.events",
    },
    "router": {"aiowapy.protocol", "aiowapy.crypto", "aiowapy.store", "aiowapy.client"},
    "store": {
        "aiowapy.client",
        "aiowapy.router",
        "aiowapy.events",
        "aiowapy.models",
        "aiowapy.stream",
    },
    # events carry protocol-level types (MediaInfo, Node) by design.
    "events": {"aiowapy.crypto", "aiowapy.store", "aiowapy.client", "aiowapy.router"},
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
