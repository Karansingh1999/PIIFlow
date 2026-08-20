from __future__ import annotations

import ast


def expression_to_str(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:
        return node.__class__.__name__


def qualified_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = qualified_name(node.value)
        if base is None:
            return node.attr
        return f"{base}.{node.attr}"
    return None


def constant_str(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def source_expr_base(node: ast.AST) -> str | None:
    if isinstance(node, ast.Attribute):
        return qualified_name(node)
    return None


def call_matches(pattern: str, call_name: str) -> bool:
    if pattern.startswith("*."):
        return call_name.endswith(pattern[1:])
    if pattern.startswith("*"):
        return call_name.endswith(pattern[1:])
    return pattern == call_name


def node_line(node: ast.AST) -> int:
    return getattr(node, "lineno", 1)


def node_col(node: ast.AST) -> int:
    return getattr(node, "col_offset", 0)
