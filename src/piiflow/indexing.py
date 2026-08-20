from __future__ import annotations

import ast
from pathlib import Path
from typing import Literal

from piiflow.models import FunctionInfo


class FunctionCollector(ast.NodeVisitor):
    def __init__(self, file: Path, module: str) -> None:
        self.file = file
        self.module = module
        self.scope: list[str] = []
        self.class_stack: list[str] = []
        self.functions: list[FunctionInfo] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.scope.append(node.name)
        self.class_stack.append(node.name)
        self.generic_visit(node)
        self.class_stack.pop()
        self.scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        qualified = ".".join([*self.scope, node.name])
        params = [arg.arg for arg in node.args.posonlyargs + node.args.args + node.args.kwonlyargs]
        if node.args.vararg is not None:
            params.append(node.args.vararg.arg)
        if node.args.kwarg is not None:
            params.append(node.args.kwarg.arg)
        class_name = self.class_stack[-1] if self.class_stack else None
        self.functions.append(
            FunctionInfo(
                name=node.name,
                module=self.module,
                identity=f"{self.module}:{qualified}",
                qualified_name=qualified,
                class_name=class_name,
                method_kind=_method_kind(node) if class_name else "function",
                file=self.file,
                node=node,
                params=params,
            )
        )
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()


def collect_functions(file: Path, module: str, tree: ast.AST) -> list[FunctionInfo]:
    collector = FunctionCollector(file, module)
    collector.visit(tree)
    return collector.functions


def collect_import_aliases(tree: ast.AST) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name.split(".")[0]] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return aliases


def _method_kind(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> Literal["instance", "staticmethod", "classmethod"]:
    for decorator in node.decorator_list:
        if isinstance(decorator, ast.Name) and decorator.id == "staticmethod":
            return "staticmethod"
        if isinstance(decorator, ast.Name) and decorator.id == "classmethod":
            return "classmethod"
        if isinstance(decorator, ast.Attribute) and decorator.attr == "staticmethod":
            return "staticmethod"
        if isinstance(decorator, ast.Attribute) and decorator.attr == "classmethod":
            return "classmethod"
    return "instance"
