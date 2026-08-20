from __future__ import annotations

import ast
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from piiflow.ast_utils import (
    call_matches,
    constant_str,
    expression_to_str,
    node_line,
    qualified_name,
    source_expr_base,
)
from piiflow.fingerprints import stable_fingerprint
from piiflow.models import (
    AnalysisOptions,
    Finding,
    FunctionInfo,
    Location,
    RuleConfig,
    SanitizerEvidence,
    Severity,
    SinkRef,
    SourceRef,
)
from piiflow.sinks import matching_sink
from piiflow.sources import is_request_collection, sensitive_category

MAX_PATH_STEPS = 8
MAX_CALL_DEPTH = 8

REMEDIATION = (
    "Apply an approved sanitizer before the sink, remove unnecessary sensitive fields, "
    "use an internal/local model if policy allows, or update the rule configuration only "
    "when this flow is intentionally permitted."
)


@dataclass(frozen=True)
class Taint:
    category: str
    source: SourceRef
    path: tuple[str, ...]
    sanitized: bool = False
    sanitizers: tuple[SanitizerEvidence, ...] = ()

    def with_step(self, step: str) -> Taint:
        if not step or (self.path and self.path[-1] == step):
            return self
        return Taint(
            category=self.category,
            source=self.source,
            path=(*self.path, step)[-MAX_PATH_STEPS:],
            sanitized=self.sanitized,
            sanitizers=self.sanitizers,
        )

    def sanitized_by(self, step: str, sanitizer: SanitizerEvidence) -> Taint:
        stepped = self.with_step(step)
        sanitizers = (*stepped.sanitizers, sanitizer)
        return Taint(
            category=stepped.category,
            source=stepped.source,
            path=stepped.path,
            sanitized=True,
            sanitizers=sanitizers,
        )


@dataclass
class AbstractValue:
    direct: list[Taint] = field(default_factory=list)
    fields: dict[str, AbstractValue] = field(default_factory=dict)
    wildcard_field: list[Taint] = field(default_factory=list)
    attrs: dict[str, AbstractValue] = field(default_factory=dict)
    wildcard_attr: list[Taint] = field(default_factory=list)
    source_collection: str | None = None
    object_id: int | None = None

    @classmethod
    def tainted(cls, taint: Taint) -> AbstractValue:
        return cls(direct=[taint])

    @classmethod
    def source(cls, collection: str) -> AbstractValue:
        return cls(source_collection=collection)

    def copy(self) -> AbstractValue:
        return AbstractValue(
            direct=list(self.direct),
            fields={key: value.copy() for key, value in self.fields.items()},
            wildcard_field=list(self.wildcard_field),
            attrs={key: value.copy() for key, value in self.attrs.items()},
            wildcard_attr=list(self.wildcard_attr),
            source_collection=self.source_collection,
            object_id=self.object_id,
        )

    def all_taints(self, *, include_structured: bool = True) -> list[Taint]:
        groups = [self.direct, self.wildcard_field, self.wildcard_attr]
        if include_structured:
            groups.extend(value.all_taints() for value in self.fields.values())
            groups.extend(value.all_taints() for value in self.attrs.values())
        return merge_taints(*groups)

    def with_step(self, step: str) -> AbstractValue:
        copied = self.copy()
        copied.direct = [taint.with_step(step) for taint in copied.direct]
        copied.wildcard_field = [taint.with_step(step) for taint in copied.wildcard_field]
        copied.wildcard_attr = [taint.with_step(step) for taint in copied.wildcard_attr]
        copied.fields = {key: value.with_step(step) for key, value in copied.fields.items()}
        copied.attrs = {key: value.with_step(step) for key, value in copied.attrs.items()}
        return copied

    def sanitized_by(self, step: str, sanitizer: SanitizerEvidence) -> AbstractValue:
        return AbstractValue(
            direct=[taint.sanitized_by(step, sanitizer) for taint in self.all_taints()],
            object_id=None,
        )


def empty_value() -> AbstractValue:
    return AbstractValue()


def value_from_taints(taints: list[Taint]) -> AbstractValue:
    return AbstractValue(direct=merge_taints(taints))


def constant_key(node: ast.AST | None) -> str | None:
    if node is None:
        return None
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return str(node.value)
    return constant_str(node)


SanitizerKey = tuple[tuple[str, str, int, int], ...]
TaintKey = tuple[str, str, int, str, bool, tuple[str, ...], SanitizerKey]


def sanitizer_key(sanitizers: tuple[SanitizerEvidence, ...]) -> SanitizerKey:
    return tuple(
        (item.name, item.location.file, item.location.line, item.location.column)
        for item in sanitizers
    )


def merge_taints(*groups: list[Taint]) -> list[Taint]:
    merged: dict[TaintKey, Taint] = {}
    for group in groups:
        for taint in group:
            key = (
                taint.category,
                taint.source.file,
                taint.source.line,
                taint.source.expression,
                taint.sanitized,
                taint.path,
                sanitizer_key(taint.sanitizers),
            )
            merged[key] = taint
    return list(merged.values())


def merge_values(*values: AbstractValue, options: AnalysisOptions) -> AbstractValue:
    direct = merge_taints(*(value.direct for value in values))
    source_collections = {value.source_collection for value in values if value.source_collection}
    result = AbstractValue(
        direct=direct,
        wildcard_field=merge_taints(*(value.wildcard_field for value in values)),
        wildcard_attr=merge_taints(*(value.wildcard_attr for value in values)),
        source_collection=next(iter(source_collections)) if len(source_collections) == 1 else None,
    )
    if not options.structured_state:
        result.direct = merge_taints(*(value.all_taints() for value in values))
        return result

    for key in sorted({key for value in values for key in value.fields}):
        result.fields[key] = merge_values(
            *(value.fields.get(key, empty_value()) for value in values),
            options=options,
        )
    for key in sorted({key for value in values for key in value.attrs}):
        result.attrs[key] = merge_values(
            *(value.attrs.get(key, empty_value()) for value in values),
            options=options,
        )
    collapse_if_needed(result, options)
    object_ids = {value.object_id for value in values if value.object_id is not None}
    if len(object_ids) == 1:
        result.object_id = next(iter(object_ids))
    return result


def collapse_if_needed(value: AbstractValue, options: AnalysisOptions) -> None:
    if len(value.fields) > options.max_known_fields_per_object:
        value.wildcard_field = merge_taints(
            value.wildcard_field,
            *(field_value.all_taints() for field_value in value.fields.values()),
        )
        value.fields = {}
    if len(value.attrs) > options.max_known_fields_per_object:
        value.wildcard_attr = merge_taints(
            value.wildcard_attr,
            *(attr_value.all_taints() for attr_value in value.attrs.values()),
        )
        value.attrs = {}


def severity_for(category: str, destination: str, sanitized: bool) -> Severity:
    if sanitized:
        return Severity.INFO
    if destination == "configurable_llm":
        return Severity.MEDIUM
    if category in {"GOVERNMENT_ID", "FINANCIAL", "MEDICAL"}:
        return Severity.CRITICAL
    return Severity.HIGH


def finding_message(category: str, sanitized: bool) -> str:
    readable = category.lower().replace("_", " ")
    if sanitized:
        return f"Sanitized {readable} data reaches an external LLM."
    return f"{readable.capitalize()} data may reach an external LLM."


class PropagationAnalyzer:
    def __init__(
        self,
        *,
        config: RuleConfig,
        root: Path,
        functions: list[FunctionInfo],
        imports_by_file: dict[Path, dict[str, str]],
        options: AnalysisOptions | None = None,
    ) -> None:
        self.config = config
        self.root = root
        self.functions = functions
        self.imports_by_file = imports_by_file
        self.options = options or AnalysisOptions()
        self.functions_by_name: dict[str, list[FunctionInfo]] = defaultdict(list)
        self.functions_by_module_name: dict[tuple[str, str], list[FunctionInfo]] = defaultdict(list)
        self.functions_by_module_qualified: dict[tuple[str, str], list[FunctionInfo]] = defaultdict(
            list
        )
        for function in functions:
            self.functions_by_name[function.name].append(function)
            self.functions_by_module_name[(function.module, function.name)].append(function)
            self.functions_by_module_qualified[(function.module, function.qualified_name)].append(
                function
            )
        self.findings: list[Finding] = []
        self.heap: dict[int, AbstractValue] = {}
        self._next_object_id = 1

    def analyze_module(self, file: Path, tree: ast.AST) -> list[Finding]:
        if isinstance(tree, ast.Module):
            self._analyze_statements(file, tree.body, {}, (), 0)
        for function in sorted(self.functions, key=lambda item: item.identity):
            if function.file == file:
                self._analyze_function(file, function, {}, (), 0)
        return self.findings

    def _relative_file(self, file: Path) -> str:
        try:
            return file.relative_to(self.root).as_posix()
        except ValueError:
            return file.name

    def _analyze_function(
        self,
        file: Path,
        function: FunctionInfo,
        arguments: dict[str, AbstractValue],
        stack: tuple[str, ...],
        depth: int,
    ) -> AbstractValue:
        if depth > MAX_CALL_DEPTH or function.identity in stack:
            return merge_values(*arguments.values(), options=self.options)
        env = {name: arguments.get(name, empty_value()).copy() for name in function.params}
        return self._analyze_statements(
            file,
            function.node.body,
            env,
            (*stack, function.identity),
            depth + 1,
        )

    def _analyze_statements(
        self,
        file: Path,
        statements: list[ast.stmt],
        env: dict[str, AbstractValue],
        stack: tuple[str, ...],
        depth: int,
    ) -> AbstractValue:
        returns = empty_value()
        for statement in statements:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if isinstance(statement, ast.Assign):
                self._handle_assign(file, statement.targets, statement.value, env, stack, depth)
            elif isinstance(statement, ast.AnnAssign):
                value = self._eval_expr(file, statement.value, env, stack, depth)
                self._assign_target(file, statement.target, value, env, stack, depth)
            elif isinstance(statement, ast.AugAssign):
                value = merge_values(
                    self._eval_expr(file, statement.target, env, stack, depth),
                    self._eval_expr(file, statement.value, env, stack, depth),
                    options=self.options,
                )
                self._assign_target(file, statement.target, value, env, stack, depth)
            elif isinstance(statement, ast.Return):
                if statement.value is not None:
                    returns = merge_values(
                        returns,
                        self._eval_expr(file, statement.value, env, stack, depth),
                        options=self.options,
                    )
            elif isinstance(statement, ast.Expr):
                self._eval_expr(file, statement.value, env, stack, depth)
            elif isinstance(statement, ast.If):
                returns = self._handle_if(file, statement, env, stack, depth, returns)
            elif isinstance(statement, ast.AsyncFor):
                self._eval_expr(file, statement.iter, env, stack, depth)
                returns = merge_values(
                    returns,
                    self._analyze_statements(file, statement.body, env, stack, depth),
                    self._analyze_statements(file, statement.orelse, env, stack, depth),
                    options=self.options,
                )
            elif isinstance(statement, ast.AsyncWith):
                for item in statement.items:
                    self._eval_expr(file, item.context_expr, env, stack, depth)
                returns = merge_values(
                    returns,
                    self._analyze_statements(file, statement.body, env, stack, depth),
                    options=self.options,
                )
            elif isinstance(statement, (ast.For, ast.While)):
                for child in ast.iter_child_nodes(statement):
                    if isinstance(child, ast.expr):
                        self._eval_expr(file, child, env, stack, depth)
                before_env = self._clone_env(env)
                self._analyze_statements(file, statement.body, env, stack, depth)
                self._merge_env_into(env, before_env, env)
            elif isinstance(statement, ast.With):
                for item in statement.items:
                    self._eval_expr(file, item.context_expr, env, stack, depth)
                returns = merge_values(
                    returns,
                    self._analyze_statements(file, statement.body, env, stack, depth),
                    options=self.options,
                )
            elif isinstance(statement, ast.Try):
                returns = self._handle_try(file, statement, env, stack, depth, returns)
            else:
                for child in ast.walk(statement):
                    if isinstance(child, ast.Call):
                        self._eval_expr(file, child, env, stack, depth)
        return returns

    def _handle_if(
        self,
        file: Path,
        statement: ast.If,
        env: dict[str, AbstractValue],
        stack: tuple[str, ...],
        depth: int,
        returns: AbstractValue,
    ) -> AbstractValue:
        self._eval_expr(file, statement.test, env, stack, depth)
        original_heap = self._clone_heap(self.heap)
        body_env = self._clone_env(env)
        self.heap = self._clone_heap(original_heap)
        body_returns = self._analyze_statements(file, statement.body, body_env, stack, depth)
        body_heap = self._clone_heap(self.heap)
        else_env = self._clone_env(env)
        self.heap = self._clone_heap(original_heap)
        else_returns = self._analyze_statements(file, statement.orelse, else_env, stack, depth)
        else_heap = self._clone_heap(self.heap)
        self._merge_env_into(env, body_env, else_env)
        self.heap = self._merge_heaps(body_heap, else_heap)
        return merge_values(returns, body_returns, else_returns, options=self.options)

    def _handle_try(
        self,
        file: Path,
        statement: ast.Try,
        env: dict[str, AbstractValue],
        stack: tuple[str, ...],
        depth: int,
        returns: AbstractValue,
    ) -> AbstractValue:
        for branch in (statement.body, statement.orelse, statement.finalbody):
            returns = merge_values(
                returns,
                self._analyze_statements(file, branch, env, stack, depth),
                options=self.options,
            )
        for handler in statement.handlers:
            handler_env = self._clone_env(env)
            handler_heap = self._clone_heap(self.heap)
            returns = merge_values(
                returns,
                self._analyze_statements(file, handler.body, handler_env, stack, depth),
                options=self.options,
            )
            self.heap = handler_heap
        return returns

    def _handle_assign(
        self,
        file: Path,
        targets: list[ast.expr],
        value: ast.expr,
        env: dict[str, AbstractValue],
        stack: tuple[str, ...],
        depth: int,
    ) -> None:
        if (
            len(targets) == 1
            and isinstance(targets[0], (ast.Tuple, ast.List))
            and isinstance(value, (ast.Tuple, ast.List))
            and len(targets[0].elts) == len(value.elts)
        ):
            for target, element in zip(targets[0].elts, value.elts, strict=True):
                self._assign_target(
                    file,
                    target,
                    self._eval_expr(file, element, env, stack, depth),
                    env,
                    stack,
                    depth,
                )
            return

        value_result = self._eval_expr(file, value, env, stack, depth)
        for target in targets:
            target_value = merge_values(
                value_result,
                self._source_from_sensitive_assignment(file, target, value),
                options=self.options,
            )
            self._assign_target(file, target, target_value, env, stack, depth)

    def _assign_target(
        self,
        file: Path,
        target: ast.expr,
        value: AbstractValue,
        env: dict[str, AbstractValue],
        stack: tuple[str, ...],
        depth: int,
    ) -> None:
        if isinstance(target, ast.Name):
            assigned = value.with_step(target.id)
            if assigned.object_id is not None:
                self.heap[assigned.object_id] = assigned.copy()
            env[target.id] = assigned
            return
        if isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self._assign_target(file, element, value, env, stack, depth)
            return
        if not self.options.structured_state:
            return
        if isinstance(target, ast.Subscript):
            field_container = self._eval_expr(file, target.value, env, stack, depth)
            key = constant_key(target.slice)
            self._write_field(field_container, key, value)
            return
        if isinstance(target, ast.Attribute):
            attr_container, attr = self._attribute_container(target, file, env, stack, depth)
            if attr_container is not None:
                self._write_attr(attr_container, attr, value)

    def _eval_expr(
        self,
        file: Path,
        node: ast.AST | None,
        env: dict[str, AbstractValue],
        stack: tuple[str, ...],
        depth: int,
    ) -> AbstractValue:
        if node is None:
            return empty_value()
        if isinstance(node, ast.Name):
            if node.id not in env:
                self._ensure_named_object(env, node.id)
            elif self._should_promote_to_object(env[node.id]):
                env[node.id] = self._new_object(env[node.id])
            return self._deref(env[node.id]).copy()
        if isinstance(node, ast.Subscript):
            source_taint = self._source_from_subscript(file, node, env)
            if source_taint.direct:
                return source_taint
            field_container = self._eval_expr(file, node.value, env, stack, depth)
            key = constant_key(node.slice)
            return self._read_field(field_container, key).with_step(expression_to_str(node))
        if isinstance(node, ast.Attribute):
            source_collection = self._source_collection_name(node)
            if source_collection is not None:
                return AbstractValue.source(source_collection)
            attr_container, attr = self._attribute_container(node, file, env, stack, depth)
            if attr_container is not None:
                return self._read_attr(attr_container, attr).with_step(expression_to_str(node))
            return self._eval_expr(file, node.value, env, stack, depth)
        if isinstance(node, ast.JoinedStr):
            return self._children_value(file, node, env, stack, depth).with_step(
                expression_to_str(node)
            )
        if isinstance(node, ast.BinOp):
            return merge_values(
                self._eval_expr(file, node.left, env, stack, depth),
                self._eval_expr(file, node.right, env, stack, depth),
                options=self.options,
            ).with_step(expression_to_str(node))
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return self._container_value(file, node.elts, env, stack, depth)
        if isinstance(node, ast.Dict):
            return self._dict_value(file, node, env, stack, depth)
        if isinstance(node, ast.IfExp):
            return merge_values(
                self._eval_expr(file, node.body, env, stack, depth),
                self._eval_expr(file, node.orelse, env, stack, depth),
                options=self.options,
            )
        if isinstance(node, ast.Call):
            return self._eval_call(file, node, env, stack, depth)
        if isinstance(node, ast.Await):
            return self._children_value(file, node, env, stack, depth)
        return self._children_value(file, node, env, stack, depth)

    def _children_value(
        self,
        file: Path,
        node: ast.AST,
        env: dict[str, AbstractValue],
        stack: tuple[str, ...],
        depth: int,
    ) -> AbstractValue:
        return merge_values(
            *(
                self._eval_expr(file, child, env, stack, depth)
                for child in ast.iter_child_nodes(node)
                if isinstance(child, ast.expr)
            ),
            options=self.options,
        )

    def _container_value(
        self,
        file: Path,
        nodes: list[ast.expr],
        env: dict[str, AbstractValue],
        stack: tuple[str, ...],
        depth: int,
    ) -> AbstractValue:
        values = [self._eval_expr(file, node, env, stack, depth) for node in nodes]
        value = merge_values(*values, options=self.options)
        if not self.options.structured_state:
            return value
        value = AbstractValue(fields={str(index): child for index, child in enumerate(values)})
        collapse_if_needed(value, self.options)
        return self._new_object(value)

    def _dict_value(
        self,
        file: Path,
        node: ast.Dict,
        env: dict[str, AbstractValue],
        stack: tuple[str, ...],
        depth: int,
    ) -> AbstractValue:
        if not self.options.structured_state:
            return self._children_value(file, node, env, stack, depth)
        value = AbstractValue()
        for key_node, value_node in zip(node.keys, node.values, strict=True):
            child_value = self._eval_expr(file, value_node, env, stack, depth)
            key = constant_key(key_node) if key_node is not None else None
            if key is None:
                value.wildcard_field = merge_taints(value.wildcard_field, child_value.all_taints())
            else:
                value.fields[key] = child_value
        collapse_if_needed(value, self.options)
        return self._new_object(value)

    def _source_from_subscript(
        self,
        file: Path,
        node: ast.Subscript,
        env: dict[str, AbstractValue],
    ) -> AbstractValue:
        base = source_expr_base(node.value)
        if base is None and self.options.structured_state and isinstance(node.value, ast.Name):
            base = env.get(node.value.id, empty_value()).source_collection
        if base is None or not is_request_collection(base, self.config):
            return empty_value()
        key = constant_str(node.slice)
        if key is None:
            return empty_value()
        category = sensitive_category(key, self.config)
        if category is None:
            return empty_value()
        expression = expression_to_str(node)
        source = SourceRef(
            file=self._relative_file(file),
            line=node_line(node),
            expression=expression,
        )
        return AbstractValue.tainted(Taint(category=category, source=source, path=(expression,)))

    def _source_from_sensitive_assignment(
        self,
        file: Path,
        target: ast.expr,
        value: ast.expr,
    ) -> AbstractValue:
        if not isinstance(target, ast.Name):
            return empty_value()
        category = sensitive_category(target.id, self.config)
        if category is None:
            return empty_value()
        base: str | None = None
        if isinstance(value, ast.Attribute):
            base = source_expr_base(value)
        elif isinstance(value, ast.Subscript):
            base = source_expr_base(value.value)
        elif (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Attribute)
            and value.func.attr == "get"
        ):
            base = source_expr_base(value.func.value)
        if base is None or not is_request_collection(base, self.config):
            return empty_value()
        expression = expression_to_str(value)
        source = SourceRef(
            file=self._relative_file(file),
            line=node_line(value),
            expression=expression,
        )
        return AbstractValue.tainted(Taint(category=category, source=source, path=(expression,)))

    def _source_from_get_call(
        self, file: Path, node: ast.Call, env: dict[str, AbstractValue]
    ) -> AbstractValue:
        if not isinstance(node.func, ast.Attribute) or node.func.attr != "get":
            return empty_value()
        base = source_expr_base(node.func.value)
        if base is None and self.options.structured_state and isinstance(node.func.value, ast.Name):
            base = env.get(node.func.value.id, empty_value()).source_collection
        if base is None or not is_request_collection(base, self.config):
            return empty_value()
        if not node.args:
            return empty_value()
        key = constant_str(node.args[0])
        if key is None:
            return empty_value()
        category = sensitive_category(key, self.config)
        if category is None:
            return empty_value()
        expression = expression_to_str(node)
        source = SourceRef(
            file=self._relative_file(file),
            line=node_line(node),
            expression=expression,
        )
        return AbstractValue.tainted(Taint(category=category, source=source, path=(expression,)))

    def _eval_call(
        self,
        file: Path,
        node: ast.Call,
        env: dict[str, AbstractValue],
        stack: tuple[str, ...],
        depth: int,
    ) -> AbstractValue:
        call_name = qualified_name(node.func) or expression_to_str(node.func)
        call_text = expression_to_str(node)
        source_value = self._source_from_get_call(file, node, env)

        receiver_value = empty_value()
        if isinstance(node.func, ast.Attribute):
            receiver_value = self._eval_expr(file, node.func.value, env, stack, depth)
        arg_values = [self._eval_expr(file, arg, env, stack, depth) for arg in node.args]
        kw_values = {
            keyword.arg: self._eval_expr(file, keyword.value, env, stack, depth)
            for keyword in node.keywords
            if keyword.arg is not None
        }
        flat_value = merge_values(
            receiver_value,
            *arg_values,
            *kw_values.values(),
            source_value,
            options=self.options,
        )

        self._record_sink(file, node, call_name, arg_values, kw_values)

        getattr_value = self._eval_getattr_call(file, node, arg_values)
        if getattr_value is not None:
            return getattr_value.with_step(call_text)

        sanitizer_name = self._matched_sanitizer(call_name)
        if sanitizer_name is not None:
            sanitizer = SanitizerEvidence(
                name=sanitizer_name,
                location=Location(file=self._relative_file(file), line=node_line(node)),
            )
            return flat_value.sanitized_by(call_text, sanitizer)

        function = self._resolve_function(file=file, node=node, call_name=call_name)
        if function is not None:
            bound = self._bind_arguments(function, receiver_value, arg_values, kw_values)
            returns = self._analyze_function(function.file, function, bound, stack, depth)
            return returns.with_step(call_text)

        if flat_value.all_taints() or flat_value.source_collection:
            result = value_from_taints(flat_value.all_taints()).with_step(call_text)
            result.source_collection = flat_value.source_collection
            return result
        return empty_value()

    def _eval_getattr_call(
        self,
        file: Path,
        node: ast.Call,
        arg_values: list[AbstractValue],
    ) -> AbstractValue | None:
        del file
        call_name = qualified_name(node.func)
        if call_name != "getattr" or not arg_values:
            return None
        key = constant_str(node.args[1]) if len(node.args) > 1 else None
        if key is not None:
            return self._read_attr(arg_values[0], key)
        return value_from_taints(self._deref(arg_values[0]).all_taints())

    def _bind_arguments(
        self,
        function: FunctionInfo,
        receiver_value: AbstractValue,
        arg_values: list[AbstractValue],
        kw_values: dict[str, AbstractValue],
    ) -> dict[str, AbstractValue]:
        bound: dict[str, AbstractValue] = {}
        positional_offset = 0
        if function.method_kind in {"instance", "classmethod"} and function.params:
            bound[function.params[0]] = receiver_value
            positional_offset = 1
        for index, value in enumerate(arg_values):
            param_index = index + positional_offset
            if param_index < len(function.params):
                bound[function.params[param_index]] = value
        for name, value in kw_values.items():
            if name in function.params:
                bound[name] = value
        return bound

    def _record_sink(
        self,
        file: Path,
        node: ast.Call,
        call_name: str,
        arg_values: list[AbstractValue],
        kw_values: dict[str, AbstractValue],
    ) -> None:
        rule = matching_sink(call_name, self.config.sink_patterns)
        if rule is None:
            return
        for argument in rule.arguments:
            value = empty_value()
            argument_name = str(argument)
            if isinstance(argument, int) and argument < len(arg_values):
                value = arg_values[argument]
            elif isinstance(argument, str) and argument in kw_values:
                value = kw_values[argument]
            for taint in self._deref(value).all_taints():
                sink = SinkRef(
                    file=self._relative_file(file),
                    line=node_line(node),
                    call=call_name,
                    argument=argument_name,
                )
                severity = severity_for(taint.category, rule.destination, taint.sanitized)
                finding = Finding(
                    severity=severity,
                    category=taint.category,
                    source=taint.source,
                    sink=sink,
                    path=list(taint.path),
                    sanitized=taint.sanitized,
                    sanitizers=list(taint.sanitizers),
                    message=finding_message(taint.category, taint.sanitized),
                    remediation=REMEDIATION,
                    fingerprint=stable_fingerprint(
                        rule_id="PIIFLOW001",
                        category=taint.category,
                        source=taint.source,
                        sink=sink,
                        sanitized=taint.sanitized,
                    ),
                    provider=rule.provider,
                    trust_zone=rule.trust_zone,
                    observed_sanitizers=sorted({item.name for item in taint.sanitizers}),
                )
                self.findings.append(finding)

    def _read_field(self, container: AbstractValue, key: str | None) -> AbstractValue:
        resolved = self._deref(container)
        if not self.options.structured_state:
            return value_from_taints(resolved.all_taints())
        if key is not None:
            return merge_values(
                resolved.fields.get(key, empty_value()),
                value_from_taints(resolved.wildcard_field),
                options=self.options,
            )
        return value_from_taints(resolved.all_taints())

    def _write_field(
        self,
        container: AbstractValue,
        key: str | None,
        value: AbstractValue,
    ) -> None:
        resolved = self._deref(container)
        if key is None:
            resolved.wildcard_field = merge_taints(resolved.wildcard_field, value.all_taints())
        else:
            resolved.fields[key] = value.copy()
        collapse_if_needed(resolved, self.options)

    def _read_attr(self, container: AbstractValue, attr: str | None) -> AbstractValue:
        resolved = self._deref(container)
        if not self.options.structured_state:
            return value_from_taints(resolved.all_taints())
        if attr is not None:
            return merge_values(
                resolved.attrs.get(attr, empty_value()),
                value_from_taints(resolved.wildcard_attr),
                options=self.options,
            )
        return value_from_taints(resolved.all_taints())

    def _write_attr(
        self,
        container: AbstractValue,
        attr: str | None,
        value: AbstractValue,
    ) -> None:
        resolved = self._deref(container)
        if attr is None:
            resolved.wildcard_attr = merge_taints(resolved.wildcard_attr, value.all_taints())
        else:
            resolved.attrs[attr] = value.copy()
        collapse_if_needed(resolved, self.options)

    def _attribute_container(
        self,
        node: ast.Attribute,
        file: Path,
        env: dict[str, AbstractValue],
        stack: tuple[str, ...],
        depth: int,
    ) -> tuple[AbstractValue | None, str | None]:
        del file, stack, depth
        parts: list[str] = []
        current: ast.AST = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if not isinstance(current, ast.Name):
            return None, None
        parts.reverse()
        if len(parts) > self.options.max_access_path_depth:
            return self._ensure_named_object(env, current.id), None
        container = self._ensure_named_object(env, current.id)
        for attr in parts[:-1]:
            next_value = self._read_attr(container, attr)
            if next_value.object_id is None:
                next_value = self._new_object(next_value)
                self._write_attr(container, attr, next_value)
            container = next_value
        return container, parts[-1]

    def _source_collection_name(self, node: ast.Attribute) -> str | None:
        name = qualified_name(node)
        if name and is_request_collection(name, self.config):
            return name
        return None

    def _new_object(self, value: AbstractValue | None = None) -> AbstractValue:
        source = value.copy() if value is not None else AbstractValue()
        object_id = self._next_object_id
        self._next_object_id += 1
        source.object_id = object_id
        self.heap[object_id] = source
        return source.copy()

    def _ensure_named_object(self, env: dict[str, AbstractValue], name: str) -> AbstractValue:
        if name not in env or self._should_promote_to_object(env[name]):
            env[name] = self._new_object()
        return env[name]

    def _deref(self, value: AbstractValue) -> AbstractValue:
        if value.object_id is None:
            return value
        return self.heap.setdefault(value.object_id, value.copy())

    def _should_promote_to_object(self, value: AbstractValue) -> bool:
        return (
            self.options.structured_state
            and value.object_id is None
            and not value.direct
            and not value.fields
            and not value.wildcard_field
            and not value.attrs
            and not value.wildcard_attr
            and value.source_collection is None
        )

    def _clone_env(self, env: dict[str, AbstractValue]) -> dict[str, AbstractValue]:
        return {key: value.copy() for key, value in env.items()}

    def _clone_heap(self, heap: dict[int, AbstractValue]) -> dict[int, AbstractValue]:
        return {key: value.copy() for key, value in heap.items()}

    def _merge_env_into(
        self,
        target: dict[str, AbstractValue],
        left: dict[str, AbstractValue],
        right: dict[str, AbstractValue],
    ) -> None:
        for name in sorted(set(left) | set(right)):
            target[name] = merge_values(
                left.get(name, empty_value()),
                right.get(name, empty_value()),
                options=self.options,
            )

    def _merge_heaps(
        self,
        left: dict[int, AbstractValue],
        right: dict[int, AbstractValue],
    ) -> dict[int, AbstractValue]:
        return {
            object_id: merge_values(
                left.get(object_id, empty_value()),
                right.get(object_id, empty_value()),
                options=self.options,
            )
            for object_id in sorted(set(left) | set(right))
        }

    def _resolve_function(
        self,
        *,
        file: Path,
        node: ast.Call,
        call_name: str,
    ) -> FunctionInfo | None:
        aliases = self.imports_by_file.get(file, {})
        module = self._module_for_file(file)
        if isinstance(node.func, ast.Name):
            alias_target = aliases.get(node.func.id)
            if alias_target is not None:
                imported = self._resolve_import_target(alias_target)
                if imported is not None:
                    return imported
                return None
            return self._single_candidate(
                self.functions_by_module_name.get((module, node.func.id), [])
            ) or self._single_candidate(self.functions_by_name.get(node.func.id, []))

        if isinstance(node.func, ast.Attribute):
            receiver_name = qualified_name(node.func.value)
            if receiver_name is not None:
                imported_call = self._resolve_imported_attribute(
                    receiver_name,
                    node.func.attr,
                    aliases,
                )
                if imported_call is not None:
                    return imported_call

                same_module_class = self._single_candidate(
                    self.functions_by_module_qualified.get(
                        (module, f"{receiver_name}.{node.func.attr}"),
                        [],
                    )
                )
                if same_module_class is not None:
                    return same_module_class

            same_module_methods = [
                candidate
                for candidate in self.functions_by_module_name.get((module, node.func.attr), [])
                if candidate.class_name is not None
            ]
            resolved = self._single_candidate(same_module_methods)
            if resolved is not None:
                return resolved

            all_methods = [
                candidate
                for candidate in self.functions_by_name.get(node.func.attr, [])
                if candidate.class_name is not None
            ]
            return self._single_candidate(all_methods)
        return self._single_candidate(self.functions_by_name.get(call_name.rsplit(".", 1)[-1], []))

    def _resolve_import_target(self, target: str) -> FunctionInfo | None:
        module, _, name = target.rpartition(".")
        if not module or not name:
            return None
        return self._single_candidate(self.functions_by_module_name.get((module, name), []))

    def _resolve_imported_attribute(
        self,
        receiver_name: str,
        attr: str,
        aliases: dict[str, str],
    ) -> FunctionInfo | None:
        first, _, rest = receiver_name.partition(".")
        alias_target = aliases.get(first)
        if alias_target is None:
            return None
        resolved_receiver = ".".join(part for part in [alias_target, rest] if part)
        candidate = self._single_candidate(
            self.functions_by_module_name.get((resolved_receiver, attr), [])
        )
        if candidate is not None:
            return candidate
        module, _, imported_name = resolved_receiver.rpartition(".")
        if module and imported_name:
            return self._single_candidate(
                self.functions_by_module_qualified.get((module, f"{imported_name}.{attr}"), [])
            )
        return None

    def _single_candidate(self, candidates: list[FunctionInfo]) -> FunctionInfo | None:
        identities = {candidate.identity for candidate in candidates}
        if len(identities) == 1:
            return candidates[0]
        return None

    def _module_for_file(self, file: Path) -> str:
        for function in self.functions:
            if function.file == file:
                return function.module
        try:
            relative = file.relative_to(self.root).with_suffix("")
        except ValueError:
            relative = file.with_suffix("")
        parts = list(relative.parts)
        if parts and parts[-1] == "__init__":
            parts = parts[:-1]
        return ".".join(parts) or file.stem

    def _matched_sanitizer(self, call_name: str) -> str | None:
        short_name = call_name.rsplit(".", 1)[-1]
        for pattern in self.config.sanitizer_patterns:
            if call_matches(pattern, call_name) or short_name == pattern:
                return pattern
        return None
