"""
Research Context Builder
========================

Builds controlled context levels for vulnerability repair experiments.

Context levels:
    C0 - Minimal
    C1 - SAST enriched
    C2 - Structural
    C3 - Security-grounded

The important research property is that context construction is deterministic
and does not use an LLM.
"""

from __future__ import annotations

import ast
import os
from dataclasses import dataclass, asdict
from typing import Optional


@dataclass
class StructuralContext:
    file_path: str
    function_name: Optional[str]
    class_name: Optional[str]
    function_source: str
    parameters: list[str]
    local_variables: list[str]
    imports: list[str]
    callers: list[str]
    callees: list[str]


def _find_enclosing_scope(
    tree: ast.AST,
    target_line: int,
) -> tuple[Optional[str], Optional[str], Optional[ast.AST]]:
    """
    Find the function/method and class containing target_line.
    """
    best_function = None
    best_class = None
    best_node = None

    class StackVisitor(ast.NodeVisitor):
        def __init__(self):
            self.class_stack = []

        def visit_ClassDef(self, node):
            nonlocal best_class
            if node.lineno <= target_line <= getattr(node, "end_lineno", node.lineno):
                best_class = node.name
            self.class_stack.append(node.name)
            self.generic_visit(node)
            self.class_stack.pop()

        def visit_FunctionDef(self, node):
            nonlocal best_function, best_class, best_node

            if node.lineno <= target_line <= getattr(
                node, "end_lineno", node.lineno
            ):
                best_function = node.name
                best_node = node
                if self.class_stack:
                    best_class = self.class_stack[-1]

            self.generic_visit(node)

        def visit_AsyncFunctionDef(self, node):
            nonlocal best_function, best_class, best_node

            if node.lineno <= target_line <= getattr(
                node, "end_lineno", node.lineno
            ):
                best_function = node.name
                best_node = node
                if self.class_stack:
                    best_class = self.class_stack[-1]

            self.generic_visit(node)

    StackVisitor().visit(tree)

    return best_function, best_class, best_node


def _collect_parameters(node: ast.AST) -> list[str]:
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return []

    args = []

    for arg in node.args.posonlyargs:
        args.append(arg.arg)

    for arg in node.args.args:
        args.append(arg.arg)

    if node.args.vararg:
        args.append("*" + node.args.vararg.arg)

    for arg in node.args.kwonlyargs:
        args.append(arg.arg)

    if node.args.kwarg:
        args.append("**" + node.args.kwarg.arg)

    return args


def _collect_local_variables(node: ast.AST) -> list[str]:
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return []

    variables = set()

    for child in ast.walk(node):
        if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
            variables.add(child.id)

    return sorted(variables)


def _collect_imports(tree: ast.AST) -> list[str]:
    imports = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(alias.name)

        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                imports.append(
                    f"{module}.{alias.name}" if module else alias.name
                )

    return sorted(set(imports))


def _collect_calls(node: ast.AST) -> list[str]:
    if node is None:
        return []

    calls = set()

    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue

        func = child.func

        if isinstance(func, ast.Name):
            calls.add(func.id)

        elif isinstance(func, ast.Attribute):
            parts = []
            current = func

            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value

            if isinstance(current, ast.Name):
                parts.append(current.id)

            calls.add(".".join(reversed(parts)))

    return sorted(calls)


def _collect_functions(tree: ast.AST) -> list[tuple[str, ast.AST]]:
    result = []

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            result.append((node.name, node))

    return result


def _collect_callers(tree: ast.AST, function_name: Optional[str]) -> list[str]:
    if not function_name:
        return []

    callers = set()

    for name, node in _collect_functions(tree):
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                called_name = None

                if isinstance(child.func, ast.Name):
                    called_name = child.func.id

                elif isinstance(child.func, ast.Attribute):
                    called_name = child.func.attr

                if called_name == function_name and name != function_name:
                    callers.add(name)

    return sorted(callers)


def build_structural_context(
    file_path: str,
    finding: dict,
    file_content: str,
) -> StructuralContext:
    """
    Build deterministic structural information from Python AST.
    """
    try:
        tree = ast.parse(file_content)
    except SyntaxError:
        return StructuralContext(
            file_path=file_path,
            function_name=None,
            class_name=None,
            function_source="",
            parameters=[],
            local_variables=[],
            imports=[],
            callers=[],
            callees=[],
        )

    line = int(finding.get("line", 1))

    function_name, class_name, function_node = _find_enclosing_scope(
        tree, line
    )

    function_source = ""

    if function_node is not None:
        try:
            function_source = ast.get_source_segment(
                file_content,
                function_node,
            ) or ""
        except Exception:
            function_source = ""

    parameters = _collect_parameters(function_node)
    local_variables = _collect_local_variables(function_node)
    imports = _collect_imports(tree)
    callees = _collect_calls(function_node)
    callers = _collect_callers(tree, function_name)

    return StructuralContext(
        file_path=file_path,
        function_name=function_name,
        class_name=class_name,
        function_source=function_source,
        parameters=parameters,
        local_variables=local_variables,
        imports=imports,
        callers=callers,
        callees=callees,
    )


def build_context(
    finding: dict,
    file_content: str,
    condition: str = "C1",
    security_context: Optional[dict] = None,
) -> str:
    """
    Build the actual textual repair context.

    condition may be:
        C0
        C1
        C2
        C3

    Legacy names are also accepted:
        minimal  -> C0
        enriched -> C1
    """

    normalized = condition.lower()

    if normalized == "minimal":
        normalized = "c0"

    elif normalized == "enriched":
        normalized = "c1"

    if normalized not in {"c0", "c1", "c2", "c3"}:
        raise ValueError(
            f"Unknown context condition: {condition}. "
            "Expected C0, C1, C2 or C3."
        )

    vulnerability_type = finding.get(
        "rule_id",
        "unknown",
    ).split(".")[-1]

    if normalized == "c0":
        return f"""Vulnerability type:
{vulnerability_type}

Full file content:
{file_content}
"""

    base = f"""Vulnerability Details:
- File: {finding.get("file", "")}
- Line: {finding.get("line", "")}
- Rule: {finding.get("rule_id", "")}
- Severity: {finding.get("severity", "")}
- Issue: {finding.get("message", "")}
- Vulnerable code snippet:
{finding.get("code_snippet", "")}

Full file content:
{file_content}
"""

    if normalized == "c1":
        return base

    structural = build_structural_context(
        finding.get("file", ""),
        finding,
        file_content,
    )

    structural_text = f"""
Structural Context:
- Enclosing class: {structural.class_name or "None"}
- Enclosing function: {structural.function_name or "None"}
- Parameters: {", ".join(structural.parameters) or "None"}
- Local variables: {", ".join(structural.local_variables) or "None"}
- Imports: {", ".join(structural.imports) or "None"}
- Calls made by target function: {", ".join(structural.callees) or "None"}
- Functions calling target function: {", ".join(structural.callers) or "None"}

Target function source:
{structural.function_source or "Unavailable"}
"""

    if normalized == "c2":
        return base + structural_text

    security_context = security_context or {}

    security_text = f"""
Security-Grounded Context:
- CWE: {security_context.get("cwe", "Not provided")}
- CVE: {security_context.get("cve", "Not provided")}
- Attack mechanism: {security_context.get("attack_mechanism", "Not provided")}
- Secure repair guidance: {security_context.get("repair_guidance", "Not provided")}
- Security constraints: {security_context.get("constraints", "Not provided")}
"""

    return base + structural_text + security_text


def context_metadata(
    finding: dict,
    file_content: str,
    condition: str,
    security_context: Optional[dict] = None,
) -> dict:
    """
    Return machine-readable metadata for experiment logging.
    """
    normalized = condition.lower()

    if normalized == "minimal":
        normalized = "C0"
    elif normalized == "enriched":
        normalized = "C1"
    else:
        normalized = normalized.upper()

    structural = build_structural_context(
        finding.get("file", ""),
        finding,
        file_content,
    )

    context = build_context(
        finding,
        file_content,
        condition,
        security_context,
    )

    return {
        "condition": normalized,
        "context_characters": len(context),
        "context_lines": len(context.splitlines()),
        "structural": asdict(structural),
        "security_context_provided": bool(security_context),
    }
