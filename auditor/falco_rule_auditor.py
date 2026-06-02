#!/usr/bin/env python3
"""Audit Falco rules against the detection-anchor taxonomy."""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import yaml


FIELD_PATTERN = re.compile(r"\b([a-z]+\.[a-z_.]+)\b")
ANCHOR_STRENGTH = {
    "mount-anchored": 4,
    "syscall-anchored": 3,
    "path-anchored": 2,
    "name-anchored": 1,
    "metadata": 0,
}
ANCHOR_RESISTANCE = {
    "mount-anchored": "HIGH",
    "syscall-anchored": "HIGH",
    "path-anchored": "LOW",
    "name-anchored": "LOW",
    "metadata": "INFO",
}
LOW_ANCHOR_MESSAGES = {
    "name-anchored": "vulnerable to binary rename, custom binaries, or cmdline changes",
    "path-anchored": "vulnerable to symlink, fd redirection, /proc/self/fd, or alternate mount path evasion",
}
DEFAULT_FIELD_MAP = (
    Path(__file__).resolve().parents[1] / "taxonomy" / "field_classification.yaml"
)
DEFAULT_ANCHOR_CLASSES = (
    Path(__file__).resolve().parents[1] / "taxonomy" / "anchor_classes.yaml"
)
DEFAULT_ATTACK_TECHNIQUE_COSTS = (
    Path(__file__).resolve().parents[1] / "taxonomy" / "attack_technique_costs.yaml"
)
MAX_MACRO_EXPANSION_DEPTH = 32


@dataclass(frozen=True)
class ParsedRule:
    name: str
    condition: str
    priority: str
    tags: list[str]
    source: str


@dataclass(frozen=True)
class HardeningSuggestion:
    target_field: str
    target_anchor_class: str
    target_resistance: str
    tradeoff: str
    example_before: str
    example_after: str


@dataclass(frozen=True)
class FieldRiskDetail:
    field: str
    anchor_class: str
    resistance: str
    strengths: list[str]
    limitations: list[str]
    evasion_techniques: list[str]
    coverage_note: str
    hardening_suggestions: list[HardeningSuggestion]


@dataclass(frozen=True)
class FieldUsage:
    field: str
    anchor_class: str
    resistance: str


@dataclass(frozen=True)
class BranchAnalysis:
    index: int
    expression: str
    fields: list[str]
    required_fields: list[str]
    filter_only_fields: list[str]
    anchor_profile: list[str]
    strongest_anchor: str | None
    weakest_anchor: str | None
    verdict: str


@dataclass(frozen=True)
class AttackCostEstimate:
    technique: str | None
    label: str
    score: float | None
    band: str
    effort_minutes: int | None
    anchor_classes: list[str]
    evidence: str
    experiment_refs: list[str]
    description: str
    basis: str


@dataclass(frozen=True)
class RuleAudit:
    rule: str
    source: str
    priority: str
    tags: list[str]
    condition: str
    expanded_condition: str
    fields: list[FieldUsage]
    filter_only_fields: list[FieldUsage]
    unknown_fields: list[str]
    anchor_profile: list[str]
    strongest_anchor: str | None
    weakest_anchor: str | None
    verdict: str
    attacker_cost: AttackCostEstimate
    warnings: list[str]
    recommendation: str
    branches: list[BranchAnalysis]
    resilient_branch_count: int
    branch_count: int
    field_risk_details: list[FieldRiskDetail] = field(default_factory=list)


@dataclass
class ExprNode:
    op: str
    text: str = ""
    children: list["ExprNode"] = field(default_factory=list)


def load_field_classification(path: Path) -> dict[str, str]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Expected a mapping in {path}")
    return {str(key): str(value) for key, value in data.items()}


def load_anchor_classes(path: Path) -> dict[str, dict[str, Any]]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    if not isinstance(data, list):
        raise ValueError(f"Expected a list in {path}")
    anchors: dict[str, dict[str, Any]] = {}
    for entry in data:
        if isinstance(entry, dict) and "class" in entry:
            anchors[str(entry["class"])] = entry
    return anchors


def load_attack_technique_costs(path: Path) -> dict[str, dict[str, Any]]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    if not isinstance(data, list):
        raise ValueError(f"Expected a list in {path}")
    techniques: dict[str, dict[str, Any]] = {}
    for entry in data:
        if isinstance(entry, dict) and "technique" in entry:
            techniques[str(entry["technique"])] = entry
    return techniques


def iter_yaml_entries(path: Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for document in yaml.safe_load_all(handle):
            if document is None:
                continue
            if isinstance(document, list):
                entries.extend(item for item in document if isinstance(item, dict))
            elif isinstance(document, dict):
                entries.append(document)
    return entries


def parse_rule_file(path: Path) -> list[ParsedRule]:
    rules, _ = collect_rule_file_context(path)
    return rules


def collect_rule_file_context(path: Path) -> tuple[list[ParsedRule], dict[str, str]]:
    rules: list[ParsedRule] = []
    macros: dict[str, str] = {}
    for entry in iter_yaml_entries(path):
        if "macro" in entry and isinstance(entry.get("condition"), str):
            macros[str(entry["macro"])] = entry["condition"].strip()
        if "rule" not in entry:
            continue
        if any(skip_key in entry for skip_key in ("macro", "list", "required_engine_version")):
            continue
        condition = entry.get("condition")
        if not isinstance(condition, str):
            continue
        priority = str(entry.get("priority", "UNKNOWN"))
        tags = entry.get("tags") or []
        if not isinstance(tags, list):
            tags = [str(tags)]
        rules.append(
            ParsedRule(
                name=str(entry["rule"]),
                condition=condition.strip(),
                priority=priority,
                tags=[str(tag) for tag in tags],
                source=str(path),
            )
        )
    return rules, macros


def parse_rules_from_path(path: Path) -> list[ParsedRule]:
    rules, _ = collect_context_from_path(path)
    return rules


def collect_context_from_path(path: Path) -> tuple[list[ParsedRule], dict[str, str]]:
    rules: list[ParsedRule] = []
    if not path.exists():
        raise FileNotFoundError(f"Input path does not exist: {path}")
    if path.is_file():
        return collect_rule_file_context(path)

    files = sorted(
        candidate
        for candidate in path.iterdir()
        if candidate.is_file() and candidate.suffix.lower() in {".yaml", ".yml"}
    )
    macros: dict[str, str] = {}
    for file_path in files:
        file_rules, file_macros = collect_rule_file_context(file_path)
        rules.extend(file_rules)
        macros.update(file_macros)
    return rules, macros


def unique_in_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            ordered.append(value)
    return ordered


def extract_fields(condition: str, known_fields: dict[str, str]) -> tuple[list[str], list[str]]:
    matches = FIELD_PATTERN.findall(condition)
    known_prefixes = {field_name.split(".", 1)[0] for field_name in known_fields}
    used_fields = unique_in_order([match for match in matches if match in known_fields])
    unknown_fields = unique_in_order(
        [
            match
            for match in matches
            if match not in known_fields and match.split(".", 1)[0] in known_prefixes
        ]
    )
    return used_fields, unknown_fields


def expand_macros_in_condition(condition: str, macros: dict[str, str]) -> str:
    cache: dict[str, str] = {}
    return expand_expression(condition, macros, cache, ())


def expand_expression(
    expression: str,
    macros: dict[str, str],
    cache: dict[str, str],
    stack: tuple[str, ...],
) -> str:
    output: list[str] = []
    index = 0
    in_single = False
    in_double = False

    while index < len(expression):
        char = expression[index]
        if char == "'" and not in_double and (index == 0 or expression[index - 1] != "\\"):
            in_single = not in_single
            output.append(char)
            index += 1
            continue
        if char == '"' and not in_single and (index == 0 or expression[index - 1] != "\\"):
            in_double = not in_double
            output.append(char)
            index += 1
            continue

        if not in_single and not in_double and (char.isalpha() or char == "_"):
            end = index + 1
            while end < len(expression) and (expression[end].isalnum() or expression[end] == "_"):
                end += 1
            token = expression[index:end]
            before = expression[index - 1] if index > 0 else ""
            after = expression[end] if end < len(expression) else ""
            if token in macros and before != "." and after != ".":
                output.append(f"({expand_macro_name(token, macros, cache, stack)})")
            else:
                output.append(token)
            index = end
            continue

        output.append(char)
        index += 1

    return "".join(output)


def expand_macro_name(
    name: str,
    macros: dict[str, str],
    cache: dict[str, str],
    stack: tuple[str, ...],
) -> str:
    if name in cache:
        return cache[name]
    if name in stack or len(stack) >= MAX_MACRO_EXPANSION_DEPTH:
        return macros[name]
    expanded = expand_expression(macros[name], macros, cache, stack + (name,))
    cache[name] = expanded
    return expanded


def anchor_strength(anchor_class: str | None) -> int:
    if anchor_class is None:
        return -1
    return ANCHOR_STRENGTH.get(anchor_class, -1)


def strongest_anchor(anchor_classes: list[str]) -> str | None:
    if not anchor_classes:
        return None
    return max(anchor_classes, key=lambda item: (anchor_strength(item), item))


def weakest_anchor(anchor_classes: list[str]) -> str | None:
    if not anchor_classes:
        return None
    return min(anchor_classes, key=lambda item: (anchor_strength(item), item))


def is_word_char(char: str) -> bool:
    return char.isalnum() or char == "_"


def strip_outer_parentheses(expression: str) -> str:
    expr = expression.strip()
    while expr.startswith("(") and expr.endswith(")"):
        depth = 0
        encloses_all = True
        in_single = False
        in_double = False
        for index, char in enumerate(expr):
            if char == "'" and not in_double and (index == 0 or expr[index - 1] != "\\"):
                in_single = not in_single
            elif char == '"' and not in_single and (index == 0 or expr[index - 1] != "\\"):
                in_double = not in_double
            elif not in_single and not in_double:
                if char == "(":
                    depth += 1
                elif char == ")":
                    depth -= 1
                    if depth == 0 and index != len(expr) - 1:
                        encloses_all = False
                        break
        if not encloses_all:
            break
        expr = expr[1:-1].strip()
    return expr


def split_top_level(expression: str, keyword: str) -> list[str]:
    expr = expression.strip()
    parts: list[str] = []
    start = 0
    depth = 0
    in_single = False
    in_double = False
    index = 0
    keyword_len = len(keyword)

    while index < len(expr):
        char = expr[index]
        if char == "'" and not in_double and (index == 0 or expr[index - 1] != "\\"):
            in_single = not in_single
        elif char == '"' and not in_single and (index == 0 or expr[index - 1] != "\\"):
            in_double = not in_double
        elif not in_single and not in_double:
            if char == "(":
                depth += 1
            elif char == ")":
                depth = max(0, depth - 1)
            elif depth == 0 and expr[index : index + keyword_len].lower() == keyword:
                before = expr[index - 1] if index > 0 else ""
                after_index = index + keyword_len
                after = expr[after_index] if after_index < len(expr) else ""
                if not is_word_char(before) and not is_word_char(after):
                    parts.append(expr[start:index].strip())
                    start = after_index
                    index = after_index
                    continue
        index += 1

    if not parts:
        return [expr]
    parts.append(expr[start:].strip())
    return [part for part in parts if part]


def parse_condition(expression: str) -> ExprNode:
    expr = strip_outer_parentheses(expression.strip())
    or_parts = split_top_level(expr, "or")
    if len(or_parts) > 1:
        return ExprNode(op="or", children=[parse_condition(part) for part in or_parts])

    and_parts = split_top_level(expr, "and")
    if len(and_parts) > 1:
        return ExprNode(op="and", children=[parse_condition(part) for part in and_parts])

    return ExprNode(op="atom", text=expr)


def expand_branches(node: ExprNode) -> list[list[str]]:
    if node.op == "atom":
        return [[node.text]]

    if node.op == "or":
        branches: list[list[str]] = []
        for child in node.children:
            branches.extend(expand_branches(child))
        return dedupe_branches(branches)

    if node.op == "and":
        branches: list[list[str]] = [[]]
        for child in node.children:
            child_branches = expand_branches(child)
            combined: list[list[str]] = []
            for prefix in branches:
                for suffix in child_branches:
                    combined.append(prefix + suffix)
            branches = combined
        return dedupe_branches(branches)

    return []


def dedupe_branches(branches: list[list[str]]) -> list[list[str]]:
    seen: set[tuple[str, ...]] = set()
    unique_branches: list[list[str]] = []
    for branch in branches:
        key = tuple(branch)
        if key not in seen:
            seen.add(key)
            unique_branches.append(branch)
    return unique_branches


def build_field_risk_details(
    fields: list[str],
    field_map: dict[str, str],
    anchor_metadata: dict[str, dict[str, Any]],
) -> list[FieldRiskDetail]:
    details: list[FieldRiskDetail] = []
    seen: set[str] = set()
    for field_name in fields:
        if field_name in seen:
            continue
        seen.add(field_name)
        anchor_class = field_map.get(field_name, "unknown")
        if anchor_class == "metadata":
            continue
        resistance = ANCHOR_RESISTANCE.get(anchor_class, "UNKNOWN")
        meta = anchor_metadata.get(anchor_class, {})
        hardening = meta.get("hardening", {})
        strengths = [str(s) for s in hardening.get("strengths", [])]
        limitations = [str(s) for s in hardening.get("limitations", [])]
        coverage_note = str(hardening.get("coverage_notes", "")).strip()
        bypassed_by = [str(b) for b in meta.get("bypassed_by", [])]
        upgrade_to = hardening.get("upgrade_to", []) or []
        suggestions: list[HardeningSuggestion] = []
        for upgrade in upgrade_to:
            suggestions.append(HardeningSuggestion(
                target_field=str(upgrade.get("field", "")),
                target_anchor_class=str(upgrade.get("anchor_class", "")),
                target_resistance=str(upgrade.get("resistance", "")),
                tradeoff=str(upgrade.get("tradeoff", "")),
                example_before=str(upgrade.get("example_before", "")),
                example_after=str(upgrade.get("example_after", "")),
            ))
        details.append(FieldRiskDetail(
            field=field_name,
            anchor_class=anchor_class,
            resistance=resistance,
            strengths=strengths,
            limitations=limitations,
            evasion_techniques=bypassed_by,
            coverage_note=coverage_note,
            hardening_suggestions=suggestions,
        ))
    return details


def build_field_usages(fields: list[str], field_map: dict[str, str]) -> list[FieldUsage]:
    usages: list[FieldUsage] = []
    for field_name in fields:
        anchor_class = field_map[field_name]
        usages.append(
            FieldUsage(
                field=field_name,
                anchor_class=anchor_class,
                resistance=ANCHOR_RESISTANCE.get(anchor_class, "UNKNOWN"),
            )
        )
    return usages


def anchor_profile_for_fields(fields: list[str], field_map: dict[str, str]) -> list[str]:
    anchor_classes = [
        field_map[field_name]
        for field_name in fields
        if field_map[field_name] != "metadata"
    ]
    return unique_in_order(anchor_classes)


def branch_verdict(anchor_classes: list[str]) -> str:
    weak = weakest_anchor(anchor_classes)
    if weak is None:
        return "UNKNOWN"
    return "RESILIENT" if anchor_strength(weak) >= anchor_strength("syscall-anchored") else "FRAGILE"


def clause_is_negated(clause: str) -> bool:
    text = strip_outer_parentheses(clause.strip())
    return text.lower().startswith("not ")


def split_required_and_filter_fields(
    clauses: list[str],
    field_map: dict[str, str],
) -> tuple[list[str], list[str]]:
    required_fields: list[str] = []
    filter_fields: list[str] = []
    for clause in clauses:
        clause_fields, _ = extract_fields(clause, field_map)
        if clause_is_negated(clause):
            filter_fields.extend(clause_fields)
        else:
            required_fields.extend(clause_fields)
    required_unique = unique_in_order(required_fields)
    filter_unique = [
        field_name
        for field_name in unique_in_order(filter_fields)
        if field_name not in required_unique
    ]
    return required_unique, filter_unique


def analyze_branches(condition: str, field_map: dict[str, str]) -> list[BranchAnalysis]:
    tree = parse_condition(condition)
    raw_branches = expand_branches(tree)
    analyses: list[BranchAnalysis] = []
    for index, clauses in enumerate(raw_branches, start=1):
        expression = " and ".join(clause for clause in clauses if clause)
        fields, _ = extract_fields(expression, field_map)
        required_fields, filter_only_fields = split_required_and_filter_fields(clauses, field_map)
        profile = anchor_profile_for_fields(required_fields, field_map)
        analyses.append(
            BranchAnalysis(
                index=index,
                expression=expression,
                fields=fields,
                required_fields=required_fields,
                filter_only_fields=filter_only_fields,
                anchor_profile=profile,
                strongest_anchor=strongest_anchor(profile),
                weakest_anchor=weakest_anchor(profile),
                verdict=branch_verdict(profile),
            )
        )
    return analyses


def build_warnings(
    fields: list[FieldUsage],
    unknown_fields: list[str],
    anchor_metadata: dict[str, dict[str, Any]],
    attacker_cost: AttackCostEstimate,
) -> list[str]:
    warnings: list[str] = []
    for usage in fields:
        if usage.anchor_class in LOW_ANCHOR_MESSAGES:
            detail = LOW_ANCHOR_MESSAGES[usage.anchor_class]
            bypassed_by = anchor_metadata.get(usage.anchor_class, {}).get("bypassed_by") or []
            if bypassed_by:
                detail = f"{detail}; known techniques: {', '.join(str(item) for item in bypassed_by)}"
            warnings.append(
                f"[!] {usage.field} is {usage.anchor_class}: {detail}"
            )
    for field_name in unknown_fields:
        warnings.append(
            f"[?] {field_name} is not mapped in taxonomy/field_classification.yaml; extend the mapping before trusting this verdict"
        )
    if attacker_cost.technique is not None and attacker_cost.score is not None:
        warnings.append(
            "[~] Attacker cost floor: "
            f"{attacker_cost.label} ({attacker_cost.band}, score {attacker_cost.score:.2f}/5, "
            f"~{attacker_cost.effort_minutes} min hands-on)"
        )
    return warnings


def build_recommendation(verdict: str, unknown_fields: list[str], resilient_branch_count: int) -> str:
    if unknown_fields:
        return (
            "Review the unknown fields first and extend the field taxonomy before relying on this audit."
        )
    if verdict == "RESILIENT":
        return (
            "Rule already relies on high-resistance anchors; keep weak string checks optional if you add them later."
        )
    if verdict == "MIXED" or resilient_branch_count > 0:
        return (
            "Preserve the independent high-resistance branch and avoid making detection depend on attacker-controlled name or path strings."
        )
    return (
        "Add a mount-anchored or syscall-anchored fallback that can fire without relying on attacker-controlled name or path strings."
    )


def overall_verdict(branches: list[BranchAnalysis]) -> str:
    if not branches:
        return "UNKNOWN"

    branch_verdicts = {branch.verdict for branch in branches}
    if branch_verdicts == {"RESILIENT"}:
        return "RESILIENT"
    if "RESILIENT" in branch_verdicts and "FRAGILE" in branch_verdicts:
        return "MIXED"
    if branch_verdicts == {"UNKNOWN"}:
        return "UNKNOWN"
    return "FRAGILE"


def effort_bucket(minutes: int) -> int:
    if minutes <= 5:
        return 1
    if minutes <= 15:
        return 2
    if minutes <= 30:
        return 3
    if minutes <= 60:
        return 4
    return 5


def cost_band(score: float) -> str:
    if score <= 1.5:
        return "TRIVIAL"
    if score <= 2.5:
        return "LOW"
    if score <= 3.5:
        return "MODERATE"
    return "HIGH"


def technique_cost_score(technique_data: dict[str, Any]) -> float:
    score = (
        0.45 * effort_bucket(int(technique_data["effort_minutes"]))
        + 0.25 * float(technique_data["skill_level"])
        + 0.20 * float(technique_data["prerequisite_level"])
        + 0.10 * float(technique_data["operational_change_level"])
    )
    return round(score, 2)


def estimate_attacker_cost(
    anchor_profile: list[str],
    anchor_metadata: dict[str, dict[str, Any]],
    technique_costs: dict[str, dict[str, Any]],
) -> AttackCostEstimate:
    low_anchor_classes = [
        anchor_class
        for anchor_class in anchor_profile
        if anchor_class in LOW_ANCHOR_MESSAGES
    ]
    if not low_anchor_classes:
        return AttackCostEstimate(
            technique=None,
            label="No direct in-scope bypass observed",
            score=None,
            band="HARDENED",
            effort_minutes=None,
            anchor_classes=[],
            evidence="n/a",
            experiment_refs=[],
            description=(
                "Required anchors are syscall-anchored and/or mount-anchored. The current cost model "
                "treats coverage shifts such as changing syscall or deployment as out of scope."
            ),
            basis="No low-resistance anchor class is required for this rule.",
        )

    candidates: list[tuple[float, int, str, dict[str, Any], list[str]]] = []
    for anchor_class in low_anchor_classes:
        bypassed_by = anchor_metadata.get(anchor_class, {}).get("bypassed_by") or []
        for technique_name in bypassed_by:
            if technique_name not in technique_costs:
                continue
            technique_data = technique_costs[technique_name]
            score = technique_cost_score(technique_data)
            applies_to = [
                item
                for item in low_anchor_classes
                if technique_name in (anchor_metadata.get(item, {}).get("bypassed_by") or [])
            ]
            candidates.append(
                (
                    score,
                    int(technique_data["effort_minutes"]),
                    str(technique_data["label"]),
                    technique_data,
                    applies_to,
                )
            )

    if not candidates:
        return AttackCostEstimate(
            technique=None,
            label="No modeled bypass technique",
            score=None,
            band="UNKNOWN",
            effort_minutes=None,
            anchor_classes=low_anchor_classes,
            evidence="n/a",
            experiment_refs=[],
            description="The rule depends on a low-resistance anchor, but no matching technique is defined in the current cost model.",
            basis="Extend taxonomy/attack_technique_costs.yaml to complete the estimate.",
        )

    score, _, _, technique_data, applies_to = min(candidates, key=lambda item: (item[0], item[1], item[2]))
    return AttackCostEstimate(
        technique=str(technique_data["technique"]),
        label=str(technique_data["label"]),
        score=score,
        band=cost_band(score),
        effort_minutes=int(technique_data["effort_minutes"]),
        anchor_classes=applies_to,
        evidence=str(technique_data.get("evidence", "reasoned")),
        experiment_refs=[str(item) for item in technique_data.get("experiment_refs", [])],
        description=str(technique_data.get("description", "")),
        basis=(
            "Lower-bound estimate: cheapest modeled single technique associated with any low-resistance "
            "anchor class present in the rule."
        ),
    )


def analyze_rule(
    rule: ParsedRule,
    field_map: dict[str, str],
    anchor_metadata: dict[str, dict[str, Any]],
    technique_costs: dict[str, dict[str, Any]] | None = None,
    macros: dict[str, str] | None = None,
) -> RuleAudit:
    macro_map = macros or {}
    cost_map = technique_costs or {}
    expanded_condition = expand_macros_in_condition(rule.condition, macro_map)
    used_fields, unknown_fields = extract_fields(expanded_condition, field_map)
    branches = analyze_branches(expanded_condition, field_map)
    required_field_names = unique_in_order(
        [field_name for branch in branches for field_name in branch.required_fields]
    )
    filter_only_field_names = [
        field_name
        for field_name in used_fields
        if field_name not in required_field_names
    ]
    field_usages = build_field_usages(used_fields, field_map)
    filter_only_usages = build_field_usages(filter_only_field_names, field_map)
    required_usages = build_field_usages(required_field_names, field_map)
    anchor_profile = anchor_profile_for_fields(required_field_names, field_map)
    resilient_branch_count = sum(1 for branch in branches if branch.verdict == "RESILIENT")
    verdict = overall_verdict(branches)
    attacker_cost = estimate_attacker_cost(anchor_profile, anchor_metadata, cost_map)
    warnings = build_warnings(required_usages, unknown_fields, anchor_metadata, attacker_cost)
    recommendation = build_recommendation(verdict, unknown_fields, resilient_branch_count)
    risk_details = build_field_risk_details(required_field_names, field_map, anchor_metadata)
    return RuleAudit(
        rule=rule.name,
        source=rule.source,
        priority=rule.priority,
        tags=rule.tags,
        condition=rule.condition,
        expanded_condition=expanded_condition,
        fields=field_usages,
        filter_only_fields=filter_only_usages,
        unknown_fields=unknown_fields,
        anchor_profile=anchor_profile,
        strongest_anchor=strongest_anchor(anchor_profile),
        weakest_anchor=weakest_anchor(anchor_profile),
        verdict=verdict,
        attacker_cost=attacker_cost,
        warnings=warnings,
        recommendation=recommendation,
        branches=branches,
        resilient_branch_count=resilient_branch_count,
        branch_count=len(branches),
        field_risk_details=risk_details,
    )


def audit_paths(
    inputs: list[Path],
    field_map_path: Path = DEFAULT_FIELD_MAP,
    anchor_classes_path: Path = DEFAULT_ANCHOR_CLASSES,
    attack_technique_costs_path: Path = DEFAULT_ATTACK_TECHNIQUE_COSTS,
) -> list[RuleAudit]:
    field_map = load_field_classification(field_map_path)
    anchor_metadata = load_anchor_classes(anchor_classes_path)
    technique_costs = load_attack_technique_costs(attack_technique_costs_path)

    rules: list[ParsedRule] = []
    macros: dict[str, str] = {}
    for input_path in inputs:
        path_rules, path_macros = collect_context_from_path(input_path)
        rules.extend(path_rules)
        macros.update(path_macros)
    return [analyze_rule(rule, field_map, anchor_metadata, technique_costs, macros) for rule in rules]


def short_anchor_name(anchor_class: str | None) -> str:
    if not anchor_class:
        return "-"
    return anchor_class.replace("-anchored", "")


def render_rule(audit: RuleAudit) -> str:
    lines = [
        f"Rule: {audit.rule}",
        f"  Source: {audit.source}",
        f"  Priority: {audit.priority}",
        f"  Tags: {', '.join(audit.tags) if audit.tags else '-'}",
        "  Fields used:",
    ]
    if audit.fields:
        for usage in audit.fields:
            lines.append(
                f"    - {usage.field:<18} -> {usage.anchor_class:<17} ({usage.resistance} resistance)"
            )
    else:
        lines.append("    - No mapped Falco fields found")

    if audit.filter_only_fields:
        lines.append("  Filter-only fields:")
        for usage in audit.filter_only_fields:
            lines.append(
                f"    - {usage.field:<18} -> {usage.anchor_class:<17} ({usage.resistance} resistance)"
            )

    if audit.unknown_fields:
        lines.append("  Unknown dotted fields:")
        for field_name in audit.unknown_fields:
            lines.append(f"    - {field_name}")

    lines.extend(
        [
            f"  Anchor profile: {', '.join(audit.anchor_profile) if audit.anchor_profile else '-'}",
            f"  Strongest anchor: {audit.strongest_anchor or '-'}",
            f"  Weakest anchor: {audit.weakest_anchor or '-'}",
            f"  Verdict: {audit.verdict}",
        ]
    )

    lines.append("  Attacker cost floor:")
    if audit.attacker_cost.score is None:
        lines.append(f"    - {audit.attacker_cost.label}")
        lines.append(f"    - Basis: {audit.attacker_cost.basis}")
    else:
        refs = ", ".join(audit.attacker_cost.experiment_refs) if audit.attacker_cost.experiment_refs else "discussion-only"
        lines.append(
            f"    - {audit.attacker_cost.label} ({audit.attacker_cost.band}, score {audit.attacker_cost.score:.2f}/5)"
        )
        lines.append(
            f"    - Applies to: {', '.join(audit.attacker_cost.anchor_classes)}"
        )
        lines.append(
            f"    - Evidence: {audit.attacker_cost.evidence}; refs: {refs}; effort: ~{audit.attacker_cost.effort_minutes} min"
        )

    if audit.branch_count > 1:
        lines.append("  Branch analysis:")
        for branch in audit.branches:
            filter_suffix = ""
            if branch.filter_only_fields:
                filter_suffix = f"; filters={', '.join(branch.filter_only_fields)}"
            lines.append(
                "    - "
                f"Branch {branch.index}: {branch.verdict} "
                f"(weakest={branch.weakest_anchor or '-'}; "
                f"required={', '.join(branch.required_fields) or '-'}{filter_suffix})"
            )

    lines.append("  Warnings:")
    if audit.warnings:
        for warning in audit.warnings:
            lines.append(f"    {warning}")
    else:
        lines.append("    None")

    lines.append(f"  Recommendation: {audit.recommendation}")

    if audit.field_risk_details:
        lines.append("  Field risk analysis:")
        for detail in audit.field_risk_details:
            lines.append(f"    [{detail.resistance}] {detail.field}  ({detail.anchor_class})")
            if detail.strengths:
                lines.append("      Strengths:")
                for s in detail.strengths:
                    lines.append(f"        + {s}")
            if detail.limitations:
                lines.append("      Limitations:")
                for lim in detail.limitations:
                    lines.append(f"        - {lim}")
            if detail.evasion_techniques:
                lines.append(f"      Evasion techniques: {', '.join(detail.evasion_techniques)}")
            if detail.coverage_note:
                lines.append(f"      Coverage: {detail.coverage_note}")
            if detail.hardening_suggestions:
                lines.append("      Hardening options:")
                for sug in detail.hardening_suggestions:
                    lines.append(f"        -> Upgrade to {sug.target_field} ({sug.target_anchor_class}, {sug.target_resistance})")
                    lines.append(f"           Before: {sug.example_before}")
                    lines.append(f"           After:  {sug.example_after}")
                    lines.append(f"           Trade-off: {sug.tradeoff}")

    return "\n".join(lines)


def render_summary(audits: list[RuleAudit]) -> str:
    headers = ("Rule", "Strongest", "Weakest", "Verdict", "Cost Floor")
    rows = [
        (
            audit.rule,
            short_anchor_name(audit.strongest_anchor),
            short_anchor_name(audit.weakest_anchor),
            audit.verdict,
            (
                audit.attacker_cost.band
                if audit.attacker_cost.score is not None
                else audit.attacker_cost.label
            ),
        )
        for audit in audits
    ]
    widths = [len(header) for header in headers]
    for row in rows:
        for index, value in enumerate(row):
            widths[index] = max(widths[index], len(value))

    divider = "  ".join("-" * width for width in widths)
    lines = ["RULE AUDIT SUMMARY", divider]
    lines.append(
        "  ".join(header.ljust(widths[index]) for index, header in enumerate(headers))
    )
    lines.append(divider)
    for row in rows:
        lines.append(
            "  ".join(value.ljust(widths[index]) for index, value in enumerate(row))
        )
    lines.append(divider)
    return "\n".join(lines)


def to_json_ready(audits: list[RuleAudit]) -> dict[str, Any]:
    verdict_counts: dict[str, int] = {}
    for audit in audits:
        verdict_counts[audit.verdict] = verdict_counts.get(audit.verdict, 0) + 1
    return {
        "rules": [asdict(audit) for audit in audits],
        "summary": {
            "total_rules": len(audits),
            "verdict_counts": verdict_counts,
        },
    }


def emit_csv(audits: list[RuleAudit], output_stream: Any) -> None:
    writer = csv.DictWriter(
        output_stream,
        fieldnames=[
            "rule",
            "source",
            "priority",
            "strongest_anchor",
            "weakest_anchor",
                "verdict",
                "anchor_profile",
                "fields",
                "unknown_fields",
                "attacker_cost_technique",
                "attacker_cost_band",
                "attacker_cost_score",
                "attacker_cost_effort_minutes",
                "branch_count",
                "resilient_branch_count",
                "tags",
        ],
    )
    writer.writeheader()
    for audit in audits:
        writer.writerow(
            {
                "rule": audit.rule,
                "source": audit.source,
                "priority": audit.priority,
                "strongest_anchor": audit.strongest_anchor or "",
                "weakest_anchor": audit.weakest_anchor or "",
                "verdict": audit.verdict,
                "anchor_profile": ";".join(audit.anchor_profile),
                "fields": ";".join(usage.field for usage in audit.fields),
                "unknown_fields": ";".join(audit.unknown_fields),
                "attacker_cost_technique": audit.attacker_cost.technique or "",
                "attacker_cost_band": audit.attacker_cost.band,
                "attacker_cost_score": "" if audit.attacker_cost.score is None else f"{audit.attacker_cost.score:.2f}",
                "attacker_cost_effort_minutes": audit.attacker_cost.effort_minutes or "",
                "branch_count": audit.branch_count,
                "resilient_branch_count": audit.resilient_branch_count,
                "tags": ";".join(audit.tags),
            }
        )


def _anchor_color(anchor_class: str) -> str:
    return {
        "syscall-anchored": "#1767a0",
        "mount-anchored": "#1a7f4b",
        "path-anchored": "#c0392b",
        "name-anchored": "#d97706",
        "metadata": "#6b7280",
    }.get(anchor_class, "#6b7280")


def _verdict_color(verdict: str) -> str:
    return {
        "RESILIENT": "#1a7f4b",
        "FRAGILE": "#c0392b",
        "MIXED": "#d97706",
    }.get(verdict, "#6b7280")


def _resistance_badge(resistance: str) -> str:
    col = "#1a7f4b" if resistance == "HIGH" else "#c0392b" if resistance == "LOW" else "#6b7280"
    return f'<span style="background:{col};color:#fff;padding:2px 10px;border-radius:3px;font-size:12px;font-weight:600">{resistance}</span>'


def _escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def emit_html(audits: list[RuleAudit], output_path: str | Path) -> None:
    total = len(audits)
    verdicts = {}
    anchor_counts: dict[str, int] = {}
    for audit in audits:
        verdicts[audit.verdict] = verdicts.get(audit.verdict, 0) + 1
        for ac in audit.anchor_profile:
            anchor_counts[ac] = anchor_counts.get(ac, 0) + 1

    resilient = verdicts.get("RESILIENT", 0)
    fragile = verdicts.get("FRAGILE", 0)
    mixed = verdicts.get("MIXED", 0)

    rule_cards = []
    for audit in audits:
        vc = _verdict_color(audit.verdict)
        src_name = Path(audit.source).name

        field_rows = ""
        for usage in audit.fields:
            ac = _anchor_color(usage.anchor_class)
            field_rows += f"""<tr>
                <td><code>{_escape(usage.field)}</code></td>
                <td><span style="background:{ac};color:#fff;padding:2px 8px;border-radius:3px;font-size:11px">{_escape(usage.anchor_class)}</span></td>
                <td>{_resistance_badge(usage.resistance)}</td>
            </tr>"""

        branch_html = ""
        if audit.branch_count > 1:
            branch_rows = ""
            for branch in audit.branches:
                bvc = _verdict_color(branch.verdict)
                req = ", ".join(branch.required_fields) or "-"
                filt = ", ".join(branch.filter_only_fields) or "-"
                branch_rows += f"""<tr>
                    <td style="text-align:center">{branch.index}</td>
                    <td><span style="color:{bvc};font-weight:600">{branch.verdict}</span></td>
                    <td><code style="font-size:11px">{_escape(req)}</code></td>
                    <td style="color:#6b7280;font-size:11px">{_escape(filt)}</td>
                </tr>"""
            branch_html = f"""
            <div style="margin-top:16px">
                <h4 style="color:#94a3b8;margin:0 0 8px 0;font-size:13px;text-transform:uppercase;letter-spacing:1px">Branch Analysis ({audit.branch_count} branches, {audit.resilient_branch_count} resilient)</h4>
                <table style="width:100%;border-collapse:collapse;font-size:13px">
                    <tr style="border-bottom:1px solid #2a3a52">
                        <th style="text-align:center;padding:6px;color:#94a3b8;width:50px">#</th>
                        <th style="padding:6px;color:#94a3b8">Verdict</th>
                        <th style="padding:6px;color:#94a3b8">Required fields</th>
                        <th style="padding:6px;color:#94a3b8">Filter-only</th>
                    </tr>
                    {branch_rows}
                </table>
            </div>"""

        risk_html = ""
        for detail in audit.field_risk_details:
            ac = _anchor_color(detail.anchor_class)
            strengths = "".join(f'<li style="color:#1a7f4b">{_escape(s)}</li>' for s in detail.strengths)
            limitations = "".join(f'<li style="color:#c0392b">{_escape(l)}</li>' for l in detail.limitations)
            evasion_list = ""
            if detail.evasion_techniques:
                techs = ", ".join(detail.evasion_techniques)
                evasion_list = f'<div style="margin-top:8px"><span style="color:#d97706;font-weight:600;font-size:12px">EVASION TECHNIQUES:</span> <span style="color:#e2e6ec;font-size:12px">{_escape(techs)}</span></div>'

            coverage = ""
            if detail.coverage_note:
                coverage = f'<div style="margin-top:8px;padding:8px 12px;background:#0d1520;border-left:3px solid {ac};border-radius:3px;font-size:12px;color:#94a3b8"><strong style="color:#b0c0d8">Coverage:</strong> {_escape(detail.coverage_note)}</div>'

            hardening = ""
            if detail.hardening_suggestions:
                sug_rows = ""
                for sug in detail.hardening_suggestions:
                    tac = _anchor_color(sug.target_anchor_class)
                    sug_rows += f"""<div style="margin-top:8px;padding:10px;background:#0d1520;border-radius:4px">
                        <div style="margin-bottom:6px">
                            <span style="color:#94a3b8;font-size:11px">UPGRADE TO</span>
                            <code style="color:#e2e6ec;font-size:13px;margin-left:6px">{_escape(sug.target_field)}</code>
                            <span style="background:{tac};color:#fff;padding:2px 8px;border-radius:3px;font-size:10px;margin-left:6px">{_escape(sug.target_anchor_class)}</span>
                            {_resistance_badge(sug.target_resistance)}
                        </div>
                        <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:6px">
                            <div style="padding:6px 8px;background:#1a0e0e;border-radius:3px;font-size:11px">
                                <span style="color:#c0392b;font-weight:600">BEFORE:</span><br>
                                <code style="color:#e2e6ec">{_escape(sug.example_before)}</code>
                            </div>
                            <div style="padding:6px 8px;background:#0e1a12;border-radius:3px;font-size:11px">
                                <span style="color:#1a7f4b;font-weight:600">AFTER:</span><br>
                                <code style="color:#e2e6ec">{_escape(sug.example_after)}</code>
                            </div>
                        </div>
                        <div style="margin-top:6px;font-size:11px;color:#d97706">
                            <strong>Trade-off:</strong> {_escape(sug.tradeoff)}
                        </div>
                    </div>"""
                hardening = f"""<div style="margin-top:10px">
                    <span style="color:#1d6fb5;font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:1px">Hardening Options</span>
                    {sug_rows}
                </div>"""

            risk_html += f"""
            <div style="margin-top:12px;padding:12px;background:#141e30;border-left:3px solid {ac};border-radius:4px">
                <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
                    <code style="font-size:14px;color:#e2e6ec;font-weight:600">{_escape(detail.field)}</code>
                    <span style="background:{ac};color:#fff;padding:2px 8px;border-radius:3px;font-size:11px">{_escape(detail.anchor_class)}</span>
                    {_resistance_badge(detail.resistance)}
                </div>
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
                    <div>
                        <div style="color:#1a7f4b;font-size:11px;font-weight:600;margin-bottom:4px">STRENGTHS</div>
                        <ul style="margin:0;padding-left:16px;font-size:12px;color:#b0c0d8">{strengths}</ul>
                    </div>
                    <div>
                        <div style="color:#c0392b;font-size:11px;font-weight:600;margin-bottom:4px">LIMITATIONS</div>
                        <ul style="margin:0;padding-left:16px;font-size:12px;color:#b0c0d8">{limitations}</ul>
                    </div>
                </div>
                {evasion_list}
                {coverage}
                {hardening}
            </div>"""

        risk_section = ""
        if risk_html:
            risk_section = f"""
            <div style="margin-top:16px">
                <h4 style="color:#94a3b8;margin:0 0 8px 0;font-size:13px;text-transform:uppercase;letter-spacing:1px">Field Risk Analysis</h4>
                {risk_html}
            </div>"""

        cost_html = ""
        if audit.attacker_cost.score is not None:
            band_colors = {"TRIVIAL": "#c0392b", "LOW": "#d97706", "MODERATE": "#d97706", "HIGH": "#1a7f4b", "HARDENED": "#1a7f4b"}
            bc = band_colors.get(audit.attacker_cost.band, "#6b7280")
            refs = ", ".join(audit.attacker_cost.experiment_refs) if audit.attacker_cost.experiment_refs else "discussion-only"
            pct = min(audit.attacker_cost.score / 5.0 * 100, 100)
            cost_html = f"""
            <div style="margin-top:16px;padding:12px;background:#141e30;border-radius:4px">
                <h4 style="color:#94a3b8;margin:0 0 10px 0;font-size:13px;text-transform:uppercase;letter-spacing:1px">Attacker Cost Floor</h4>
                <div style="display:flex;align-items:center;gap:12px;margin-bottom:8px">
                    <span style="background:{bc};color:#fff;padding:4px 14px;border-radius:3px;font-weight:700;font-size:14px">{_escape(audit.attacker_cost.band)}</span>
                    <span style="color:#e2e6ec;font-size:14px;font-weight:600">{_escape(audit.attacker_cost.label)}</span>
                </div>
                <div style="margin:8px 0">
                    <div style="background:#0d1520;border-radius:4px;height:10px;width:100%;position:relative">
                        <div style="background:{bc};border-radius:4px;height:10px;width:{pct:.0f}%"></div>
                    </div>
                    <div style="display:flex;justify-content:space-between;font-size:10px;color:#6b7280;margin-top:2px">
                        <span>Easy to bypass</span>
                        <span>Score: {audit.attacker_cost.score:.1f} / 5.0</span>
                        <span>Hard to bypass</span>
                    </div>
                </div>
                <div style="font-size:12px;color:#94a3b8;margin-top:4px">
                    Effort: ~{audit.attacker_cost.effort_minutes} min &middot;
                    Evidence: {_escape(audit.attacker_cost.evidence)} &middot;
                    Refs: {_escape(refs)}
                </div>
            </div>"""
        elif audit.verdict == "RESILIENT":
            cost_html = f"""
            <div style="margin-top:16px;padding:12px;background:#0e1a12;border-left:3px solid #1a7f4b;border-radius:4px">
                <span style="color:#1a7f4b;font-weight:600">No direct bypass modeled</span>
                <span style="color:#94a3b8;font-size:12px;margin-left:8px">— rule anchors are syscall and/or mount-based</span>
            </div>"""

        warn_html = ""
        if audit.warnings:
            warn_items = "".join(f'<div style="padding:4px 0;font-size:12px;color:#d97706">{_escape(w)}</div>' for w in audit.warnings)
            warn_html = f'<div style="margin-top:12px;padding:10px;background:#1a1508;border-left:3px solid #d97706;border-radius:4px">{warn_items}</div>'

        rec_color = "#1a7f4b" if audit.verdict == "RESILIENT" else "#d97706" if audit.verdict == "MIXED" else "#1d6fb5"
        rec_html = f"""
        <div style="margin-top:12px;padding:10px;background:#0d1520;border-left:3px solid {rec_color};border-radius:4px;font-size:13px;color:#b0c0d8">
            <strong style="color:{rec_color}">Recommendation:</strong> {_escape(audit.recommendation)}
        </div>"""

        condition_display = _escape(audit.expanded_condition if audit.expanded_condition != audit.condition else audit.condition)

        card = f"""
        <div id="rule-{len(rule_cards)}" style="background:#182840;border-radius:8px;padding:20px;margin-bottom:20px;border-left:4px solid {vc}">
            <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:12px">
                <div>
                    <h3 style="margin:0;color:#e2e6ec;font-size:18px">{_escape(audit.rule)}</h3>
                    <div style="color:#6b7280;font-size:12px;margin-top:4px">{_escape(src_name)} &middot; Priority: {_escape(audit.priority)} &middot; Tags: {_escape(', '.join(audit.tags))}</div>
                </div>
                <div style="text-align:right">
                    <span style="background:{vc};color:#fff;padding:6px 18px;border-radius:4px;font-weight:700;font-size:16px;letter-spacing:1px">{audit.verdict}</span>
                </div>
            </div>

            <details style="margin-bottom:12px">
                <summary style="cursor:pointer;color:#94a3b8;font-size:12px;text-transform:uppercase;letter-spacing:1px">Condition</summary>
                <pre style="margin:8px 0 0 0;padding:10px;background:#0d1520;border-radius:4px;font-size:12px;color:#b0c0d8;overflow-x:auto;white-space:pre-wrap">{condition_display}</pre>
            </details>

            <table style="width:100%;border-collapse:collapse;font-size:13px;margin-bottom:4px">
                <tr style="border-bottom:1px solid #2a3a52">
                    <th style="text-align:left;padding:6px;color:#94a3b8;font-size:11px;text-transform:uppercase;letter-spacing:1px">Field</th>
                    <th style="text-align:left;padding:6px;color:#94a3b8;font-size:11px;text-transform:uppercase;letter-spacing:1px">Anchor Class</th>
                    <th style="text-align:left;padding:6px;color:#94a3b8;font-size:11px;text-transform:uppercase;letter-spacing:1px">Resistance</th>
                </tr>
                {field_rows}
            </table>

            {branch_html}
            {risk_section}
            {cost_html}
            {warn_html}
            {rec_html}
        </div>"""
        rule_cards.append(card)

    verdict_json = json.dumps(verdicts)
    anchor_json = json.dumps(anchor_counts)

    nav_items = ""
    for i, audit in enumerate(audits):
        vc = _verdict_color(audit.verdict)
        nav_items += f'<a href="#rule-{i}" style="display:block;padding:6px 12px;color:#b0c0d8;text-decoration:none;font-size:12px;border-left:3px solid {vc};margin-bottom:2px;transition:background 0.2s" onmouseover="this.style.background=\'#1e2d44\'" onmouseout="this.style.background=\'transparent\'">{_escape(audit.rule)}<br><span style="color:{vc};font-size:10px;font-weight:600">{audit.verdict}</span></a>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Falco Rule Audit Report</title>
<style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{
        font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
        background: #0d1520;
        color: #e2e6ec;
        line-height: 1.5;
    }}
    .layout {{
        display: grid;
        grid-template-columns: 260px 1fr;
        min-height: 100vh;
    }}
    .sidebar {{
        background: #101828;
        border-right: 1px solid #1e2d44;
        padding: 20px 0;
        position: sticky;
        top: 0;
        height: 100vh;
        overflow-y: auto;
    }}
    .main {{
        padding: 30px 40px;
        max-width: 1100px;
    }}
    .kpi-grid {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
        gap: 16px;
        margin-bottom: 30px;
    }}
    .kpi {{
        background: #182840;
        border-radius: 8px;
        padding: 18px;
        text-align: center;
    }}
    .kpi-value {{
        font-size: 36px;
        font-weight: 700;
        line-height: 1.1;
    }}
    .kpi-label {{
        font-size: 12px;
        color: #94a3b8;
        margin-top: 4px;
        text-transform: uppercase;
        letter-spacing: 1px;
    }}
    .charts {{
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 20px;
        margin-bottom: 30px;
    }}
    .chart-card {{
        background: #182840;
        border-radius: 8px;
        padding: 20px;
    }}
    .chart-title {{
        color: #94a3b8;
        font-size: 13px;
        text-transform: uppercase;
        letter-spacing: 1px;
        margin-bottom: 12px;
    }}
    canvas {{ max-width: 100%; }}
    details > summary {{
        list-style: none;
    }}
    details > summary::-webkit-details-marker {{
        display: none;
    }}
    details > summary::before {{
        content: '\\25B6  ';
        font-size: 10px;
    }}
    details[open] > summary::before {{
        content: '\\25BC  ';
    }}
    @media (max-width: 900px) {{
        .layout {{ grid-template-columns: 1fr; }}
        .sidebar {{ display: none; }}
        .main {{ padding: 16px; }}
        .charts {{ grid-template-columns: 1fr; }}
    }}
</style>
</head>
<body>
<div class="layout">
    <nav class="sidebar">
        <div style="padding:0 16px 16px;border-bottom:1px solid #1e2d44;margin-bottom:12px">
            <h2 style="font-size:14px;color:#1d6fb5;text-transform:uppercase;letter-spacing:2px">Falco Rule Audit</h2>
            <div style="font-size:11px;color:#6b7280;margin-top:4px">{total} rules analysed</div>
        </div>
        {nav_items}
    </nav>
    <main class="main">
        <h1 style="font-size:28px;font-weight:700;margin-bottom:4px">Rule Audit Report</h1>
        <p style="color:#6b7280;font-size:13px;margin-bottom:24px">Detection Anchor Taxonomy Analysis &middot; Generated by falco_rule_auditor.py</p>

        <div class="kpi-grid">
            <div class="kpi">
                <div class="kpi-value" style="color:#e2e6ec">{total}</div>
                <div class="kpi-label">Total Rules</div>
            </div>
            <div class="kpi">
                <div class="kpi-value" style="color:#1a7f4b">{resilient}</div>
                <div class="kpi-label">Resilient</div>
            </div>
            <div class="kpi">
                <div class="kpi-value" style="color:#c0392b">{fragile}</div>
                <div class="kpi-label">Fragile</div>
            </div>
            <div class="kpi">
                <div class="kpi-value" style="color:#d97706">{mixed}</div>
                <div class="kpi-label">Mixed</div>
            </div>
            <div class="kpi">
                <div class="kpi-value" style="color:#e2e6ec">{fragile * 100 // total if total else 0}%</div>
                <div class="kpi-label">Fragile Rate</div>
            </div>
        </div>

        <div class="charts">
            <div class="chart-card">
                <div class="chart-title">Verdict Distribution</div>
                <canvas id="verdictChart" height="200"></canvas>
            </div>
            <div class="chart-card">
                <div class="chart-title">Anchor Class Usage</div>
                <canvas id="anchorChart" height="200"></canvas>
            </div>
        </div>

        <h2 style="font-size:20px;margin-bottom:16px;color:#b0c0d8">Rule Details</h2>
        {"".join(rule_cards)}
    </main>
</div>

<script>
// Minimal inline chart renderer — no external dependencies
(function() {{
    const verdicts = {verdict_json};
    const anchors = {anchor_json};

    function drawDonut(canvasId, data, colors) {{
        const canvas = document.getElementById(canvasId);
        const ctx = canvas.getContext('2d');
        const dpr = window.devicePixelRatio || 1;
        const rect = canvas.getBoundingClientRect();
        canvas.width = rect.width * dpr;
        canvas.height = rect.height * dpr;
        ctx.scale(dpr, dpr);

        const cx = rect.width / 2;
        const cy = rect.height / 2;
        const radius = Math.min(cx, cy) - 30;
        const innerRadius = radius * 0.55;
        const total = Object.values(data).reduce((a, b) => a + b, 0);

        let angle = -Math.PI / 2;
        const entries = Object.entries(data);
        entries.forEach(([label, value], i) => {{
            const slice = (value / total) * Math.PI * 2;
            ctx.beginPath();
            ctx.arc(cx, cy, radius, angle, angle + slice);
            ctx.arc(cx, cy, innerRadius, angle + slice, angle, true);
            ctx.closePath();
            ctx.fillStyle = colors[i % colors.length];
            ctx.fill();

            // Label
            const mid = angle + slice / 2;
            const lx = cx + (radius + 18) * Math.cos(mid);
            const ly = cy + (radius + 18) * Math.sin(mid);
            ctx.fillStyle = '#b0c0d8';
            ctx.font = '11px Segoe UI, sans-serif';
            ctx.textAlign = Math.cos(mid) > 0 ? 'left' : 'right';
            ctx.textBaseline = 'middle';
            ctx.fillText(label + ' (' + value + ')', lx, ly);

            angle += slice;
        }});

        // Center text
        ctx.fillStyle = '#e2e6ec';
        ctx.font = 'bold 24px Segoe UI, sans-serif';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(total, cx, cy - 6);
        ctx.fillStyle = '#6b7280';
        ctx.font = '11px Segoe UI, sans-serif';
        ctx.fillText('rules', cx, cy + 14);
    }}

    function drawBar(canvasId, data, colors) {{
        const canvas = document.getElementById(canvasId);
        const ctx = canvas.getContext('2d');
        const dpr = window.devicePixelRatio || 1;
        const rect = canvas.getBoundingClientRect();
        canvas.width = rect.width * dpr;
        canvas.height = rect.height * dpr;
        ctx.scale(dpr, dpr);

        const entries = Object.entries(data);
        const maxVal = Math.max(...Object.values(data), 1);
        const barH = 28;
        const gap = 8;
        const labelW = 120;
        const chartW = rect.width - labelW - 50;
        const startY = 10;

        entries.forEach(([label, value], i) => {{
            const y = startY + i * (barH + gap);
            const w = (value / maxVal) * chartW;

            // Bar
            ctx.fillStyle = colors[i % colors.length];
            ctx.beginPath();
            ctx.roundRect(labelW, y, w, barH, 4);
            ctx.fill();

            // Label
            ctx.fillStyle = '#b0c0d8';
            ctx.font = '11px Segoe UI, sans-serif';
            ctx.textAlign = 'right';
            ctx.textBaseline = 'middle';
            const shortLabel = label.replace('-anchored', '');
            ctx.fillText(shortLabel, labelW - 8, y + barH / 2);

            // Value
            ctx.fillStyle = '#e2e6ec';
            ctx.font = 'bold 12px Segoe UI, sans-serif';
            ctx.textAlign = 'left';
            ctx.fillText(value, labelW + w + 8, y + barH / 2);
        }});
    }}

    drawDonut('verdictChart', verdicts, ['#1a7f4b', '#c0392b', '#d97706', '#6b7280']);
    drawBar('anchorChart', anchors, ['#1767a0', '#1a7f4b', '#c0392b', '#d97706', '#6b7280']);
}})();
</script>
</body>
</html>"""

    Path(output_path).write_text(html, encoding="utf-8")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Audit Falco rules against the detection-anchor taxonomy."
    )
    parser.add_argument(
        "inputs",
        nargs="+",
        help="YAML file(s) or directories to audit",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json", "csv", "html"),
        default="text",
        help="Output format (html writes to --output path)",
    )
    parser.add_argument(
        "--field-map",
        default=str(DEFAULT_FIELD_MAP),
        help="Path to taxonomy/field_classification.yaml",
    )
    parser.add_argument(
        "--anchor-classes",
        default=str(DEFAULT_ANCHOR_CLASSES),
        help="Path to taxonomy/anchor_classes.yaml",
    )
    parser.add_argument(
        "--attack-technique-costs",
        default=str(DEFAULT_ATTACK_TECHNIQUE_COSTS),
        help="Path to taxonomy/attack_technique_costs.yaml",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Output file path (required for html format, optional for others)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    try:
        audits = audit_paths(
            [Path(item).resolve() for item in args.inputs],
            field_map_path=Path(args.field_map).resolve(),
            anchor_classes_path=Path(args.anchor_classes).resolve(),
            attack_technique_costs_path=Path(args.attack_technique_costs).resolve(),
        )
    except Exception as exc:  # pragma: no cover - thin CLI wrapper
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.format == "html":
        out_path = args.output or "audit_report.html"
        emit_html(audits, out_path)
        print(f"HTML report saved to {out_path}")
        return 0

    if args.format == "json":
        json.dump(to_json_ready(audits), sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0

    if args.format == "csv":
        emit_csv(audits, sys.stdout)
        return 0

    rule_blocks = [render_rule(audit) for audit in audits]
    if rule_blocks:
        sys.stdout.write("\n\n".join(rule_blocks))
        sys.stdout.write("\n\n")
    sys.stdout.write(render_summary(audits))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
