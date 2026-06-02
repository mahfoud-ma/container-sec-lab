#!/usr/bin/env python3
"""Unit tests for the Falco rule auditor."""

from __future__ import annotations

import unittest
from pathlib import Path

from auditor.falco_rule_auditor import (
    ParsedRule,
    analyze_rule,
    audit_paths,
    expand_macros_in_condition,
    load_attack_technique_costs,
    load_anchor_classes,
    load_field_classification,
)


ROOT = Path(__file__).resolve().parents[1]
FIELD_MAP_PATH = ROOT / "taxonomy" / "field_classification.yaml"
ANCHOR_CLASSES_PATH = ROOT / "taxonomy" / "anchor_classes.yaml"
ATTACKER_COSTS_PATH = ROOT / "taxonomy" / "attack_technique_costs.yaml"


class FalcoRuleAuditorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.field_map = load_field_classification(FIELD_MAP_PATH)
        cls.anchor_metadata = load_anchor_classes(ANCHOR_CLASSES_PATH)
        cls.attacker_costs = load_attack_technique_costs(ATTACKER_COSTS_PATH)

    def make_rule(self, condition: str, name: str = "Synthetic Rule") -> ParsedRule:
        return ParsedRule(
            name=name,
            condition=condition,
            priority="CRITICAL",
            tags=["unit-test"],
            source="synthetic.yaml",
        )

    def test_evt_type_setns_is_resilient(self) -> None:
        audit = analyze_rule(
            self.make_rule("evt.type=setns"),
            self.field_map,
            self.anchor_metadata,
            self.attacker_costs,
        )
        self.assertEqual(["evt.type"], [usage.field for usage in audit.fields])
        self.assertEqual("syscall-anchored", audit.weakest_anchor)
        self.assertEqual("RESILIENT", audit.verdict)
        self.assertIsNone(audit.attacker_cost.technique)

    def test_proc_name_nsenter_is_fragile(self) -> None:
        audit = analyze_rule(
            self.make_rule("proc.name=nsenter"),
            self.field_map,
            self.anchor_metadata,
            self.attacker_costs,
        )
        self.assertEqual("name-anchored", audit.weakest_anchor)
        self.assertEqual("FRAGILE", audit.verdict)
        self.assertEqual("binary_rename", audit.attacker_cost.technique)

    def test_fd_name_docker_sock_is_path_fragile(self) -> None:
        audit = analyze_rule(
            self.make_rule('fd.name contains "docker.sock"'),
            self.field_map,
            self.anchor_metadata,
            self.attacker_costs,
        )
        self.assertEqual("path-anchored", audit.weakest_anchor)
        self.assertEqual("FRAGILE", audit.verdict)
        self.assertEqual([], audit.unknown_fields)
        self.assertEqual("symlink", audit.attacker_cost.technique)

    def test_container_mounts_docker_sock_is_resilient(self) -> None:
        audit = analyze_rule(
            self.make_rule('container.mounts contains "docker.sock"'),
            self.field_map,
            self.anchor_metadata,
            self.attacker_costs,
        )
        self.assertEqual("mount-anchored", audit.weakest_anchor)
        self.assertEqual("RESILIENT", audit.verdict)
        self.assertEqual("HARDENED", audit.attacker_cost.band)

    def test_and_condition_uses_weakest_link(self) -> None:
        audit = analyze_rule(
            self.make_rule("evt.type=setns and proc.name=nsenter"),
            self.field_map,
            self.anchor_metadata,
            self.attacker_costs,
        )
        self.assertEqual("name-anchored", audit.weakest_anchor)
        self.assertEqual("FRAGILE", audit.verdict)

    def test_real_rule_file_parses_all_rules(self) -> None:
        audits = audit_paths([ROOT / "falco" / "rules.d" / "30-setns-or-nsenter.yaml"])
        self.assertEqual(3, len(audits))

    def test_real_setns_nsenter_results_match_taxonomy(self) -> None:
        audits = audit_paths([ROOT / "falco" / "rules.d" / "30-setns-or-nsenter.yaml"])
        by_name = {audit.rule: audit for audit in audits}

        self.assertEqual("RESILIENT", by_name["Container Calling setns Syscall"].verdict)
        self.assertEqual("syscall-anchored", by_name["Container Calling setns Syscall"].weakest_anchor)
        self.assertEqual(2, by_name["Container Calling setns Syscall"].resilient_branch_count)

        self.assertEqual("RESILIENT", by_name["Container Calling unshare Syscall"].verdict)
        self.assertEqual("syscall-anchored", by_name["Container Calling unshare Syscall"].weakest_anchor)

        self.assertEqual("FRAGILE", by_name["Container Using nsenter"].verdict)
        self.assertEqual("name-anchored", by_name["Container Using nsenter"].weakest_anchor)

    def test_or_with_independent_strong_branch_is_mixed(self) -> None:
        audit = analyze_rule(
            self.make_rule("evt.type=setns or proc.name=nsenter"),
            self.field_map,
            self.anchor_metadata,
            self.attacker_costs,
        )
        self.assertEqual("MIXED", audit.verdict)
        self.assertEqual(1, audit.resilient_branch_count)
        self.assertEqual(2, audit.branch_count)

    def test_macro_expansion_exposes_hidden_fields(self) -> None:
        expanded = expand_macros_in_condition(
            "spawned_process and open_write and container",
            {
                "spawned_process": "(evt.type in (execve, execveat))",
                "open_write": "(evt.type in (open, openat) and evt.is_open_write=true)",
                "container": "(container.id != host)",
            },
        )
        self.assertIn("evt.type", expanded)
        self.assertIn("evt.is_open_write", expanded)
        self.assertIn("container.id", expanded)

    def test_field_risk_details_present_for_fragile_rule(self) -> None:
        audit = analyze_rule(
            self.make_rule('fd.name contains "docker.sock"'),
            self.field_map,
            self.anchor_metadata,
            self.attacker_costs,
        )
        self.assertTrue(len(audit.field_risk_details) >= 1)
        fd_detail = next(d for d in audit.field_risk_details if d.field == "fd.name")
        self.assertEqual("path-anchored", fd_detail.anchor_class)
        self.assertEqual("LOW", fd_detail.resistance)
        self.assertTrue(len(fd_detail.limitations) > 0)
        self.assertTrue(len(fd_detail.evasion_techniques) > 0)
        self.assertIn("symlink", fd_detail.evasion_techniques)

    def test_field_risk_details_have_hardening_suggestions(self) -> None:
        audit = analyze_rule(
            self.make_rule("proc.name=nsenter"),
            self.field_map,
            self.anchor_metadata,
            self.attacker_costs,
        )
        name_detail = next(d for d in audit.field_risk_details if d.field == "proc.name")
        self.assertTrue(len(name_detail.hardening_suggestions) > 0)
        first_sug = name_detail.hardening_suggestions[0]
        self.assertEqual("HIGH", first_sug.target_resistance)
        self.assertTrue(len(first_sug.tradeoff) > 0)
        self.assertTrue(len(first_sug.example_before) > 0)
        self.assertTrue(len(first_sug.example_after) > 0)

    def test_resilient_rule_has_no_hardening_suggestions(self) -> None:
        audit = analyze_rule(
            self.make_rule("evt.type=setns"),
            self.field_map,
            self.anchor_metadata,
            self.attacker_costs,
        )
        for detail in audit.field_risk_details:
            self.assertEqual([], detail.hardening_suggestions)
            self.assertEqual([], detail.evasion_techniques)

    def test_field_risk_details_skip_metadata_fields(self) -> None:
        audit = analyze_rule(
            self.make_rule("container.id != host and evt.type=setns"),
            self.field_map,
            self.anchor_metadata,
            self.attacker_costs,
        )
        detail_fields = [d.field for d in audit.field_risk_details]
        self.assertNotIn("container.id", detail_fields)
        self.assertIn("evt.type", detail_fields)

    def test_html_output_generates_file(self) -> None:
        import tempfile
        audits = audit_paths([ROOT / "falco" / "rules.d" / "30-setns-or-nsenter.yaml"])
        from auditor.falco_rule_auditor import emit_html
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            emit_html(audits, f.name)
            html = Path(f.name).read_text()
            self.assertIn("Falco Rule Audit Report", html)
            self.assertIn("Container Calling setns Syscall", html)
            self.assertIn("RESILIENT", html)
            self.assertIn("FRAGILE", html)
            self.assertIn("verdictChart", html)
            Path(f.name).unlink()

    @unittest.skipUnless(Path("/etc/falco/falco_rules.yaml").exists(), "requires local Falco rules file")
    def test_upstream_ruleset_audits_with_broad_coverage(self) -> None:
        audits = audit_paths([Path("/etc/falco/falco_rules.yaml")])
        verdicts = {}
        for audit in audits:
            verdicts[audit.verdict] = verdicts.get(audit.verdict, 0) + 1

        self.assertGreaterEqual(len(audits), 20)
        self.assertGreaterEqual(verdicts.get("RESILIENT", 0), 6)
        self.assertGreaterEqual(verdicts.get("FRAGILE", 0), 8)
        self.assertLessEqual(verdicts.get("UNKNOWN", 0), 2)


if __name__ == "__main__":
    unittest.main()
