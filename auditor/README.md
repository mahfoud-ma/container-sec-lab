# Falco Rule Auditor

This tool audits Falco rules using the detection-anchor taxonomy in `taxonomy/`.

## What it does

- Loads Falco rule YAML from a file or a rules directory
- Extracts known Falco condition fields from each rule
- Maps each field to an anchor class from `taxonomy/field_classification.yaml`
- Applies weakest-link analysis across `AND` branches
- Detects independently resilient `OR` branches
- Emits human-readable text, JSON, CSV, or HTML output

## Usage

Audit one file:

```bash
python3 auditor/falco_rule_auditor.py falco/rules.d/10-dockersock.yaml
```

Audit the active rules directory:

```bash
python3 auditor/falco_rule_auditor.py falco/rules.d/
```

Export machine-readable results:

```bash
python3 auditor/falco_rule_auditor.py falco/rules.d/ --format json
python3 auditor/falco_rule_auditor.py falco/rules.d/ --format csv
python3 auditor/falco_rule_auditor.py falco/rules.d/ --format html -o audit_report.html
```

Run tests:

```bash
python3 -m unittest auditor.test_auditor
```

## Interpretation

- `RESILIENT`: every reachable branch is anchored only on high-resistance fields (`syscall-anchored` and/or `mount-anchored`)
- `FRAGILE`: every reachable branch still depends on at least one low-resistance field (`name-anchored` or `path-anchored`)
- `MIXED`: at least one branch is resilient, but at least one alternative branch is still fragile

`Filter-only fields` are fields that appear only in negated allowlist logic such as `not proc.cmdline startswith "runc:["`. They are reported for transparency, but they do not define the rule's primary anchor classification.

The auditor also reports an `Attacker cost floor`, which is a lightweight lower-bound estimate of the cheapest modeled bypass associated with any low-resistance anchor present in the rule.
