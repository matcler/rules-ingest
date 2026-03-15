# Dataset Governance

## Scope

`rules-ingest` stays data-only and opt-in.

This repository:

- versions SRD-oriented source material and derived JSON datasets
- does not execute gameplay
- does not mutate the Rule Engine contract
- does not integrate automatically with `sss-backend`
- does not integrate automatically with `rule-engine-backend`

## Path Classification

### Source tracked

These paths are tracked because they are useful inputs to the local extraction workflow, not because they are the canonical dataset:

- `asset/pdfs/ENG-SRD_CC_v5.2.1.pdf`
- `ingest/text/`
- `ingest/candidates/`

### Intermediate / generated

These paths are kept for inspection and local iteration, but they are not the stable source-of-truth surface:

- `extraction/structured/`
- `ingest/reports/`
- page-scoped working bundles in `ingest/atoms/`, except the baseline file explicitly listed below

### Canonical dataset

The official minimal canonical dataset is:

- `ingest/atoms/combat.mvp.atoms.json`

This file is the only dataset under `ingest/` that is currently frozen as stable and versioned by policy.

### Distributable artifact

The distributable baseline is:

- `dist/atoms.bundle.json`
- `dist/atoms.index.json`

These are derived, versioned artifacts. They are validated for consistency, but they remain opt-in data outputs, not runtime integration points.

## Official Baseline

Baseline name: `combat-mvp-minimal-v1`

Included paths:

- structured fixture: `extraction/structured/srd.spell.ray_of_frost.json`
- canonical dataset: `ingest/atoms/combat.mvp.atoms.json`
- distributable artifacts:
  - `dist/atoms.bundle.json`
  - `dist/atoms.index.json`

The baseline is intentionally narrow. It exists to keep one minimal dataset stable and understandable, not to declare the whole repository canonical.

## Maintenance Invariants

- Only paths listed in `dataset_baseline.json` count as the official minimal baseline.
- `ingest/atoms/combat.mvp.atoms.json` is the source-of-truth dataset for the current baseline.
- `dist/atoms.bundle.json` must remain a derived copy of the canonical baseline atoms.
- `dist/atoms.index.json` must remain consistent with `dist/atoms.bundle.json`.
- `pathClasses.canonical_dataset` must exactly match `baseline.canonicalAtomsBundles`.
- `pathClasses.distributable_artifact` must exactly match `baseline.distributableArtifacts`.
- `distributableArtifacts.bundle.derivedFrom` must point only to the declared canonical dataset paths.
- canonical atom types must remain covered by both `atoms_registry.json` and `schemas/atoms.schema.json`.
- The structured fixture is only a schema guardrail. It is not a runtime dataset and not an integration contract.
- Everything in this repository remains opt-in. Nothing here is imported automatically by runtime repos.

## Canonical Gate

Canonical local pre-push path:

```bash
make gate-baseline
```

Canonical CI path:

```bash
make gate-baseline-ci
```

Both paths execute the same essential verification sequence and fail loudly if:

- `dataset_baseline.json` declares inconsistent canonical paths
- `dist/` diverges from the canonical minimal dataset
- canonical atom types drift out of registry/schema coverage
- rules/schema validation or baseline validation is skipped from the gate path

Optional repo-local hook installation:

```bash
make install-hooks
```

## Onboarding

A new collaborator should use this order:

1. Read `README.md`.
2. Read `docs/dataset_governance.md`.
3. Inspect `dataset_baseline.json`.
4. Run `python3 tools/validate_json.py --baseline` in a Python environment with `requirements.txt` installed.

If the canonical baseline needs to grow, extend it by adding a small, named dataset slice and update both the governance doc and `dataset_baseline.json` in the same change.
