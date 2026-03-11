# Rules-Ingest

`rules-ingest` is a data-only, opt-in repository for SRD rule ingestion and normalization.

It does not implement gameplay logic, mutate the Rule Engine contract, or integrate automatically with `sss-backend` or `rule-engine-backend`.

## Repository Role

The repository exists to:

- track SRD source material and extraction work
- normalize selected rule slices into structured JSON and atoms
- version a small canonical dataset with repeatable validation
- publish distributable JSON artifacts without introducing runtime side effects

## Architectural Boundary

These constraints are mandatory:

- data-only and opt-in
- no automatic integration with `sss-backend`
- no automatic integration with `rule-engine-backend`
- no gameplay logic
- no runtime side effects
- no cross-repo coupling beyond schemas and data files stored here

## Content Taxonomy

The repository intentionally separates tracked material by role.

- `source tracked`
  - `asset/pdfs/ENG-SRD_CC_v5.2.1.pdf`
  - `ingest/text/`
  - `ingest/candidates/`
  - tracked SRD source material and extracted candidate inputs; stable to keep, but not the canonical dataset
- `intermediate / generated`
  - `extraction/structured/`
  - `ingest/reports/`
  - `ingest/atoms/pages_0010_0025.atoms.json`
  - `ingest/atoms/pages_0010_0025_v2.atoms.json`
  - `ingest/atoms/pages_0028_0046.atoms.json`
  - `ingest/atoms/pages_0104_0106.atoms.json`
  - `ingest/atoms/poison_spray.variant_A.atoms.json`
  - working outputs and validation fixtures that can be regenerated or replaced
- `canonical dataset`
  - `ingest/atoms/combat.mvp.atoms.json`
  - the official minimal source-of-truth dataset tracked for stable versioning in this repo
- `distributable artifact`
  - `dist/atoms.bundle.json`
  - `dist/atoms.index.json`
  - publishable bundle and lookup index derived from the canonical dataset

The machine-readable source for this taxonomy and baseline is [dataset_baseline.json](/home/matte/dev/rules-ingest/dataset_baseline.json).

## Official Minimal Baseline

Baseline name: `combat-mvp-minimal-v1`

This baseline is intentionally small:

- one structured validation fixture
  - `extraction/structured/srd.spell.ray_of_frost.json`
- one canonical atoms dataset
  - `ingest/atoms/combat.mvp.atoms.json`
- two distributable artifacts derived from that dataset
  - `dist/atoms.bundle.json`
  - `dist/atoms.index.json`

Why this baseline:

- it is small enough to maintain by hand
- it exercises both canonical schemas
- it exercises every atom type currently declared in `atoms_registry.json`
- it freezes a single canonical path in `ingest/` instead of treating the whole tree as stable API

## What To Version Stable vs Regenerate

Version stable:

- `schemas/`
- `atoms_registry.json`
- [dataset_baseline.json](/home/matte/dev/rules-ingest/dataset_baseline.json)
- [docs/dataset_governance.md](/home/matte/dev/rules-ingest/docs/dataset_governance.md)
- `ingest/atoms/combat.mvp.atoms.json`
- `dist/atoms.bundle.json`
- `dist/atoms.index.json`

May be regenerated or replaced as working material:

- `ingest/reports/`
- page-sliced atoms bundles under `ingest/atoms/` that are not listed above
- `extraction/structured/` outputs beyond the documented validation fixture
- candidate and text slices when the extraction workflow is rerun

## Recommended Validation Commands

Set up a local Python environment once:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

Run the canonical governance check:

```bash
.venv/bin/python tools/validate_json.py --baseline
```

Useful focused checks:

```bash
.venv/bin/python tools/validate_json.py --atoms ingest/atoms/combat.mvp.atoms.json dist
.venv/bin/python tools/validate_json.py --schema schemas/structured.schema.json extraction/structured/srd.spell.ray_of_frost.json
.venv/bin/python tools/validate_json.py --rules
```

## Governance Reference

See [docs/dataset_governance.md](/home/matte/dev/rules-ingest/docs/dataset_governance.md) for the human-readable policy and [dataset_baseline.json](/home/matte/dev/rules-ingest/dataset_baseline.json) for the repeatable baseline contract used by `tools/validate_json.py --baseline`.
