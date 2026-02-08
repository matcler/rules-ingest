# source.ref convention (SRD 5.2.1)

This repository uses **dot notation** for `source.ref` to provide a stable, SRD-oriented anchor for every extracted rule.

## Goals

- **Stable** across extraction methods (manual / LLM).
- **Human-readable** and easy to type.
- **Versioned via `source.corpus`**, not via the ref itself.
- **No implicit architecture**: `source.ref` is metadata only.

## `source.corpus`

Use an explicit corpus identifier:

- `SRD_5E_5.2.1_EN`
- `SRD_5E_5.2.1_IT`

(Other corpora are allowed, but must be uppercase and stable.)

## `source.ref` format

**Pattern** (enforced by schema):

- lowercase
- snake_case segments
- dot-separated hierarchy

Examples:

- `combat.melee_attack`
- `combat.opportunity_attack`
- `conditions.grappled`
- `spellcasting.concentration`
- `spells.ray_of_frost`

## How to choose the segments

Build the ref from the SRD **heading hierarchy**:

1. **Top-level domain**: the SRD chapter or major section (e.g. `combat`, `spellcasting`, `equipment`, `conditions`, `spells`).
2. **Subsections**: append one segment per heading level, in order.
3. **Leaf**: for an atomic rule, the leaf should name the smallest SRD section that fully contains the rule.

## Normalization rules

- Convert headings to lowercase.
- Replace spaces with `_`.
- Remove punctuation (keep only letters, digits, `_`).
- Avoid abbreviations unless they appear in SRD headings.

## Collisions and disambiguation

If two different SRD headings normalize to the same ref, disambiguate by appending a short qualifier:

- `combat.cover_half`
- `combat.cover_three_quarters`

Keep qualifiers SRD-native and minimal.

## Relationship to rule `id`

Recommended (not enforced):

- `id = <corpus_short>.<source.ref>`

Example:

- `id: srd.combat.melee_attack`
- `source.corpus: SRD_5E_5.2.1_EN`
- `source.ref: combat.melee_attack`
