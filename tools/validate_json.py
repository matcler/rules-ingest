from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional, Iterable, Tuple, Any, Dict

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource


def eprint(*args: object) -> None:
    print(*args, file=sys.stderr)


def load_text(path: Path) -> str:
    return path.read_text(encoding="utf-8-sig")


def load_json(path: Path) -> object:
    return json.loads(load_text(path))


def build_registry(repo_root: Path) -> Registry:
    """Build a registry from all schemas in ./schemas so $id references can resolve."""
    schemas_dir = repo_root / "schemas"
    registry = Registry()

    if schemas_dir.exists():
        for p in schemas_dir.rglob("*.json"):
            try:
                doc = load_json(p)
                if isinstance(doc, dict) and isinstance(doc.get("$id"), str):
                    res = Resource.from_contents(doc)
                    registry = registry.with_resource(doc["$id"], res)
            except Exception as ex:
                eprint(f"[WARN] Unable to index schema '{p}': {ex}")

    return registry


def collect_files(paths: List[str]) -> List[Path]:
    out: List[Path] = []
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            out.extend(
                [x for x in p.rglob("*") if x.is_file() and x.suffix.lower() in (".json", ".jsonl")]
            )
        elif p.is_file():
            out.append(p)
        else:
            eprint(f"[WARN] Path not found: {raw}")
    return out


def iter_jsonl(path: Path) -> Iterable[Tuple[int, object]]:
    """Yield (line_number, parsed_object). Ignores empty/whitespace-only lines."""
    for i, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), start=1):
        if not line.strip():
            continue
        yield i, json.loads(line)


def validate_one(validator: Draft202012Validator, data: object, label: str) -> List[str]:
    errors = sorted(validator.iter_errors(data), key=lambda e: list(e.absolute_path))
    msgs: List[str] = []
    for err in errors:
        path = ".".join([str(p) for p in err.absolute_path]) or "<root>"
        msgs.append(f"{label}: {path}: {err.message}")
    return msgs


def lint_rule(data: Any, file_path: Path) -> List[str]:
    """Minimal architectural lint for mass extraction (null-safe)."""
    msgs: List[str] = []

    if not isinstance(data, dict):
        return msgs

    scenario = data.get("scenario")
    if not scenario:
        msgs.append(f"{file_path}: <root>: missing required field: scenario")
        return msgs

    # Only lint legality rules for now (guard-rail)
    is_legality = "rules/legality" in file_path.as_posix().replace("\\", "/")
    if not is_legality:
        return msgs

    constraints = data.get("constraints")
    if constraints is None:
        constraints = []
    if not isinstance(constraints, list):
        msgs.append(f"{file_path}: constraints: expected array")
        return msgs

    # Scenario 1 must not include ranged/LoS gating
    if scenario == "SCENARIO_1":
        banned = {"requires_line_of_sight", "requires_range_max"}
        for i, c in enumerate(constraints):
            if isinstance(c, dict) and c.get("type") in banned:
                msgs.append(
                    f"{file_path}: constraints[{i}].type: '{c.get('type')}' not allowed in SCENARIO_1"
                )

    return msgs


def lint_atoms(data: Any, file_path: Path, atoms_registry_types: Dict[str, Any]) -> List[str]:
    """Validate atoms against atoms_registry.json (null-safe)."""
    msgs: List[str] = []

    if not isinstance(data, dict):
        return msgs

    # Accept either a single atom object (has atomType) OR a bundle {kind:"atoms", atoms:[...]}
    atoms: List[Any] = []
    scenario = data.get("scenario")

    if "atomType" in data:
        atoms = [data]
    elif data.get("kind") == "atoms" and isinstance(data.get("atoms"), list):
        atoms = data.get("atoms", [])

    if not atoms:
        return msgs

    for i, atom in enumerate(atoms):
        atom_label = f"{file_path}: atoms[{i}]" if "atomType" not in data else f"{file_path}: <root>"

        if not isinstance(atom, dict):
            msgs.append(f"{atom_label}: expected object")
            continue

        atom_type = atom.get("atomType")
        if not atom_type:
            msgs.append(f"{atom_label}.atomType: missing required field")
            continue

        registry_entry = atoms_registry_types.get(atom_type)
        if not registry_entry:
            msgs.append(f"{atom_label}.atomType: '{atom_type}' not in atoms_registry")
            continue

        # Scenario gating (MVP policy)
        if scenario == "SCENARIO_1" and atom_type == "REQUIRES_ADJACENT_TARGET":
            msgs.append(f"{atom_label}.atomType: '{atom_type}' not allowed in SCENARIO_1")

        required_fields = registry_entry.get("requiredFields", [])
        if isinstance(required_fields, list):
            for field in required_fields:
                if isinstance(field, str) and field not in atom:
                    msgs.append(f"{atom_label}.{field}: missing required field")

        applies_to = atom.get("appliesTo")
        if not isinstance(applies_to, dict):
            msgs.append(f"{atom_label}.appliesTo: missing required field")
        else:
            allowed_applies = registry_entry.get("appliesTo", {})
            allowed_event_types = allowed_applies.get("eventType") if isinstance(allowed_applies, dict) else None
            event_type = applies_to.get("eventType")

            if isinstance(allowed_event_types, list) and event_type not in allowed_event_types:
                msgs.append(f"{atom_label}.appliesTo.eventType: '{event_type}' not allowed")

            action_type = applies_to.get("actionType")
            allowed_action_types = allowed_applies.get("actionType") if isinstance(allowed_applies, dict) else None

            if allowed_action_types is None:
                # registry says: no actionType allowed (except null/omitted)
                if "actionType" in applies_to and action_type is not None:
                    msgs.append(f"{atom_label}.appliesTo.actionType: not allowed for this atomType")
            elif isinstance(allowed_action_types, list):
                if action_type not in allowed_action_types:
                    msgs.append(f"{atom_label}.appliesTo.actionType: '{action_type}' not allowed")

        enforcement = atom.get("enforcement")
        if not isinstance(enforcement, dict):
            msgs.append(f"{atom_label}.enforcement: missing required field")
        else:
            deny_code = enforcement.get("denyCode")
            details_reason = enforcement.get("detailsReason")
            if_data_missing = enforcement.get("ifDataMissing")

            if deny_code is None:
                msgs.append(f"{atom_label}.enforcement.denyCode: missing required field")
            if details_reason is None:
                msgs.append(f"{atom_label}.enforcement.detailsReason: missing required field")
            if if_data_missing is None:
                msgs.append(f"{atom_label}.enforcement.ifDataMissing: missing required field")

            registry_enforcement = registry_entry.get("enforcement", {})
            if isinstance(registry_enforcement, dict):
                registry_deny = registry_enforcement.get("denyCode")
                if registry_deny and deny_code != registry_deny:
                    msgs.append(
                        f"{atom_label}.enforcement.denyCode: '{deny_code}' does not match registry"
                    )

            if if_data_missing != "DENY":
                msgs.append(f"{atom_label}.enforcement.ifDataMissing: must be DENY for MVP atoms")

        params_rules = registry_entry.get("params", {})
        if isinstance(params_rules, dict) and params_rules.get("allowed"):
            if "params" in atom:
                params = atom.get("params")
                if not isinstance(params, dict):
                    msgs.append(f"{atom_label}.params: expected object")
                else:
                    allowed_keys = params_rules.get("allowedKeys", [])
                    if isinstance(allowed_keys, list):
                        extra_keys = [k for k in params.keys() if k not in allowed_keys]
                        if extra_keys:
                            msgs.append(f"{atom_label}.params: keys not allowed: {extra_keys}")
                        if "phase" in allowed_keys:
                            phase_value = params.get("phase")
                            if phase_value is None:
                                msgs.append(f"{atom_label}.params.phase: missing required field")
                            elif not isinstance(phase_value, str):
                                msgs.append(f"{atom_label}.params.phase: expected string")
        else:
            if "params" in atom:
                msgs.append(f"{atom_label}.params: not allowed for this atomType")

    return msgs


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate .json or .jsonl files against a JSON Schema (draft 2020-12)."
    )
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument(
        "--schema",
        help="Path to schema JSON file (e.g. schemas/structured.schema.json)",
    )
    mode_group.add_argument(
        "--rules",
        action="store_true",
        help="Validate rules/legality, rules/triggers, and rules/transitions against their schemas.",
    )
    mode_group.add_argument(
        "--atoms",
        action="store_true",
        help="Validate atoms bundles/objects against atoms_registry.json (lint-only by default).",
    )
    parser.add_argument(
        "paths",
        nargs="*",
        help="Files or directories to validate (.json/.jsonl). Directories are searched recursively.",
    )
    args = parser.parse_args(argv)

    repo_root = Path(__file__).resolve().parents[1]
    registry = build_registry(repo_root)
    all_errors: List[str] = []

    # Load atoms registry (optional)
    atoms_registry_path = repo_root / "atoms_registry.json"
    atoms_registry_types: Dict[str, Any] = {}
    if atoms_registry_path.exists():
        try:
            atoms_registry = load_json(atoms_registry_path)
            if isinstance(atoms_registry, dict):
                atom_types = atoms_registry.get("atomTypes", {})
                if isinstance(atom_types, dict):
                    atoms_registry_types = atom_types  # type: ignore[assignment]
        except Exception as ex:
            all_errors.append(
                f"[ERROR] Failed to parse atoms registry '{atoms_registry_path}': {ex}"
            )

    def validate_schema(schema_path: Path, paths: List[Path], allow_empty: bool) -> None:
        if not schema_path.exists():
            all_errors.append(f"[ERROR] Schema not found: {schema_path}")
            return
        try:
            schema_doc = load_json(schema_path)
        except Exception as ex:
            all_errors.append(f"[ERROR] Failed to parse schema '{schema_path}': {ex}")
            return

        validator = Draft202012Validator(schema_doc, registry=registry, format_checker=FormatChecker())
        files = collect_files([str(p) for p in paths])

        if not files:
            msg = f"[WARN] No .json/.jsonl files found to validate for {schema_path}."
            if allow_empty:
                eprint(msg)
                return
            all_errors.append(msg)
            return

        for f in files:
            ext = f.suffix.lower()
            try:
                if ext == ".json":
                    data = load_json(f)
                    all_errors.extend(validate_one(validator, data, str(f)))
                    all_errors.extend(lint_rule(data, f))
                    all_errors.extend(lint_atoms(data, f, atoms_registry_types))
                elif ext == ".jsonl":
                    for line_no, obj in iter_jsonl(f):
                        label = f"{f}#L{line_no}"
                        all_errors.extend(validate_one(validator, obj, label))
                        all_errors.extend(lint_rule(obj, f))
                        all_errors.extend(lint_atoms(obj, f, atoms_registry_types))
            except json.JSONDecodeError as ex:
                all_errors.append(f"{f}: JSON parse error: {ex}")
            except Exception as ex:
                all_errors.append(f"{f}: Unexpected error: {ex}")
    if args.atoms:
        # Atoms lint-only pass. Default to ./dist if no paths provided.
        atom_paths = [repo_root / "dist"] if not args.paths else [Path(p) for p in args.paths]
        files = collect_files([str(p) for p in atom_paths])
        if not files:
            eprint("[WARN] No .json/.jsonl files found to validate for atoms.")
        else:
            for f in files:
                ext = f.suffix.lower()
                try:
                    if ext == ".json":
                        data = load_json(f)
                        all_errors.extend(lint_atoms(data, f, atoms_registry_types))
                    elif ext == ".jsonl":
                        for line_no, obj in iter_jsonl(f):
                            all_errors.extend(lint_atoms(obj, f, atoms_registry_types))
                except json.JSONDecodeError as ex:
                    all_errors.append(f"{f}: JSON parse error: {ex}")
                except Exception as ex:
                    all_errors.append(f"{f}: Unexpected error: {ex}")

    elif args.rules:

        rule_sets = [
            (repo_root / "schemas" / "rules.legality.schema.json", [repo_root / "rules" / "legality"]),
            (repo_root / "schemas" / "rules.triggers.schema.json", [repo_root / "rules" / "triggers"]),
            (repo_root / "schemas" / "rules.transitions.schema.json", [repo_root / "rules" / "transitions"]),
        ]
        for schema_path, paths in rule_sets:
            validate_schema(schema_path, paths, allow_empty=True)
    else:
        if not args.paths:
            eprint("[ERROR] No .json/.jsonl files found to validate.")
            return 2
        schema_path = Path(args.schema).resolve()
        validate_schema(schema_path, [Path(p) for p in args.paths], allow_empty=False)

    if all_errors:
        eprint("VALIDATION FAILED")
        for msg in all_errors:
            eprint(" - " + msg)
        return 1

    print("VALIDATION OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
