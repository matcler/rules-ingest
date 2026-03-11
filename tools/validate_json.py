from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, DefaultDict, Dict, Iterable, List, Optional, Sequence, Tuple

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


def load_validator(schema_path: Path, registry: Registry) -> Draft202012Validator:
    schema_doc = load_json(schema_path)
    if not isinstance(schema_doc, dict):
        raise TypeError(f"Schema '{schema_path}' must be a JSON object.")
    return Draft202012Validator(schema_doc, registry=registry, format_checker=FormatChecker())


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
    errors = sorted(validator.iter_errors(data), key=lambda err: list(err.absolute_path))
    msgs: List[str] = []
    for err in errors:
        path = ".".join([str(part) for part in err.absolute_path]) or "<root>"
        msgs.append(f"{label}: {path}: {err.message}")
    return msgs


def lint_rule(data: Any, file_path: Path) -> List[str]:
    """Minimal architectural lint for rules/* payloads."""
    msgs: List[str] = []
    if not isinstance(data, dict):
        return msgs

    path_text = file_path.as_posix().replace("\\", "/")
    is_legality = "/rules/legality/" in path_text
    if not is_legality:
        return msgs

    scenario = data.get("scenario")
    if not scenario:
        msgs.append(f"{file_path}: <root>: missing required field: scenario")
        return msgs

    constraints = data.get("constraints")
    if constraints is None:
        constraints = []
    if not isinstance(constraints, list):
        msgs.append(f"{file_path}: constraints: expected array")
        return msgs

    if scenario == "SCENARIO_1":
        banned = {"requires_line_of_sight", "requires_range_max"}
        for idx, constraint in enumerate(constraints):
            if isinstance(constraint, dict) and constraint.get("type") in banned:
                msgs.append(
                    f"{file_path}: constraints[{idx}].type: '{constraint.get('type')}' not allowed in SCENARIO_1"
                )

    return msgs


def lint_atoms(data: Any, file_path: Path, atoms_registry_types: Dict[str, Any]) -> List[str]:
    """Validate atoms against atoms_registry.json."""
    msgs: List[str] = []

    if not isinstance(data, dict):
        return msgs

    atoms: List[Any] = []
    scenario = data.get("scenario")

    if "atomType" in data:
        atoms = [data]
    elif data.get("kind") == "atoms" and isinstance(data.get("atoms"), list):
        atoms = data.get("atoms", [])

    if not atoms:
        return msgs

    for idx, atom in enumerate(atoms):
        atom_label = f"{file_path}: atoms[{idx}]" if "atomType" not in data else f"{file_path}: <root>"

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
            allowed_event_types = (
                allowed_applies.get("eventType") if isinstance(allowed_applies, dict) else None
            )
            event_type = applies_to.get("eventType")

            if isinstance(allowed_event_types, list) and event_type not in allowed_event_types:
                msgs.append(f"{atom_label}.appliesTo.eventType: '{event_type}' not allowed")

            action_type = applies_to.get("actionType")
            allowed_action_types = (
                allowed_applies.get("actionType") if isinstance(allowed_applies, dict) else None
            )

            if allowed_action_types is None:
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
                        extra_keys = [key for key in params.keys() if key not in allowed_keys]
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


def validate_atoms_data(
    validator: Draft202012Validator,
    data: Any,
    label: str,
    file_path: Path,
    atoms_registry_types: Dict[str, Any],
) -> List[str]:
    msgs: List[str] = []

    if not isinstance(data, dict):
        return [f"{label}: <root>: expected object"]

    if "atomType" in data:
        msgs.extend(validate_one(validator, data, label))
        msgs.extend(lint_atoms(data, file_path, atoms_registry_types))
        return msgs

    if data.get("kind") == "atoms_index":
        return msgs

    if data.get("kind") != "atoms":
        msgs.append(f"{label}: <root>: expected atom object or atoms bundle")
        return msgs

    atoms = data.get("atoms")
    if not isinstance(atoms, list):
        msgs.append(f"{label}: atoms: expected array")
        return msgs

    if "scenario" in data and not isinstance(data.get("scenario"), str):
        msgs.append(f"{label}: scenario: expected string")
    if "source" in data and not isinstance(data.get("source"), dict):
        msgs.append(f"{label}: source: expected object")
    if "extraction" in data and not isinstance(data.get("extraction"), dict):
        msgs.append(f"{label}: extraction: expected object")

    for idx, atom in enumerate(atoms):
        msgs.extend(validate_one(validator, atom, f"{label}: atoms[{idx}]"))

    msgs.extend(lint_atoms(data, file_path, atoms_registry_types))
    return msgs


def load_atoms_registry_types(repo_root: Path) -> Dict[str, Any]:
    atoms_registry_path = repo_root / "atoms_registry.json"
    atoms_registry_types: Dict[str, Any] = {}

    if not atoms_registry_path.exists():
        return atoms_registry_types

    atoms_registry = load_json(atoms_registry_path)
    if isinstance(atoms_registry, dict):
        atom_types = atoms_registry.get("atomTypes", {})
        if isinstance(atom_types, dict):
            atoms_registry_types = atom_types  # type: ignore[assignment]

    return atoms_registry_types


def normalize_json_value(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def require_object(data: Any, label: str) -> List[str]:
    if isinstance(data, dict):
        return []
    return [f"{label}: <root>: expected object"]


def bundle_atoms(data: Dict[str, Any]) -> List[Any]:
    atoms = data.get("atoms")
    return atoms if isinstance(atoms, list) else []


def validate_structured_fixture(data: Any, spec: Dict[str, Any], label: str) -> List[str]:
    msgs = require_object(data, label)
    if msgs:
        return msgs

    payload = data  # type: ignore[assignment]
    assert isinstance(payload, dict)

    expected_id = spec.get("expectedId")
    if isinstance(expected_id, str) and payload.get("id") != expected_id:
        msgs.append(f"{label}: id: expected '{expected_id}', found '{payload.get('id')}'")

    expected_kind = spec.get("expectedKind")
    if isinstance(expected_kind, str) and payload.get("kind") != expected_kind:
        msgs.append(f"{label}: kind: expected '{expected_kind}', found '{payload.get('kind')}'")

    expected_pack = spec.get("expectedPack")
    if isinstance(expected_pack, str) and payload.get("pack") != expected_pack:
        msgs.append(f"{label}: pack: expected '{expected_pack}', found '{payload.get('pack')}'")

    expected_constraint_types = spec.get("expectedConstraintTypes")
    if isinstance(expected_constraint_types, list):
        constraints = payload.get("constraints")
        actual_types = [
            constraint.get("type")
            for constraint in constraints
            if isinstance(constraint, dict)
        ] if isinstance(constraints, list) else None
        if actual_types != expected_constraint_types:
            msgs.append(
                f"{label}: constraints: expected type list {expected_constraint_types}, found {actual_types}"
            )

    return msgs


def validate_atoms_bundle_expectations(data: Any, spec: Dict[str, Any], label: str) -> List[str]:
    msgs = require_object(data, label)
    if msgs:
        return msgs

    payload = data  # type: ignore[assignment]
    assert isinstance(payload, dict)

    if payload.get("kind") != "atoms":
        msgs.append(f"{label}: kind: expected 'atoms', found '{payload.get('kind')}'")
        return msgs

    expected_scenario = spec.get("scenario")
    if isinstance(expected_scenario, str) and payload.get("scenario") != expected_scenario:
        msgs.append(
            f"{label}: scenario: expected '{expected_scenario}', found '{payload.get('scenario')}'"
        )

    atoms = bundle_atoms(payload)
    actual_ids = [atom.get("id") for atom in atoms if isinstance(atom, dict)]
    expected_ids = spec.get("expectedAtomIds")
    if isinstance(expected_ids, list) and actual_ids != expected_ids:
        msgs.append(f"{label}: atom ids: expected {expected_ids}, found {actual_ids}")

    actual_types = [atom.get("atomType") for atom in atoms if isinstance(atom, dict)]
    expected_types = spec.get("expectedAtomTypes")
    if isinstance(expected_types, list) and actual_types != expected_types:
        msgs.append(f"{label}: atom types: expected {expected_types}, found {actual_types}")

    return msgs


def simplify_index_entries(entries: Any) -> Optional[List[Dict[str, Any]]]:
    if not isinstance(entries, list):
        return None

    simplified: List[Dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            return None
        atom_ids = entry.get("atomIds")
        if not isinstance(atom_ids, list):
            return None
        simplified.append(
            {
                "scenario": entry.get("scenario"),
                "eventType": entry.get("eventType"),
                "actionType": entry.get("actionType"),
                "atomIds": atom_ids,
            }
        )
    return simplified


def validate_atoms_index(data: Any, spec: Dict[str, Any], label: str) -> List[str]:
    msgs = require_object(data, label)
    if msgs:
        return msgs

    payload = data  # type: ignore[assignment]
    assert isinstance(payload, dict)

    if payload.get("kind") != "atoms_index":
        msgs.append(f"{label}: kind: expected 'atoms_index', found '{payload.get('kind')}'")

    simplified = simplify_index_entries(payload.get("entries"))
    if simplified is None:
        msgs.append(f"{label}: entries: expected array of objects")
        return msgs

    expected_entries = spec.get("expectedEntries")
    if isinstance(expected_entries, list) and simplified != expected_entries:
        msgs.append(f"{label}: entries: expected {expected_entries}, found {simplified}")

    return msgs


def derive_index_entries(bundle_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    scenario = bundle_data.get("scenario")
    groups: DefaultDict[Tuple[Any, Any], List[str]] = defaultdict(list)

    for atom in bundle_atoms(bundle_data):
        if not isinstance(atom, dict):
            continue
        applies_to = atom.get("appliesTo")
        if not isinstance(applies_to, dict):
            continue
        key = (applies_to.get("eventType"), applies_to.get("actionType"))
        atom_id = atom.get("id")
        if isinstance(atom_id, str):
            groups[key].append(atom_id)

    entries: List[Dict[str, Any]] = []
    for event_type, action_type in sorted(
        groups.keys(),
        key=lambda item: (str(item[0]), "" if item[1] is None else str(item[1])),
    ):
        entries.append(
            {
                "scenario": scenario,
                "eventType": event_type,
                "actionType": action_type,
                "atomIds": groups[(event_type, action_type)],
            }
        )

    return entries


def validate_artifact_derivation(
    bundle_data: Dict[str, Any],
    index_data: Dict[str, Any],
    canonical_bundle_data: Sequence[Dict[str, Any]],
    bundle_label: str,
    index_label: str,
) -> List[str]:
    msgs: List[str] = []

    derived_atoms: List[Any] = []
    for canonical_bundle in canonical_bundle_data:
        derived_atoms.extend(bundle_atoms(canonical_bundle))

    canonical_snapshot = sorted(
        [normalize_json_value(atom) for atom in derived_atoms if isinstance(atom, dict)]
    )
    artifact_snapshot = sorted(
        [normalize_json_value(atom) for atom in bundle_atoms(bundle_data) if isinstance(atom, dict)]
    )

    if artifact_snapshot != canonical_snapshot:
        msgs.append(f"{bundle_label}: bundle content does not match canonical baseline atoms")

    actual_entries = simplify_index_entries(index_data.get("entries"))
    derived_entries = derive_index_entries(bundle_data)
    if actual_entries is None:
        msgs.append(f"{index_label}: entries: expected array of objects")
    elif actual_entries != derived_entries:
        msgs.append(
            f"{index_label}: entries do not match bundle grouping; expected {derived_entries}, found {actual_entries}"
        )

    return msgs


def validate_baseline(
    repo_root: Path,
    registry: Registry,
    atoms_registry_types: Dict[str, Any],
    manifest_path: Path,
) -> List[str]:
    errors: List[str] = []

    try:
        manifest = load_json(manifest_path)
    except Exception as ex:
        return [f"[ERROR] Failed to parse baseline manifest '{manifest_path}': {ex}"]

    if not isinstance(manifest, dict):
        return [f"[ERROR] Baseline manifest '{manifest_path}' must be a JSON object."]

    path_classes = manifest.get("pathClasses")
    if not isinstance(path_classes, dict):
        errors.append(f"[ERROR] Baseline manifest '{manifest_path}': missing pathClasses object")
        return errors

    required_classes = [
        "source_tracked",
        "intermediate_generated",
        "canonical_dataset",
        "distributable_artifact",
    ]
    for class_name in required_classes:
        entries = path_classes.get(class_name)
        if not isinstance(entries, list) or not entries:
            errors.append(
                f"[ERROR] Baseline manifest '{manifest_path}': pathClasses.{class_name} must be a non-empty array"
            )

    schemas = manifest.get("schemas")
    if not isinstance(schemas, dict):
        errors.append(f"[ERROR] Baseline manifest '{manifest_path}': missing schemas object")
        return errors

    structured_schema_rel = schemas.get("structured")
    atoms_schema_rel = schemas.get("atoms")
    if not isinstance(structured_schema_rel, str) or not isinstance(atoms_schema_rel, str):
        errors.append(f"[ERROR] Baseline manifest '{manifest_path}': schemas must declare structured and atoms")
        return errors

    try:
        structured_validator = load_validator(repo_root / structured_schema_rel, registry)
        atoms_validator = load_validator(repo_root / atoms_schema_rel, registry)
    except Exception as ex:
        errors.append(f"[ERROR] Failed to load baseline schemas: {ex}")
        return errors

    baseline = manifest.get("baseline")
    if not isinstance(baseline, dict):
        errors.append(f"[ERROR] Baseline manifest '{manifest_path}': missing baseline object")
        return errors

    structured_fixtures = baseline.get("structuredFixtures", [])
    if not isinstance(structured_fixtures, list) or not structured_fixtures:
        errors.append(f"[ERROR] Baseline manifest '{manifest_path}': baseline.structuredFixtures must be a non-empty array")
        return errors

    for fixture in structured_fixtures:
        if not isinstance(fixture, dict) or not isinstance(fixture.get("path"), str):
            errors.append("[ERROR] baseline.structuredFixtures entries must be objects with a path")
            continue
        fixture_path = repo_root / fixture["path"]
        if not fixture_path.exists():
            errors.append(f"[ERROR] Structured fixture not found: {fixture_path}")
            continue
        try:
            fixture_data = load_json(fixture_path)
        except Exception as ex:
            errors.append(f"[ERROR] Failed to parse structured fixture '{fixture_path}': {ex}")
            continue
        errors.extend(validate_one(structured_validator, fixture_data, str(fixture_path)))
        errors.extend(validate_structured_fixture(fixture_data, fixture, str(fixture_path)))

    canonical_specs = baseline.get("canonicalAtomsBundles", [])
    if not isinstance(canonical_specs, list) or not canonical_specs:
        errors.append(
            f"[ERROR] Baseline manifest '{manifest_path}': baseline.canonicalAtomsBundles must be a non-empty array"
        )
        return errors

    canonical_bundle_data: List[Dict[str, Any]] = []
    for spec in canonical_specs:
        if not isinstance(spec, dict) or not isinstance(spec.get("path"), str):
            errors.append("[ERROR] baseline.canonicalAtomsBundles entries must be objects with a path")
            continue

        bundle_path = repo_root / spec["path"]
        if not bundle_path.exists():
            errors.append(f"[ERROR] Canonical atoms bundle not found: {bundle_path}")
            continue
        try:
            bundle_data = load_json(bundle_path)
        except Exception as ex:
            errors.append(f"[ERROR] Failed to parse canonical atoms bundle '{bundle_path}': {ex}")
            continue
        errors.extend(
            validate_atoms_data(atoms_validator, bundle_data, str(bundle_path), bundle_path, atoms_registry_types)
        )
        errors.extend(validate_atoms_bundle_expectations(bundle_data, spec, str(bundle_path)))
        if isinstance(bundle_data, dict):
            canonical_bundle_data.append(bundle_data)

    artifacts = baseline.get("distributableArtifacts")
    if not isinstance(artifacts, dict):
        errors.append(f"[ERROR] Baseline manifest '{manifest_path}': missing baseline.distributableArtifacts")
        return errors

    bundle_spec = artifacts.get("bundle")
    index_spec = artifacts.get("index")
    if not isinstance(bundle_spec, dict) or not isinstance(bundle_spec.get("path"), str):
        errors.append("[ERROR] baseline.distributableArtifacts.bundle must be an object with a path")
        return errors
    if not isinstance(index_spec, dict) or not isinstance(index_spec.get("path"), str):
        errors.append("[ERROR] baseline.distributableArtifacts.index must be an object with a path")
        return errors

    bundle_path = repo_root / bundle_spec["path"]
    if not bundle_path.exists():
        errors.append(f"[ERROR] Artifact bundle not found: {bundle_path}")
        return errors
    try:
        bundle_data = load_json(bundle_path)
    except Exception as ex:
        errors.append(f"[ERROR] Failed to parse artifact bundle '{bundle_path}': {ex}")
        return errors
    errors.extend(validate_atoms_data(atoms_validator, bundle_data, str(bundle_path), bundle_path, atoms_registry_types))
    errors.extend(validate_atoms_bundle_expectations(bundle_data, bundle_spec, str(bundle_path)))

    index_path = repo_root / index_spec["path"]
    if not index_path.exists():
        errors.append(f"[ERROR] Artifact index not found: {index_path}")
        return errors
    try:
        index_data = load_json(index_path)
    except Exception as ex:
        errors.append(f"[ERROR] Failed to parse artifact index '{index_path}': {ex}")
        return errors
    errors.extend(validate_atoms_index(index_data, index_spec, str(index_path)))

    if isinstance(bundle_data, dict) and isinstance(index_data, dict) and canonical_bundle_data:
        errors.extend(
            validate_artifact_derivation(
                bundle_data,
                index_data,
                canonical_bundle_data,
                str(bundle_path),
                str(index_path),
            )
        )

    return errors


def validate_schema_paths(
    schema_path: Path,
    paths: List[Path],
    allow_empty: bool,
    registry: Registry,
    atoms_registry_types: Dict[str, Any],
) -> List[str]:
    errors: List[str] = []

    if not schema_path.exists():
        return [f"[ERROR] Schema not found: {schema_path}"]

    try:
        validator = load_validator(schema_path, registry)
    except Exception as ex:
        return [f"[ERROR] Failed to parse schema '{schema_path}': {ex}"]

    files = collect_files([str(path) for path in paths])
    if not files:
        msg = f"[WARN] No .json/.jsonl files found to validate for {schema_path}."
        if allow_empty:
            eprint(msg)
            return errors
        return [msg]

    atoms_mode = schema_path.name == "atoms.schema.json"

    for file_path in files:
        ext = file_path.suffix.lower()
        try:
            if ext == ".json":
                data = load_json(file_path)
                if atoms_mode:
                    errors.extend(
                        validate_atoms_data(
                            validator,
                            data,
                            str(file_path),
                            file_path,
                            atoms_registry_types,
                        )
                    )
                else:
                    errors.extend(validate_one(validator, data, str(file_path)))
                    errors.extend(lint_rule(data, file_path))
            elif ext == ".jsonl":
                for line_no, obj in iter_jsonl(file_path):
                    label = f"{file_path}#L{line_no}"
                    if atoms_mode:
                        errors.extend(validate_atoms_data(validator, obj, label, file_path, atoms_registry_types))
                    else:
                        errors.extend(validate_one(validator, obj, label))
                        errors.extend(lint_rule(obj, file_path))
        except json.JSONDecodeError as ex:
            errors.append(f"{file_path}: JSON parse error: {ex}")
        except Exception as ex:
            errors.append(f"{file_path}: Unexpected error: {ex}")

    return errors


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate .json or .jsonl files against repository schemas and baseline policy."
    )
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument(
        "--schema",
        help="Path to schema JSON file (for atoms schema, atom bundles are validated item by item).",
    )
    mode_group.add_argument(
        "--rules",
        action="store_true",
        help="Validate rules/legality, rules/triggers, and rules/transitions against their schemas.",
    )
    mode_group.add_argument(
        "--atoms",
        action="store_true",
        help="Validate atom objects or atom bundles against atoms.schema.json and atoms_registry.json.",
    )
    mode_group.add_argument(
        "--baseline",
        action="store_true",
        help="Validate the official minimal baseline declared in dataset_baseline.json.",
    )
    parser.add_argument(
        "paths",
        nargs="*",
        help="Files or directories to validate (.json/.jsonl). Directories are searched recursively.",
    )
    args = parser.parse_args(argv)

    repo_root = Path(__file__).resolve().parents[1]
    registry = build_registry(repo_root)

    try:
        atoms_registry_types = load_atoms_registry_types(repo_root)
    except Exception as ex:
        eprint("VALIDATION FAILED")
        eprint(f" - [ERROR] Failed to parse atoms registry '{repo_root / 'atoms_registry.json'}': {ex}")
        return 1

    errors: List[str] = []

    if args.baseline:
        errors.extend(validate_baseline(repo_root, registry, atoms_registry_types, repo_root / "dataset_baseline.json"))
    elif args.atoms:
        atom_paths = [repo_root / "dist"] if not args.paths else [Path(path) for path in args.paths]
        errors.extend(
            validate_schema_paths(
                repo_root / "schemas" / "atoms.schema.json",
                atom_paths,
                allow_empty=False,
                registry=registry,
                atoms_registry_types=atoms_registry_types,
            )
        )
    elif args.rules:
        rule_sets = [
            (repo_root / "schemas" / "rules.legality.schema.json", [repo_root / "rules" / "legality"]),
            (repo_root / "schemas" / "rules.triggers.schema.json", [repo_root / "rules" / "triggers"]),
            (repo_root / "schemas" / "rules.transitions.schema.json", [repo_root / "rules" / "transitions"]),
        ]
        for schema_path, paths in rule_sets:
            errors.extend(
                validate_schema_paths(
                    schema_path,
                    paths,
                    allow_empty=True,
                    registry=registry,
                    atoms_registry_types=atoms_registry_types,
                )
            )
    else:
        if not args.paths:
            eprint("[ERROR] No .json/.jsonl files found to validate.")
            return 2
        errors.extend(
            validate_schema_paths(
                Path(args.schema).resolve(),
                [Path(path) for path in args.paths],
                allow_empty=False,
                registry=registry,
                atoms_registry_types=atoms_registry_types,
            )
        )

    if errors:
        eprint("VALIDATION FAILED")
        for message in errors:
            eprint(" - " + message)
        return 1

    print("VALIDATION OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
