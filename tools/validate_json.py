from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional, Iterable, Tuple, Any

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
    parser.add_argument(
        "paths",
        nargs="*",
        help="Files or directories to validate (.json/.jsonl). Directories are searched recursively.",
    )
    args = parser.parse_args(argv)

    repo_root = Path(__file__).resolve().parents[1]
    registry = build_registry(repo_root)
    all_errors: List[str] = []

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

        is_legality = "rules/legality" in file_path.as_posix().replace("\\\\", "/")

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

                    msgs.append(f"{file_path}: constraints[{i}].type: '{c.get('type')}' not allowed in SCENARIO_1")

    

        return msgs

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
                elif ext == ".jsonl":
                    for line_no, obj in iter_jsonl(f):
                        label = f"{f}#L{line_no}"
                        all_errors.extend(validate_one(validator, obj, label))
                        all_errors.extend(lint_rule(obj, f))
            except json.JSONDecodeError as ex:
                all_errors.append(f"{f}: JSON parse error: {ex}")
            except Exception as ex:
                all_errors.append(f"{f}: Unexpected error: {ex}")

    if args.rules:
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









