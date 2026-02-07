from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Iterable, List, Tuple, Optional

from jsonschema import Draft202012Validator
from referencing import Registry, Resource


def eprint(*args: object) -> None:
    print(*args, file=sys.stderr)


def load_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def load_json(path: Path) -> object:
    return json.loads(load_text(path))


def build_registry(repo_root: Path) -> Registry:
    \"\"\"Build a registry from all schemas in ./schemas so  references can resolve.\"\"\"
    schemas_dir = repo_root / "schemas"
    registry = Registry()

    if schemas_dir.exists():
        for p in schemas_dir.rglob("*.json"):
            try:
                doc = load_json(p)
                if isinstance(doc, dict) and isinstance(doc.get("\"), str):
                    res = Resource.from_contents(doc)
                    registry = registry.with_resource(doc["\"], res)
            except Exception as ex:
                eprint(f"[WARN] Unable to index schema '{p}': {ex}")

    return registry


def collect_files(paths: List[str]) -> List[Path]:
    out: List[Path] = []
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            out.extend([x for x in p.rglob("*") if x.is_file() and x.suffix.lower() in (".json", ".jsonl")])
        elif p.is_file():
            out.append(p)
        else:
            # support glob-like input via shell expansion; if not expanded, warn
            eprint(f"[WARN] Path not found: {raw}")
    return out


def iter_jsonl(path: Path) -> Iterable[Tuple[int, object]]:
    \"\"\"Yield (line_number, parsed_object). Ignores empty/whitespace-only lines.\"\"\"
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
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
    parser.add_argument(
        "--schema",
        required=True,
        help="Path to schema JSON file (e.g. schemas/structured.schema.json)",
    )
    parser.add_argument(
        "paths",
        nargs="+",
        help="Files or directories to validate (.json/.jsonl). Directories are searched recursively.",
    )
    args = parser.parse_args(argv)

    repo_root = Path(__file__).resolve().parents[1]
    schema_path = Path(args.schema).resolve()

    if not schema_path.exists():
        eprint(f"[ERROR] Schema not found: {schema_path}")
        return 2

    try:
        schema_doc = load_json(schema_path)
    except Exception as ex:
        eprint(f"[ERROR] Failed to parse schema '{schema_path}': {ex}")
        return 2

    registry = build_registry(repo_root)
    validator = Draft202012Validator(schema_doc, registry=registry)

    files = collect_files(args.paths)
    if not files:
        eprint("[ERROR] No .json/.jsonl files found to validate.")
        return 2

    all_errors: List[str] = []

    for f in files:
        ext = f.suffix.lower()
        try:
            if ext == ".json":
                data = load_json(f)
                all_errors.extend(validate_one(validator, data, str(f)))
            elif ext == ".jsonl":
                for line_no, obj in iter_jsonl(f):
                    label = f"{f}#L{line_no}"
                    all_errors.extend(validate_one(validator, obj, label))
            else:
                continue
        except json.JSONDecodeError as ex:
            all_errors.append(f"{f}: JSON parse error: {ex}")
        except Exception as ex:
            all_errors.append(f"{f}: Unexpected error: {ex}")

    if all_errors:
        eprint("VALIDATION FAILED")
        for msg in all_errors:
            eprint(" - " + msg)
        return 1

    print("VALIDATION OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
