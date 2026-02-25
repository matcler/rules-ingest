#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List

SCENARIOS = {"SCENARIO_1", "SCENARIO_2", "SCENARIO_3", "SCENARIO_4", "SCENARIO_5"}
REF_PAGE_PAT = re.compile(r"\b(?:p\d{1,3}|page\d{1,3})\b", re.IGNORECASE)
REF_TRAIL_PAGE_PAT = re.compile(r"(?:_p\d{1,3}|\.p\d{1,3})$", re.IGNORECASE)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Lint candidate JSON files against pages text.")
    p.add_argument("--pages", required=True, help="Path to pages_XXXX_YYYY.txt")
    p.add_argument("--candidates", required=True, help="Directory of candidate JSON files")
    return p.parse_args()


def load_pages(pages_path: Path) -> Dict[int, List[str]]:
    pages: Dict[int, List[str]] = {}
    current_page = None
    for line in pages_path.read_text(encoding="utf-8").splitlines():
        if line.startswith("=== PAGE ") and line.endswith(" ==="):
            try:
                current_page = int(line.split()[2])
            except Exception:
                current_page = None
            if current_page is not None:
                pages[current_page] = []
            continue
        if current_page is not None:
            pages[current_page].append(line)
    return pages


def pages_range_from_name(pages_path: Path) -> tuple[int, int]:
    m = re.search(r"pages_(\d{4})_(\d{4})\.txt$", pages_path.name)
    if not m:
        raise SystemExit("Could not infer range from pages filename")
    return int(m.group(1)), int(m.group(2))


def check_ref(ref: str) -> List[str]:
    errs = []
    if REF_PAGE_PAT.search(ref) or REF_TRAIL_PAGE_PAT.search(ref):
        errs.append("source.ref appears to encode page numbers")
    return errs


def candidate_files(dir_path: Path) -> List[Path]:
    return sorted([p for p in dir_path.glob("*.json") if p.is_file() and p.name != "manifest.json"])


def main() -> int:
    args = parse_args()
    pages_path = Path(args.pages)
    cand_dir = Path(args.candidates)

    pages = load_pages(pages_path)
    start_page, end_page = pages_range_from_name(pages_path)

    results: Dict[str, Any] = {
        "pages": {
            "path": str(pages_path),
            "start": start_page,
            "end": end_page,
        },
        "candidates_dir": str(cand_dir),
        "counts": {
            "total": 0,
            "passed": 0,
            "failed": 0,
        },
        "failures": [],
        "status": "PASS",
    }

    for path in candidate_files(cand_dir):
        results["counts"]["total"] += 1
        errors: List[str] = []
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as ex:
            errors.append(f"invalid JSON: {ex}")
            data = None

        if isinstance(data, dict):
            if data.get("kind") != "candidate":
                errors.append("kind must be 'candidate'")
            if data.get("schemaVersion") != "v1":
                errors.append("schemaVersion must be 'v1'")
            if data.get("docId") != "SRD_5_2_1_EN":
                errors.append("docId must be 'SRD_5_2_1_EN'")

            src = data.get("source") if isinstance(data.get("source"), dict) else None
            if not src:
                errors.append("source must be an object")
            else:
                ps = src.get("pageStart")
                pe = src.get("pageEnd")
                if not isinstance(ps, int) or not isinstance(pe, int):
                    errors.append("source.pageStart/pageEnd must be integers")
                else:
                    if ps < start_page or pe > end_page:
                        errors.append("source.pageStart/pageEnd out of range")
                    if ps > pe:
                        errors.append("source.pageStart must be <= pageEnd")

                ref = src.get("ref")
                if not isinstance(ref, str) or not ref:
                    errors.append("source.ref must be a non-empty string")
                else:
                    errors.extend(check_ref(ref))

            text = data.get("text") if isinstance(data.get("text"), dict) else None
            if not text:
                errors.append("text must be an object")
            else:
                raw = text.get("raw")
                if not isinstance(raw, str) or not raw.strip():
                    errors.append("text.raw must be non-empty")

            meta = data.get("metadata") if isinstance(data.get("metadata"), dict) else None
            if not meta:
                errors.append("metadata must be an object")
            else:
                scenario = meta.get("scenario")
                if scenario not in SCENARIOS:
                    errors.append("metadata.scenario must be SCENARIO_1..SCENARIO_5")

            # substring check
            if not errors:
                ps = src.get("pageStart")
                pe = src.get("pageEnd")
                raw = text.get("raw")
                if isinstance(ps, int) and isinstance(pe, int) and isinstance(raw, str):
                    combined_pages: List[str] = []
                    for p in range(ps, pe + 1):
                        combined_pages.extend(pages.get(p, []))
                    combined_text = "\n".join(combined_pages)
                    if raw not in combined_text:
                        errors.append("text.raw not found verbatim in pages text for source range")

        if errors:
            results["counts"]["failed"] += 1
            results["failures"].append({"file": path.name, "errors": errors})
        else:
            results["counts"]["passed"] += 1

    if results["counts"]["failed"] > 0:
        results["status"] = "FAIL"

    report_path = Path("ingest/reports") / f"candidate_lint_{start_page:04d}_{end_page:04d}.json"
    report_path.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")

    if results["status"] == "FAIL":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
