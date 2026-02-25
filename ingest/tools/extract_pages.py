#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

PDF_PATH = Path("asset/pdfs/ENG-SRD_CC_v5.2.1.pdf")


def zpad(n: int) -> str:
    return f"{n:04d}"


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Extract and normalize PDF pages.")
    p.add_argument("--start", type=int, required=True, help="Start page (1-based).")
    p.add_argument("--end", type=int, required=True, help="End page (1-based).")
    return p.parse_args()


def run_pdftotext(start: int, end: int, out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        "pdftotext",
        "-f",
        str(start),
        "-l",
        str(end),
        "-enc",
        "UTF-8",
        "-eol",
        "unix",
        str(PDF_PATH),
        str(out_path),
    ]
    subprocess.run(cmd, check=True)


def normalize(raw_path: Path, start: int, end: int, out_path: Path) -> tuple[int, int]:
    raw = raw_path.read_text(encoding="utf-8")
    chunks = raw.split("\f")

    lines_out: list[str] = []
    produced = 0
    dropped = 0

    page_num = start
    for chunk in chunks:
        if page_num > end:
            break
        # process lines
        cleaned: list[str] = []
        for line in chunk.splitlines():
            s = line.strip()
            if s == "System Reference Document 5.2.1":
                continue
            if s.isdigit() and 1 <= len(s) <= 3:
                continue
            # ensure no form feed survives within a line
            cleaned.append(line.replace("\f", "").rstrip())

        # Drop page marker if page is empty after removals
        if not any(l != "" for l in cleaned):
            dropped += 1
            page_num += 1
            continue

        lines_out.append(f"=== PAGE {page_num} ===")
        lines_out.extend(cleaned)
        produced += 1
        page_num += 1

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_text = "\n".join(lines_out).rstrip("\n") + "\n"
    out_path.write_text(out_text, encoding="utf-8")
    return produced, dropped


def run_invariants_check(out_text: str) -> dict:
    ok_no_header = "System Reference Document 5.2.1" not in out_text
    ok_no_formfeed = "\f" not in out_text

    # no standalone page number lines
    ok_no_page_numbers = True
    for line in out_text.splitlines():
        s = line.strip()
        if s.isdigit() and 1 <= len(s) <= 3:
            ok_no_page_numbers = False
            break

    # no empty page blocks
    ok_no_empty_pages = True
    lines = out_text.splitlines()
    for i, line in enumerate(lines):
        if line.startswith("=== PAGE ") and line.endswith(" ==="):
            if i + 1 >= len(lines) or lines[i + 1].startswith("=== PAGE "):
                ok_no_empty_pages = False
                break

    return {
        "no_header_line": ok_no_header,
        "no_page_number_lines": ok_no_page_numbers,
        "no_form_feed": ok_no_formfeed,
        "no_empty_page_blocks": ok_no_empty_pages,
    }
    return produced, dropped


def main() -> int:
    args = parse_args()
    start = args.start
    end = args.end
    if start <= 0 or end <= 0 or end < start:
        raise SystemExit("Invalid range")

    raw_name = f"raw_{zpad(start)}_{zpad(end)}.txt"
    pages_name = f"pages_{zpad(start)}_{zpad(end)}.txt"
    raw_path = Path("ingest/text") / raw_name
    pages_path = Path("ingest/text") / pages_name

    run_pdftotext(start, end, raw_path)
    produced, dropped = normalize(raw_path, start, end, pages_path)

    print(f"Pages produced: {produced}")
    print(f"Pages dropped: {dropped}")
    out_text = pages_path.read_text(encoding="utf-8")
    checks = run_invariants_check(out_text)
    status = "PASS" if all(checks.values()) else "FAIL"
    print(f"Checks: {status} {checks}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
