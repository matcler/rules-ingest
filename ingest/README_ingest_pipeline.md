Ingest Pipeline (Text Extraction + Candidate Lint)

Canonical commands

1) Extract and normalize pages
python ingest/tools/extract_pages.py --start 10 --end 25

2) Lint candidates against pages text
python ingest/tools/lint_candidates.py --pages ingest/text/pages_0010_0025.txt --candidates ingest/candidates/pages_0010_0025/

What gets removed in normalization
- Any line that is exactly: System Reference Document 5.2.1 (after stripping)
- Any line that is only a page number (1–3 digits, after stripping)
- Trailing whitespace is trimmed from each line

What is forbidden
- No semantic edits or reflowing text
- No hyphenation fixes or word-joins
- No column merging or “smart” layout changes
- Do not emit empty page markers
