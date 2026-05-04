# Code Flow Partner Analyzer

This project is a local MVP that scans uploaded source files or an existing folder,
then produces a human-readable layout of:

- overall flow-related code sections
- partner-specific branching
- checks and guard conditions tied to each partner
- file-by-file findings that likely affect execution flow

It is intentionally heuristic, not a full compiler or AST engine. The goal is to
give you a strong local starting point that you can adapt to your codebase.

## What it does

- Runs locally with the Python standard library
- Accepts uploaded files from a browser
- Can also analyze a folder path on disk
- Scans common source file types such as `.py`, `.js`, `.ts`, `.tsx`, `.java`,
  `.go`, `.rb`, `.php`, `.json`, `.yaml`, and `.yml`
- Detects likely:
  - partner identifiers
  - `if` / `elif` / `switch` / `case` style flow branches
  - validation and eligibility checks
  - status/risk/KYC/fraud/feature-flag style guards

## Run locally

```bash
python3 app.py
```

Then open:

```text
http://127.0.0.1:8000
```

## Project structure

- `app.py` - local web server and upload UI
- `codeflow/analyzer.py` - scanning and report generation logic
- `tests/test_analyzer.py` - basic analyzer coverage

## Notes

- This is best for an MVP or first-pass internal tool.
- For higher accuracy, the next step would be language-aware parsers or an LLM
  explanation layer on top of this report.
- If your real codebase uses specific field names for partners, checks, or
  decision objects, you can extend the regex rules in `codeflow/analyzer.py`.
