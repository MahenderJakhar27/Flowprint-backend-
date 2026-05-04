# Flowprint

> The blueprint for your backend.

Flowprint is a zero-dependency static analysis tool that scans a Django codebase and generates a live, interactive architecture map — APIs, partner logic, database models, exception flows, and a Mermaid.js diagram — all in your browser.

No external services. No cloud. Just point it at a folder and go.

---

## What it does

| Feature | Detail |
|---|---|
| **API Directory** | Every inbound endpoint discovered across all Django apps with method, route, file, and checks |
| **API Spec Panel** | Per-endpoint JSON view of expected payload fields, possible exceptions (with HTTP codes + messages), and success flow |
| **Architectural Diagram** | Auto-generated Mermaid.js flowchart showing how apps, APIs, handlers, and databases connect |
| **ORM Coverage** | Every `Model.objects.create / filter / get / update / delete` call mapped to its table |
| **Partner Graph** | Detects external partner integrations and groups logic by partner |
| **Model Schema** | Field definitions and relationships extracted from `models.py` |
| **System Configs** | Key/value settings found across config files — sensitive values automatically redacted |
| **Bug Reports** | Static analysis flags for security, logic, and performance issues |
| **Omni Search** | Live search across APIs, partners, logic checks, and models |

---

## Screenshots

### API Directory with Spec Panel
Click any endpoint to see its payload, exceptions, and success flow rendered as syntax-highlighted JSON.

### Architectural Flow Map
Zoom, pan, and scroll the auto-generated diagram. Copy the Mermaid code with one click.

---

## Quickstart

**Requirements:** Python 3.11+, no external packages needed.

```bash
# Clone the repo
git clone https://github.com/MahenderJakhar27/Flowprint-backend-.git
cd flowprint

# Run the server
python app.py
```

Open your browser at:

```
http://127.0.0.1:8002
```

Enter the absolute path to your Django project folder and click **Generate Flowprint**.

---

## How it works

Flowprint runs a multi-pass static analysis entirely using Python's built-in `ast` module — no runtime execution of your code.

```
Pass 1 — File scan
  └── Parse every .py file into an AST
  └── Extract: class-based views, function-based views, URL patterns,
               ORM calls, serializers, model fields, config values

Pass 2 — Cross-file resolution
  └── Link serializer fields to view functions
  └── Resolve cls.method() → ClassName.method() call chains
  └── Bubble HTTP return codes up through call chains (ViewSet → Handler → create_or_update)

Pass 3 — API enrichment
  └── Match URL routes to view functions
  └── Attach payload fields, exceptions, success paths
  └── Aggregate by app and partner
```

### Exception detection

Four sources are checked for each view:

1. Explicit `raise SomeError(...)` statements
2. `serializer.is_valid(raise_exception=True)` → `ValidationError`
3. `except SomeError` handler blocks
4. `return HTTP_4xx, "message"` tuple returns — with inline message extraction

### Confidential config protection

Two-layer approach:

- **File-level exclusion** — `.env`, `secrets.py`, `credentials.json`, `local_settings.py`, and similar files are never scanned
- **Value-level redaction** — any config key matching `SECRET`, `PASSWORD`, `TOKEN`, `API_KEY`, `DATABASE_URL`, etc. shows `[REDACTED]` instead of its value

---

## Project structure

```
flowprint/
├── app.py                  # Web server, UI rendering, HTTP handlers
├── codeflow/
│   ├── __init__.py
│   └── analyzer.py         # Core static analysis engine
└── tests/
    └── test_analyzer.py    # Unit tests
```

---

## Extending it

All detection rules live in `codeflow/analyzer.py`. Common customisations:

- **Add partner names** — extend `extract_partners()` regex
- **Add check keywords** — extend `extract_checks()` regex
- **Exclude more secret keys** — extend `_SENSITIVE_KEY` regex pattern
- **Exclude more confidential files** — add to `CONFIDENTIAL_NAMES` frozenset

---

## Running tests

```bash
python -m unittest tests/test_analyzer.py -v
```

---

## Tech stack

| Layer | Technology |
|---|---|
| Backend | Python 3.11 stdlib only (`ast`, `http.server`, `pathlib`) |
| Diagram | [Mermaid.js](https://mermaid.js.org/) 11.4.1 |
| Frontend | Vanilla HTML/CSS/JS — no frameworks, no build step |
| Analysis | Python `ast` module (two-pass CBV + FBV analysis) |

---

