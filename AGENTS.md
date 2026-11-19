# AGENTS.md - Laboratorio de Detectabilidad LLM

Reproducible research lab for evaluating security and detectability of LLM-generated Python code. Uses CodeSecEval as the single corpus, three generator models, five CWE categories, and four detectors (Semgrep, Bandit, CodeQL, LLM auditor).

## Dev environment

- **Root:** `C:\Users\Daniel\Desktop\Investigacion\Laboratorio`
- **Toolchain:** Python 3.12, `uv` package manager, Docker Desktop + WSL
- **Package manager:** `uv` (lockfile `uv.lock`)
- **Secrets:** `OPENROUTER_API_KEY` in `.env` (never commit)
- **Install deps:** `uv sync`
- **Add dep:** `uv add <pkg>`
- **Add dev dep:** `uv add --dev <pkg>`

## Build & test

- **Run tests:** `uv run pytest`
- **Run linting:** `uv run ruff check .` and `uv run ruff format .`
- **Run type check:** `uv run mypy src`
- **Build sandbox image:** `docker build -t llm-lab-sandbox:v0.2 -f sandbox/Dockerfile sandbox/`

## Project layout

- `src/llm_lab/` — library code (schemas, generation, execution, detection)
- `tools/` — CLI scripts for corpus generation, functional tests, detectors, analysis
- `configs/` — YAML/JSON experiment, model, ground-truth, and schema configs
- `data/raw/CodeSecEval/` — frozen dataset snapshot
- `data/raw/corpus_v0.1/` — generated 375 outputs + manifest
- `data/derived/` — detector results, matrices, catalogs
- `data/adjudicated/` — gold truth and review queues
- `sandbox/` — Dockerfile and requirements for hardened sandbox
- `reports/technical/` — generated reports (ignored by git)

## Common commands

- **Generate corpus:** `uv run python tools/generate_full_corpus.py --tasks data/manifests/task_selection_v0.1.csv --models configs/models_v0.1.yaml --output-dir data/raw/corpus_v0.1/`
- **Run functional tests:** `uv run python tools/run_full_functional_tests.py`
- **Run detectors:** `uv run python tools/run_detectors.py --output-dir data/raw/corpus_v0.1/ --output data/derived/detector_results.json`
- **Run CodeQL:** `uv run python tools/run_codeql_detector.py`
- **Analyze results:** `uv run python tools/analyze_results.py`
- **Check completeness:** `uv run python tools/check_completeness.py`

## Conventions

- **Python:** `from __future__ import annotations`, type hints, frozen dataclasses for records
- **Naming:** `snake_case` files/functions, `PascalCase` classes, IDs use `{task_id}__{model_slug}__r{repetition}`
- **Records:** `OutputRecord` in `src/llm_lab/schemas.py` is the canonical output format; hashes are SHA-256
- **Config:** YAML configs under `configs/`, experiment config is `configs/experiment_v0.1.yaml`
- **Tests:** `pytest`, unit tests in `tests/unit/`, integration in `tests/integration/`
- **Commits:** conventional commits observed (e.g. `feat:`, `data:`, `docs:`)

## Pitfalls

- **Do not commit `.env`** — OpenRouter API key lives there.
- **Do not hand-edit generated files** in `data/raw/corpus_v0.1/`, `data/derived/`, or `reports/technical/`; regenerate via tools.
- **CodeQL may report 0 findings** in this Windows environment; documented as a known limitation.
- **Functional tests run inside Docker** — Docker Desktop must be running.
- **Long paths on Windows** can fail (`WinError 206`); prefer `write_file` + `uv run python script.py` over inline heredocs.
- **Corpus deduplication** is by logical key `(task_id, model_id, repetition)`, not `output_id`.
- **Reports/technical is gitignored** — handoff/docs there must be forced if committing.
