# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Web-Sploit is a bug bounty automation framework: a Django app that orchestrates recon, crawling, and
vulnerability scanning for web targets, storing everything in a relational data model, and using
AI coding-agent CLIs (Claude Code / Gemini / Codex) as subprocesses to analyze JS files and write
findings. Everything runs inside Docker — the container bundles the recon/scan binaries and the AI CLIs.

## Running the stack

```
docker compose up --build
```

This starts three services (see `docker-compose.yml`):
- `automator` — Django app (entrypoint runs migrations, then `manage.py runserver 0.0.0.0:8000`), port 8000
- `redis` — Celery broker/result backend
- `celery` — `celery -A websploit worker -l INFO`, same image as `automator`

The whole repo is bind-mounted to `/work` in both `automator` and `celery`, and SQLite (`backend/db.sqlite3`)
is shared between them via that mount — there is no Postgres despite `psycopg2-binary` being a dependency.
Config/API keys go in `.env` (copy from `.env.example`): passive-recon provider keys (`CHAOS_KEY`,
`SHODAN_KEY`, `VIRUSTOTAL_KEY`, etc.), plus `AGENT`/`MODEL`/`XICODE_TOKEN`/`DEEPCODE_TOKEN` controlling
which AI CLI backs `call_agent()`.

There is no test suite, linter, or formatter configured in this repo. `backend/core/tests.py` is not a
real Django test — it's an ad-hoc script that calls `recon(...)` directly at import time; do not treat it
as a test to run or extend without checking with the user first.

Django management commands run via `backend/manage.py` (settings module: `backend.websploit.settings`),
e.g. `python3 backend/manage.py migrate`, `python3 backend/manage.py shell`.

## Architecture

### Data model (`backend/core/models.py`)

A strict hierarchy, each level a FK to the one above:

```
Target -> Domain -> Subdomain -> WebApplication -> EndPoint -> Parameter
                                       |
                                       +-> JSFile (content + AI-generated usage_summary/routes_analysis/code_review)
                                       +-> ClientSideRoute
                     Subdomain -> ArchivedURLs (wayback/archive URLs, tagged with `source`)
```

`Vulnerability` is polymorphic: nullable FKs to exactly one of `web_app` / `endpoint` / `parameter`,
enforced by three conditional `UniqueConstraint`s keyed on `name` + whichever FK is set. When adding a
new finding, populate exactly one of those FKs and write the report into `Vulnerability.report`.

### Two different async mechanisms — don't confuse them

- **Scans (recon, webapp analysis, vuln scan, dir fuzz, add-subdomain/webapp) are Celery tasks**
  (`backend/websploit/tasks.py`), kicked off via `.delay()` from POST views in `core/views.py`.
  Progress is *not* pushed over websockets — a `LogCapture`/`CeleryTaskLogHandler` pair streams log
  lines into the Celery task's `PROGRESS` state `meta`, and the browser polls `AsyncResult` via
  `check_task_status(task_id)`.
- **JS AI-analysis (`js_summary`, `js_routes`, `js_code_review`) uses a plain Python `threading.Thread`**
  spawned in-process by the Django dev server itself (`_start_js_analysis` in `views.py`), tracked in
  module-level dicts and polled via separate `*_status` endpoints. It deliberately does not go through
  Celery.
- **Websockets are used for exactly one thing**: `core/consumers.py`'s `TerminalConsumer` opens a PTY
  and spawns `/bin/bash` (cwd = `agent/`), forwarding raw bytes both ways — a full interactive shell
  exposed at `ws/terminal/`, driven from a browser terminal page. It has no relation to scan progress.

### Module layout under `backend/core/`

- `recon/` — subdomain/DNS recon pipeline, entered via `recon()` in `recon/main.py`. `passive_recon.py`
  fans out across `recon/providers/` (one subpackage per data source: `key_chaos`, `key_shodan`, `c99`,
  `subfinder`, `key_digitalyama`, `key_virustotal`, `securitytrails_web`, each exposing `_check`/`_scrap`,
  registered in a `PROVIDERS` list). `dns_recon.py` resolves CNAMEs/IPs, `web_fingerprinting.py` probes
  live hosts, `llm_permutations.py` uses `google-genai` to generate subdomain permutation wordlists.
- `enum/` — post-recon enumeration on a specific webapp: `crawler.py` (wraps `katana`, persists
  EndPoints/Parameters), `parameter_discovery.py` (heuristic param extraction), `archived_URLs.py`
  (wayback-style URL collection), `brute_force.py`.
- `scan/` — `webapp_analysis.py` orchestrates crawl → param discovery → archived URLs → JS download →
  route extraction and flips `WebApplication.analyzed`. `vuln_scan.py` orchestrates the `XSS/`, `SQLi/`,
  `open_redirect/`, `path_traversal/` scanner subpackages behind per-type on/off flags.
- `js_analysis/` — `js_downloader.py` pulls JS into `JSFile.content`; `route_extractor.py` extracts SPA
  routes into `ClientSideRoute`; `usage_summary.py`/`routes_analysis.py`/`code_review.py` each build a
  prompt, call `call_agent()`, and persist the agent's markdown output into the matching `JSFile` field.
  `tools/JavaScript-Sinks-Analyzer/` is a bundled Node static-analysis tool installed to `/opt/js-analyzer`.
- `fuzzer/` — `directory_fuzzer.py` wraps `ffuf`, persists discovered `EndPoint`s.
- `agents/call_agent.py` — subprocess wrapper selecting an AI CLI via the `AGENT` env var
  (`claude`, `gemini`, `codex`, or `xicode`/`deepcode` — the latter two invoke the `claude` binary but
  redirect it at third-party Claude-compatible endpoints via `ANTHROPIC_BASE_URL`/`ANTHROPIC_AUTH_TOKEN`).
  This is what the JS-analysis modules call into.
- `bins/` — vendored external tool binaries copied to `/usr/local/bin` at image build time: `anew`,
  `arjun`, `dnsx`, `ffuf`, `haktrailsfree`, `httpx`, `jsluice`, `katana`, `massdns`, `naabu`, `notify`,
  `puredns`, `sourcemapper`, `subfinder`, `x8`. `nuclei` is `go install`ed separately in the Dockerfile.
- `utilities/` — shared helpers: `declutter.py` (URL dedup/normalization), `enum.py` (`heuristic()`
  param detection, header parsing), `loaders.py` (build URL sets from the DB for scanning), `url_operations.py`.

### Views/URLs

`core/views.py` is plain Django (template `render()` + `JsonResponse` for AJAX endpoints) — no DRF or
django-ninja in use despite both being importable/in requirements. `/api/targets/<pk>/...` endpoints back
AJAX-driven filtering/pagination in templates, not a general-purpose REST API.

### The `agent/` directory — a *separate* persona, not repo-dev guidance

`agent/CLAUDE.md` (mirrored in `agent/AGENTS.md` and `agent/GEMINI.md`) is a **different set of
instructions** from this file: it's the system prompt for the AI agent *running inside the container*
as an actual bug bounty hunter, invoked via the terminal websocket or `call_agent()`. It tells that agent
to only report P4–P1 findings, how to query the Django models via `manage.py`, where wordlists live, and
how to use `x8`/`jsluice`/`katana`/`ffuf`. Do not merge that content into this file — it's guidance for
the hunting persona operating on a target, not for developing this codebase.

### Output/reports directories

`output/<target-domain>/` and `reports/` at the repo root accumulate real scan artifacts (subdomain
lists, fingerprints, JSON scan results, markdown findings) from past runs against real targets. These
are data, not code — don't treat their contents as fixtures or examples to follow structurally.
