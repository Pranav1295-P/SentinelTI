# SentinelTI

Autonomous threat intelligence platform by Relativity. Upload a suspicious file and five agents analyse it statically, then produce a verdict, an evidence graph and a PDF report. Samples are never executed.

## Architecture

```
Browser ─ Caddy ─ Uvicorn ─ FastAPI + Pydantic ─ service layer
                                    │
          PostgreSQL + SQLAlchemy + Alembic │ Redis │ Celery worker ─ LangGraph pipeline
                                                                       │
                                               LIEF · YARA · strings · Neo4j · VirusTotal · OTX
```

The pipeline is a LangGraph `StateGraph` in `app/agents/graph.py`:

| Agent | Job | Tools |
|---|---|---|
| 1 Triage | Real file type, hashes, size | `identify_file_type`, `compute_file_hashes`, `check_file_size` |
| 2 Evidence | Structured evidence | `parse_binary_metadata` (LIEF), `scan_yara_rules`, `extract_strings_and_iocs`, `decode_obfuscated_strings` (FLOSS, optional) |
| 3 Behaviour Hypothesis | Capabilities proven by evidence | `correlate_capabilities`, `inspect_imports`, `search_strings` |
| 4 Threat Context | ATT&CK, internal notes, reputation | `map_attack_techniques`, `search_threat_notes`, `lookup_hash_reputation` |
| 5 Explainability & PDF | Verify every fact, score, explain, graph, PDF | `verify_facts`, Neo4j matching, reportlab + pypdf |

Each of agents 1–4 is the same LangGraph loop (`app/agents/loop.py`): the LLM chooses tools, Pydantic validates the input, the tool runs, and evidence is collected. The LLM can investigate further but cannot skip a required tool.

## Trust model

- **The LLM never decides the verdict.** The risk score is arithmetic over verified evidence (`app/analysis/scoring.py`).
- **Every claim cites evidence.** Agent 5 re-checks each fact against the quarantined bytes. A capability that loses its evidence is demoted, and uncited sentences are removed.
- **File content is treated as hostile.** Strings reach the LLM inside a fence they cannot close, and text aimed at AI analysts is itself recorded as a finding.
- **Tools cannot be pointed elsewhere.** The sample path comes from graph state, not from LLM arguments.
- **Native parsers are isolated.** LIEF and YARA run in a throwaway process with resource limits and no secrets in its environment.
- **Samples stay in quarantine.** They are read-only, content-addressed and never served back. Only the hash goes to VirusTotal and OTX.
- **Analyses are private to their owner.** Graph matching is scoped the same way.

## Run it

Everything in Docker (site on http://localhost:8080):

```bash
cp .env.example .env     # then set SECRET_KEY and NEO4J_PASSWORD
docker compose up --build
docker compose exec api python -m app.cli create-user you@company.com
```

For development on the host (site on http://localhost:8020):

```bash
docker compose up -d postgres redis neo4j
uv sync
uv run alembic upgrade head
uv run python -m app.cli create-user you@company.com
uv run celery -A app.workers.celery_app worker --loglevel=INFO --concurrency=2
uv run uvicorn app.main:app --port 8020 --reload --reload-dir app
```

API docs are at `/api/docs` outside production. `GET /api/ready` shows which integrations are configured.

### Deploy with HTTPS

On a server with ports 80 and 443 open and a domain pointing at it, set these in `.env`:

```bash
SITE_ADDRESS=sentinelti.example.com
COOKIE_SECURE=true
```

Then start the stack with the production override. Caddy gets and renews the certificate itself:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
docker compose exec api python -m app.cli create-user you@company.com
```

The stack needs about 8 GB of RAM. Postgres, Redis and Neo4j only listen on the server itself, so keep every other port closed.

## API keys

All optional. Without them the pipeline still runs on its deterministic tools and rule-based explanations, and every result says which mode produced it.

| Setting | What it turns on |
|---|---|
| `LLM_MODEL`, `LLM_API_KEY` | Agents choose tools, investigate, write hypotheses and explanations, and answer free-form questions. `LLM_MODEL` is any `provider:model` for LangChain's `init_chat_model` (anthropic, groq, mistralai and openai are installed). |
| `VIRUSTOTAL_API_KEY` | Detection counts and family labels for the hash |
| `OTX_API_KEY` | AlienVault OTX threat pulses for the hash |
| `LANGSMITH_TRACING`, `LANGSMITH_API_KEY` | LangSmith traces. These contain sample-derived strings. |

## Extending

- **YARA rules:** add `.yar` files to `app/analysis/rules/`. A `family` meta field attributes a family. The starter rules detect techniques, not specific families, so family names only appear once you add rules or a VirusTotal key.
- **Threat notes:** add `## Heading` sections to `.md` files in `app/knowledge/`.
- **Capabilities:** add a `Rule` to `app/analysis/capabilities.py`.
- **FLOSS:** install it on the worker so `floss` is on the `PATH`; the Evidence Agent can then decode hidden strings.

## Tests

```bash
uv run pytest
uv run ruff check app tests
```

The tests need no services. They use synthetic, non-functional PE files, and a scripted model stands in for a hostile LLM.
