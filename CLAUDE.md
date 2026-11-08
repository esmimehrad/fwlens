# fwlens: AI assistant for firewall configs and security logs

## Why this project exists
Portfolio project for Mehrad, who is targeting Forward Deployed Engineer roles
(secondary: Solutions / Implementation / Customer Engineer). Background: MEng Computer
Networks; strong in Palo Alto PAN-OS, FortiGate, Cisco, Kubernetes, AWS.
This project must close three gaps with evidence an interviewer can check:
production Python, SQL / data pipelines, and LLM apps (RAG + agents).

## How to work with me (read first)
- Pair-programmer mode. Explain the plan for each step before writing code, then
  explain what you wrote. I need to defend every line in interviews.
- I write these myself; you review and suggest fixes, you do not write them for me:
  1. the SQL rule checks in `src/fwlens/analysis/checks.sql`
  2. the agent tool-use loop in `src/fwlens/agent/loop.py`
- Everywhere else, scaffold and implement freely, but keep diffs small: one step at a time.
- Every step ends with: tests passing, `ruff` clean, one git commit with a clear message.
- At the end of each session, update the "Progress" section at the bottom of this file.

## Hard rules
- Synthetic or lab data only. Never real employer or client configs.
- No secrets in the repo. AWS auth comes from my local AWS CLI profile / IAM role.
  `.env` is gitignored; commit `.env.example` only.
- Ask before any AWS action that costs money (creating EC2, RDS, ECS, ECR resources).
  Prefer the smallest instance sizes. Tear-down commands go in `docs/teardown.md`.
- Ask before deleting files or rewriting git history.

## Stack
- Python 3.12, `uv`, `ruff`, `pytest`, pydantic v2
- Parsing: `lxml` for PAN-OS XML; custom parser for FortiGate `config/edit/set/next/end`
- Postgres 16 + pgvector; SQLAlchemy 2.0; Alembic migrations
- LLM: Claude on Amazon Bedrock; embeddings: Amazon Titan Text Embeddings (via boto3)
- Agent: hand-written tool-use loop (no LangChain / LlamaIndex)
- API: FastAPI; UI: Streamlit
- Local: Docker Compose (app + pgvector/pgvector:pg16)
- Deploy: Docker Compose on a single EC2 instance first; ECS Fargate + RDS is a stretch goal
- CI: GitHub Actions (ruff, pytest, docker build, push to ECR)

## Core design decision: vendor-neutral schema
Every vendor's rules are normalized into one `Rule` model; everything downstream uses only it.
- `Rule`: id, vendor, device, name, position, src_zones, dst_zones, src_addrs, dst_addrs,
  services, applications, action (allow/deny/drop), enabled, log, hit_count
- `AddressObject`, `ServiceObject` (resolve groups to members)
- `LogEvent`: timestamp, device, src_ip, dst_ip, dst_port, protocol, rule_name, action, bytes

## Repo layout
```
fwlens/
├── README.md  pyproject.toml  Dockerfile  docker-compose.yml  .env.example
├── .github/workflows/ci.yml
├── migrations/
├── docs/                      # architecture.png, teardown.md
├── data/samples/{panos,fortigate,logs}/   data/docs/
├── src/fwlens/
│   ├── models.py
│   ├── parsers/{panos,fortigate,syslog}.py
│   ├── db/{session,load}.py
│   ├── analysis/{checks.sql,checks.py}
│   ├── rag/{ingest,retrieve}.py
│   ├── agent/{tools,loop}.py
│   ├── api/main.py
│   └── ui/app.py
├── evals/{cases/,run_evals.py}
└── tests/
```

## Sample data strategy
Generate synthetic PAN-OS and FortiGate configs with deliberately seeded flaws
(any-any allow, rule shadowed by an earlier broader rule, duplicate rules, disabled-but-referenced
objects, allow rules with logging off). Generate syslog where some rules get zero hits.
Each seeded flaw is recorded in `evals/cases/*.json` so the same data is both test input
and ground truth.

## Steps (Phase 2)
- [x] 5. Repo, tooling, CI skeleton, architecture diagram in `docs/`
- [x] 6. `models.py` + PAN-OS and FortiGate parsers + tests
- [x] 7. Syslog parser + sample log generator + tests
- [ ] 8. Postgres schema (Alembic) + loader; `docker compose up` works   <- milestone, week 2
- [ ] 9. SQL rule checks: any-any, shadowed, duplicate, zero-hit, logging-off (Mehrad writes)
- [ ] 10. RAG: chunk + embed vendor best-practice docs into pgvector; retrieval with citations
- [ ] 11. Agent with tools: run_checks, query_rules, query_logs, search_docs,
          explain_block(src, dst, port), propose_rule_change (suggest only, never apply)
          (loop written by Mehrad)                                          <- milestone, week 4
- [ ] 12. Evals: 20-30 labeled cases; report precision/recall for checks and
          answer accuracy for the agent; results table in README
- [ ] 13. FastAPI endpoints (upload config, list findings, ask question) + Streamlit UI
- [ ] 14. Dockerize, deploy to EC2, CI pushes image to ECR
- [ ] 15. README as a client engagement: problem, approach, architecture, results
          (eval numbers), how to run, limitations; record a 2-minute demo   <- milestone, week 6
- [ ] 16. Draft one resume bullet (problem -> solution -> result) using real eval numbers

## Definition of done
A stranger can clone the repo, run `docker compose up`, load the sample configs, and get
findings plus agent answers. The README shows measured results, not claims.

## Progress
(Update at the end of each session: date, steps completed, open issues, next step.)

- 2026-11-07: Installed uv 0.13.7, Python 3.12.16 (uv-managed), Docker Desktop (WSL2).
  Step 5 done: uv project (src layout, py3.12 pin), ruff + pytest config, package skeleton,
  smoke tests, CI (ruff + pytest), Mermaid diagram in `docs/architecture.md`.
  Repo: https://github.com/esmimehrad/fwlens (public); first CI run green.
  Open: `docs/architecture.png` export still to do.
  Note: run `uv python install` and `gh` commands from a normal terminal, not inside the
  Claude desktop app (its AppData writes are redirected and it can't see the gh login).
  Next: Step 6 (`models.py` + PAN-OS / FortiGate parsers + tests).
- 2026-11-08: Step 6 done in three commits (6a models, 6b PAN-OS + group resolver,
  6c FortiGate). Synthetic samples with seeded flaws in `data/samples/{panos,fortigate}/`.
  ServiceObject changed from protocol+ports to `entries` ("tcp/53", "udp/53", "icmp")
  because FortiGate services mix protocols.
  Known limits (raise ValueError): PAN-OS multi-vsys / negate / dynamic groups / Panorama;
  FortiGate multi-VDOM / negate / internet-service / geography+wildcard addresses.
  FortiGate logtraffic "utm" counts as logging on (only "disable" is off) - revisit at Step 9.
  Next: Step 7 (syslog parser + sample log generator + tests; adds LogEvent).
- 2026-11-08: Step 7 done (7a LogEvent + Rule.vendor_id, 7b syslog parser, 7c generator).
  Sample logs: `data/samples/logs/{lab-fw01,lab-fgt01}.log`, 1000 sessions each, regenerate
  with `uv run python -m fwlens.samplegen` (a test fails if they drift).
  Zero-hit ground truth: `NO_TRAFFIC` in `samplegen.py` + disabled rules + logging-off rules
  (allow-ntp has traffic but no logs: Step 9 must not call it "unused" without caveat).
  Open: PAN-OS CSV field positions come from docs, not a real device; verify against one
  real lab log line if possible.
  Next: Step 8 (Postgres schema via Alembic + loader; `docker compose up` works).
