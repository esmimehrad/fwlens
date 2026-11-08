# fwlens

AI assistant for firewall configs and security logs: normalizes PAN-OS and FortiGate
rulebases into one schema, runs SQL hygiene checks, and answers questions with a
tool-using agent grounded in vendor best-practice docs.

Work in progress. See [docs/architecture.md](docs/architecture.md).

## Quickstart

Requires Docker and [uv](https://docs.astral.sh/uv/).

```bash
docker compose up -d            # Postgres 16 + pgvector on 127.0.0.1:5432
uv sync
uv run fwlens db upgrade        # create the schema
uv run fwlens load-samples      # synthetic PAN-OS + FortiGate configs and 7 days of logs
```

Load your own (lab/synthetic) files with `uv run fwlens load-config <file>` and
`uv run fwlens load-logs <file>`. Reloading a config replaces that device; reloading
the same log file is skipped.

## Dev

```bash
uv run ruff check .
uv run pytest                   # db tests skip if Postgres isn't running
uv run python -m fwlens.samplegen   # regenerate sample logs after changing sample configs
```
