# fwlens

AI assistant for firewall configs and security logs: normalizes PAN-OS and FortiGate
rulebases into one schema, runs SQL hygiene checks, and answers questions with a
tool-using agent grounded in vendor best-practice docs.

Work in progress. See [docs/architecture.md](docs/architecture.md).

## Dev setup

```bash
uv sync
uv run ruff check .
uv run pytest
```
