# Architecture

Every vendor's config is normalized into one `Rule` model at the parser boundary;
everything downstream (SQL checks, agent, API) only sees the vendor-neutral schema.

```mermaid
flowchart LR
    subgraph Inputs
        PAN[PAN-OS XML]
        FGT[FortiGate CLI config]
        LOG[Syslog traffic logs]
        DOCS[Vendor best-practice docs]
    end

    subgraph Ingest
        PP[parsers/panos.py]
        FP[parsers/fortigate.py]
        SP[parsers/syslog.py]
        RI[rag/ingest.py<br/>chunk + Titan embeddings]
    end

    subgraph Postgres["Postgres 16 + pgvector"]
        RULES[(rules, address/service objects)]
        EVENTS[(log_events)]
        VEC[(doc_chunks + vectors)]
    end

    subgraph Analysis
        SQL[analysis/checks.sql<br/>any-any, shadowed, duplicate,<br/>zero-hit, logging-off]
    end

    subgraph Agent["Agent (hand-written tool-use loop)"]
        LOOP[agent/loop.py<br/>Claude on Bedrock]
        TOOLS[agent/tools.py<br/>run_checks, query_rules, query_logs,<br/>search_docs, explain_block,<br/>propose_rule_change]
    end

    subgraph Interfaces
        API[FastAPI]
        UI[Streamlit]
    end

    PAN --> PP --> RULES
    FGT --> FP --> RULES
    LOG --> SP --> EVENTS
    DOCS --> RI --> VEC

    RULES --> SQL
    EVENTS --> SQL

    LOOP <--> TOOLS
    TOOLS --> SQL
    TOOLS --> RULES
    TOOLS --> EVENTS
    TOOLS --> VEC

    UI --> API --> LOOP
    API --> SQL
```

`propose_rule_change` only suggests changes; nothing is ever applied to a device.
