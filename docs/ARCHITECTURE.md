# Binaris Architecture

## Overview

Binaris is a modular reverse-engineering platform:

1. **Ingestion** — authenticated upload to object storage; metadata in Postgres/memory store
2. **Pipeline** — staged analysis with progress events
3. **Engines** — independent Rust crates for static analysis, security, malware, graphs, reports, AI
4. **API** — Axum REST + metrics/health; optional Redis queue
5. **Worker** — consumes analysis jobs when inline mode is disabled
6. **Web** — Next.js analyst workspace with dockable panels, graphs, Monaco, chat

## Pipeline stages

`queued → hashing → identification → unpacking → static_analysis → disassembly → graph_construction → function_extraction → string_extraction → import_export_analysis → resource_extraction → ai_semantic → security_analysis → malware_analysis → report_generation → chat_indexing → completed`

## Evidence contract

All AI-facing claims should attach `binaris_core::Evidence` variants (function, import, string, entropy, etc.). Chat retrieval answers from the analysis report first; external LLMs refine wording without inventing facts.

## Storage

- **Hot path / local:** `MemoryStore` + `LocalObjectStore`
- **Production:** Postgres (`migrations/001_init.sql`) + S3-compatible object store + Redis queue

## Extensibility

New detectors belong in focused crates (`binaris-security`, `binaris-malware`, …) and are wired in `binaris-pipeline`. Decompiler backends (Ghidra headless, Rizin) can be added as optional adapters behind the same `FunctionAnalysis` / graph types.
