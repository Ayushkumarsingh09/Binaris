# Developer guide

## Prerequisites

- Rust 1.75+
- Node 20+
- Optional: Docker, Postgres, Redis, MinIO
- Windows: Visual Studio Build Tools with **Desktop development with C++** (provides `link.exe`)

## Run API (dev)

```powershell
$env:BINARIS_INLINE_ANALYZE="true"
$env:BINARIS_STORAGE_PATH="./data/objects"
$env:RUST_LOG="info"
cargo run -p binaris-api
```

## Run web

```powershell
cd apps/web
npm install
npm run dev
```

## Tests

```powershell
cargo test -p binaris-analysis -p binaris-malware -p binaris-security -p binaris-auth
cd apps/web; npm run typecheck
```

## AI providers

Set `BINARIS_AI_PROVIDER` + `BINARIS_AI_API_KEY`. Without keys, the local evidence engine answers chat and performs semantic renames deterministically.
