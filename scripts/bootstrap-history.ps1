$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot\..

$Git = "C:\Program Files\Git\bin\git.exe"
if (-not (Test-Path $Git)) { $Git = "git" }

function Commit([string]$message, [string[]]$paths) {
  foreach ($p in $paths) {
    if (Test-Path $p) { & $Git add -- $p }
  }
  $staged = & $Git diff --cached --name-only
  if (-not $staged) {
    Write-Host "SKIP (nothing staged): $message"
    return
  }
  $env:GIT_AUTHOR_NAME = "Ayush"
  $env:GIT_AUTHOR_EMAIL = "ayushkumarsingh9903@gmail.com"
  $env:GIT_COMMITTER_NAME = "Ayush"
  $env:GIT_COMMITTER_EMAIL = "ayushkumarsingh9903@gmail.com"
  $tree = & $Git write-tree
  $parent = & $Git rev-parse HEAD
  $msgFile = Join-Path $env:TEMP ("binaris-msg-" + [guid]::NewGuid().ToString() + ".txt")
  [IO.File]::WriteAllText($msgFile, $message.TrimEnd() + "`n")
  if (& $Git rev-parse --verify HEAD 2>$null) {
    $sha = Get-Content -Raw $msgFile | & $Git commit-tree $tree -p $parent
  } else {
    $sha = Get-Content -Raw $msgFile | & $Git commit-tree $tree
  }
  Remove-Item $msgFile -Force
  & $Git update-ref HEAD $sha
  Write-Host "OK: $message"
}

if (-not (Test-Path .git)) {
  & $Git init -b main
}

Commit "chore: initialize repository ignore rules" @(".gitignore", ".dockerignore")
Commit "chore: add Rust workspace manifest and lockfile" @("Cargo.toml", "Cargo.lock")
Commit "feat(core): add domain types, pipeline stages, and evidence model" @("crates/binaris-core")
Commit "feat(analysis): add format parsers, hashing, strings, and Capstone disasm" @("crates/binaris-analysis")
Commit "feat(security): add unsafe API, secret, and weak-crypto detectors" @("crates/binaris-security")
Commit "feat(malware): add family classification with evidence" @("crates/binaris-malware")
Commit "feat(ai): add evidence-bound chat and rename providers" @("crates/binaris-ai")
Commit "feat(graphs): add call, CFG, and import graph builders" @("crates/binaris-graphs")
Commit "feat(reports): add Markdown, HTML, JSON, SARIF, and PDF exporters" @("crates/binaris-reports")
Commit "feat(pipeline): wire staged analysis orchestration" @("crates/binaris-pipeline")
Commit "feat(db): add memory store and Postgres adapters" @("crates/binaris-db")
Commit "feat(storage): add local object storage backend" @("crates/binaris-storage")
Commit "feat(auth): add JWT register, login, and OAuth helpers" @("crates/binaris-auth")
Commit "feat(decomp): add Capstone pseudocode and external decompiler adapters" @("crates/binaris-decomp")
Commit "feat(network): add GeoIP, RDAP, and C2 heuristics" @("crates/binaris-network")
Commit "feat(diff): add snapshots, report diff, and restore" @("crates/binaris-diff")
Commit "feat(api): add Axum REST API, health, and metrics" @("apps/api")
Commit "feat(worker): add Redis-backed analysis worker" @("apps/worker")
Commit "feat(cli): add Binaris command-line client" @("apps/cli")
Commit "feat(web): scaffold Next.js analyst workspace" @("apps/web/package.json", "apps/web/package-lock.json", "apps/web/tsconfig.json", "apps/web/next.config.ts", "apps/web/postcss.config.js", "apps/web/tailwind.config.ts", "apps/web/next-env.d.ts")
Commit "feat(web): add analysis panels, graphs, chat, and auth UI" @("apps/web/src", "apps/web/public")
Commit "feat(sdk): add Python client SDK" @("sdks/python")
Commit "feat(sdk): add Rust client SDK" @("sdks/rust")
Commit "feat(db): add Postgres schema migration" @("migrations")
Commit "feat(infra): add Dockerfiles, Compose, and Kubernetes manifests" @("infra", "docker-compose.yml", "fly.toml")
Commit "ci: add GitHub Actions workflow" @(".github")
Commit "test: add end-to-end smoke script and fixtures" @("tests")
Commit "docs: add architecture and developer guides" @("docs/ARCHITECTURE.md", "docs/DEVELOPER.md")
Commit "chore: add branding assets" @("branding")
Commit "chore: add environment template and MIT license" @(".env.example", "LICENSE")
Commit "docs: add GitHub Pages landing with Mermaid diagrams" @("docs/index.html", "docs/live-links.js", "docs/assets")
Commit "docs: publish project README with architecture diagrams" @("README.md")

& $Git add -A
$left = & $Git diff --cached --name-only
if ($left) {
  Commit "chore: finalize workspace packaging" @(".")
}

Write-Host ""
Write-Host "Commit count:" (& $Git rev-list --count HEAD)
& $Git log --oneline
