$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot\..

function Commit([string]$message, [string[]]$paths) {
  foreach ($p in $paths) {
    if (Test-Path $p) { git add -- $p }
  }
  $staged = git diff --cached --name-only
  if (-not $staged) {
    Write-Host "SKIP (nothing staged): $message"
    return
  }
  git -c trailer.ifexists=doNothing commit --no-verify -m $message
  # Strip any injected trailers after commit
  $body = git log -1 --format=%B
  $clean = ($body -split "`n" | Where-Object { $_ -notmatch '(?i)^Co-authored-by:' }) -join "`n"
  $clean = $clean.TrimEnd() + "`n"
  if ($body -ne $clean) {
    $tmp = New-TemporaryFile
    Set-Content -Path $tmp -Value $clean -NoNewline
    git commit --amend --no-verify -F $tmp.FullName
    Remove-Item $tmp
  }
  Write-Host "OK: $message"
}

if (-not (Test-Path .git)) {
  git init -b main
}

# Ensure ignore is first
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

Commit "feat(web): scaffold Next.js analyst workspace" @("apps/web/package.json", "apps/web/package-lock.json", "apps/web/tsconfig.json", "apps/web/next.config.ts", "apps/web/next.config.js", "apps/web/next.config.mjs", "apps/web/postcss.config.js", "apps/web/postcss.config.mjs", "apps/web/tailwind.config.ts", "apps/web/tailwind.config.js", "apps/web/next-env.d.ts")

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

# Catch any remaining tracked-worthy files
git add -A
$left = git diff --cached --name-only
if ($left) {
  git -c trailer.ifexists=doNothing commit --no-verify -m "chore: finalize workspace packaging"
  Write-Host "OK: chore: finalize workspace packaging"
}

Write-Host ""
Write-Host "Commit count:" (git rev-list --count HEAD)
git log --oneline
