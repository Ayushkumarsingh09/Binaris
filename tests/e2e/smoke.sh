#!/usr/bin/env bash
set -euo pipefail
API="${BINARIS_API_URL:-http://127.0.0.1:8080}"

echo "[e2e] health"
curl -sf "$API/healthz" >/dev/null

echo "[e2e] login"
TOKEN=$(curl -sf -X POST "$API/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"email":"demo@binaris.dev","password":"demo-password-change-me"}' | python -c 'import sys,json;print(json.load(sys.stdin)["token"])')

echo "[e2e] upload"
printf 'MZ\0\0https://evil.example/c2 AES-ECB password=hunter2 CryptEncrypt bitcoin ransom' > /tmp/binaris-sample.bin
REPORT=$(curl -sf -X POST "$API/v1/projects/01900000-0000-7000-8000-000000000003/upload" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@/tmp/binaris-sample.bin;type=application/octet-stream")
ID=$(echo "$REPORT" | python -c 'import sys,json;print(json.load(sys.stdin)["id"])')

echo "[e2e] chat"
curl -sf -X POST "$API/v1/analyses/$ID/chat" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"message":"Show encryption"}' >/dev/null

echo "[e2e] snapshot"
curl -sf -X POST "$API/v1/analyses/$ID/snapshots" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"label":"e2e"}' >/dev/null

echo "[e2e] graphql"
curl -sf -X POST "$API/v1/graphql" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"query\":\"query($id:ID!){ analysis(id:$id){ sha256 } }\",\"variables\":{\"id\":\"$ID\"}}" >/dev/null

echo "[e2e] OK analysis=$ID"
