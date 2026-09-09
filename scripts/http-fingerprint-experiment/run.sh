#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "$SCRIPT_DIR/../.." && pwd)
STAMP=$(date +%Y%m%d-%H%M%S)
OUTPUT_DIR=${1:-"$ROOT_DIR/exp/http_fingerprint_no_header/$STAMP"}
BASE_URL=${BASE_URL:-http://localhost:8080}
if [[ -z "${DCID_HMAC_SECRET:-}" ]]; then
  DCID_HMAC_SECRET=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
fi
if [[ -z "${ACCOUNT_ID_HASH_KEY:-}" ]]; then
  ACCOUNT_ID_HASH_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
fi
export DCID_HMAC_SECRET ACCOUNT_ID_HASH_KEY

if [[ -e "$OUTPUT_DIR" ]]; then
  echo "Output directory already exists: $OUTPUT_DIR" >&2
  exit 1
fi
mkdir -p "$OUTPUT_DIR"
CLIENT_STATE_DIR=$(mktemp -d)
trap 'rm -rf "$CLIENT_STATE_DIR"' EXIT

wait_ready() {
  for _ in $(seq 1 90); do
    if curl --silent --show-error --fail "$BASE_URL/__detection/api/sessions" >/dev/null; then
      return 0
    fi
    sleep 1
  done
  echo "Detector did not become ready" >&2
  return 1
}

capture() {
  local destination=$1
  curl --silent --show-error --fail "$BASE_URL/__detection/api/export" > "$destination"
}

run_phase() {
  local round=$1
  local number=$2
  local subject=$3
  shift 3
  local round_dir="$OUTPUT_DIR/round-$round"
  local before="before-$number-$subject.json"
  local after="after-$number-$subject.json"
  mkdir -p "$round_dir"
  capture "$round_dir/$before"
  local started_at
  started_at=$(date +%s%3N)
  "$@"
  local ended_at
  ended_at=$(date +%s%3N)
  capture "$round_dir/$after"
  python3 "$SCRIPT_DIR/write_phase.py" "$round_dir/phase-$number-$subject.json" \
    --round "$round" --subject "$subject" \
    --started-at "$started_at" --ended-at "$ended_at" \
    --before "$before" --after "$after"
}

run_round() {
  local round=$1
  run_phase "$round" 1 browser-a \
    python3 "$SCRIPT_DIR/browser_client.py" --base-url "$BASE_URL" --profile "$CLIENT_STATE_DIR/browser-a"
  run_phase "$round" 2 urllib-a \
    python3 "$SCRIPT_DIR/http_client.py" --base-url "$BASE_URL" --cookie-jar "$CLIENT_STATE_DIR/urllib-a.txt"
  run_phase "$round" 3 urllib-b \
    python3 "$SCRIPT_DIR/http_client.py" --base-url "$BASE_URL" --cookie-jar "$CLIENT_STATE_DIR/urllib-b.txt"
  run_phase "$round" 4 urllib-stateless \
    python3 "$SCRIPT_DIR/http_client.py" --base-url "$BASE_URL" --stateless
}

docker compose -f "$ROOT_DIR/docker-compose.yml" up --detach --build
wait_ready
run_round 1

docker compose -f "$ROOT_DIR/docker-compose.yml" restart detection-proxy
wait_ready
run_round 2

python3 "$SCRIPT_DIR/evaluate.py" "$OUTPUT_DIR"
if rg -i 'x-attacker-id|x-experiment-run-id' "$OUTPUT_DIR"/round-*/*.json >/dev/null; then
  echo "Unexpected experiment label header found in captured artifacts" >&2
  exit 1
fi

echo "Experiment artifacts: $OUTPUT_DIR"
echo "Report: $OUTPUT_DIR/report.md"
