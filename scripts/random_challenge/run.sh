#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd -- "$SCRIPT_DIR/../.." && pwd)
RUN_NUMBER=${1:-1}
if ! [[ "$RUN_NUMBER" =~ ^[1-9][0-9]*$ ]]; then
  echo "Usage: $0 [positive-run-number]" >&2
  exit 2
fi

OUTPUT_DIR="$ROOT_DIR/exp/06_랜덤_챌린지/6-2솔미디엄${RUN_NUMBER}"
RUN_ID=$(printf 'sol-medium-random-challenge-006-%03d' "$RUN_NUMBER")
if [[ -e "$OUTPUT_DIR" ]]; then
  echo "Output directory already exists: $OUTPUT_DIR" >&2
  exit 2
fi
mkdir -p "$OUTPUT_DIR"

docker compose -f "$ROOT_DIR/docker-compose.yml" down --remove-orphans
docker compose -f "$ROOT_DIR/docker-compose.yml" up -d --build

READY=false
for _ in $(seq 1 60); do
  if curl -fsS "http://localhost:8080/__detection/api/sessions" >/dev/null 2>&1; then
    READY=true
    break
  fi
  sleep 1
done
if [[ "$READY" != true ]]; then
  echo "Detector did not become ready" >&2
  exit 1
fi

JUICE_READY=false
for _ in $(seq 1 60); do
  if docker exec juice-shop /nodejs/bin/node -e \
    'fetch("http://127.0.0.1:3000/api/Challenges").then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))' \
    >/dev/null 2>&1; then
    JUICE_READY=true
    break
  fi
  sleep 1
done
if [[ "$JUICE_READY" != true ]]; then
  echo "Juice Shop challenge API did not become ready" >&2
  exit 1
fi

docker exec juice-shop /nodejs/bin/node -e \
  'fetch("http://127.0.0.1:3000/api/Challenges").then(r=>r.text()).then(console.log)' \
  > "$OUTPUT_DIR/challenges-before-all.json"

SELECTION=$(python3 "$SCRIPT_DIR/prepare_experiment.py" \
  --challenges "$OUTPUT_DIR/challenges-before-all.json" \
  --template "$SCRIPT_DIR/prompt.txt.tmpl" \
  --output-dir "$OUTPUT_DIR" \
  --run-id "$RUN_ID")
CHALLENGE_KEY=$(printf '%s' "$SELECTION" | jq -r '.challenge.key')
jq --arg key "$CHALLENGE_KEY" '.data[] | select(.key == $key)' \
  "$OUTPUT_DIR/challenges-before-all.json" > "$OUTPUT_DIR/challenge-before.json"

SCRATCH_DIR=$(mktemp -d)
trap 'rm -rf "$SCRATCH_DIR"' EXIT
TRACE_JSONL="$OUTPUT_DIR/추론과정.jsonl"
CODEX_VERSION=$(codex --version | tr -d '\r')

set +e
timeout --signal=TERM 1200 codex exec \
  --ignore-user-config \
  --ephemeral \
  --skip-git-repo-check \
  --json \
  --color never \
  --model gpt-5.6-sol \
  -c 'model_reasoning_effort="medium"' \
  --dangerously-bypass-approvals-and-sandbox \
  -C "$SCRATCH_DIR" \
  - < "$OUTPUT_DIR/prompt.txt" \
  | python3 "$SCRIPT_DIR/sanitize_jsonl.py" \
  | tee "$TRACE_JSONL"
AGENT_EXIT=${PIPESTATUS[0]}
set -e
printf '%s\n' "$AGENT_EXIT" > "$OUTPUT_DIR/agent-exit-code.txt"

python3 "$ROOT_DIR/scripts/experiment5/render_trace.py" \
  "$TRACE_JSONL" "$OUTPUT_DIR/추론과정.txt"

docker exec juice-shop /nodejs/bin/node -e \
  'fetch("http://127.0.0.1:3000/api/Challenges").then(r=>r.text()).then(console.log)' \
  > "$OUTPUT_DIR/challenges-after-all.json"
jq --arg key "$CHALLENGE_KEY" '.data[] | select(.key == $key)' \
  "$OUTPUT_DIR/challenges-after-all.json" > "$OUTPUT_DIR/challenge-after.json"

curl -fsS "http://localhost:8080/__detection/api/export" > "$OUTPUT_DIR/detection-log-export.json"
curl -fsS "http://localhost:8080/__detection/api/actors" > "$OUTPUT_DIR/actors.json"
curl -fsS "http://localhost:8080/__detection/api/sessions" > "$OUTPUT_DIR/sessions.json"
curl -fsS "http://localhost:8080/__detection/api/auth-groups" > "$OUTPUT_DIR/auth-groups.json"
curl -fsS "http://localhost:8080/__detection/api/ip-entries" > "$OUTPUT_DIR/ip-entries.json"

python3 "$ROOT_DIR/scripts/experiment5/capture_dashboard.py" --output-dir "$OUTPUT_DIR"
python3 "$SCRIPT_DIR/build_metadata.py" \
  --output-dir "$OUTPUT_DIR" \
  --run-id "$RUN_ID" \
  --agent-exit "$AGENT_EXIT" \
  --codex-version "$CODEX_VERSION"

cat "$OUTPUT_DIR/validation.json"
exit 0
