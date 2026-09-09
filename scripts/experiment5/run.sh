#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "$SCRIPT_DIR/../.." && pwd)
SUBJECT="codex"
RUN_NUMBER="1"
RESET_STACK="true"

usage() {
  echo "Usage: $0 [--subject codex|claude] [--run N] [--no-reset]"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --subject) SUBJECT="$2"; shift 2 ;;
    --run) RUN_NUMBER="$2"; shift 2 ;;
    --no-reset) RESET_STACK="false"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ ! "$RUN_NUMBER" =~ ^[1-9][0-9]*$ ]]; then
  echo "--run must be a positive integer" >&2
  exit 2
fi

case "$SUBJECT" in
  codex)
    SUBJECT_NUMBER="2"
    SUBJECT_KO="코덱스"
    ;;
  claude)
    SUBJECT_NUMBER="3"
    SUBJECT_KO="클로드"
    ;;
  *)
    echo "--subject must be codex or claude" >&2
    exit 2
    ;;
esac

PADDED_RUN=$(printf "%03d" "$RUN_NUMBER")
RUN_ID="${SUBJECT}-signup-login-review-005-${PADDED_RUN}"
EMAIL="${SUBJECT}5-${PADDED_RUN}@test.com"
PASSWORD="$EMAIL"
OUTPUT_DIR="$ROOT_DIR/exp/05_회원가입_로그인_리뷰/5-${SUBJECT_NUMBER}${SUBJECT_KO}${RUN_NUMBER}"

if [[ -e "$OUTPUT_DIR" ]]; then
  echo "Output directory already exists: $OUTPUT_DIR" >&2
  exit 1
fi
mkdir -p "$OUTPUT_DIR"

PROMPT=$(<"$SCRIPT_DIR/prompt.txt.tmpl")
PROMPT=${PROMPT//\{\{EMAIL\}\}/$EMAIL}
PROMPT=${PROMPT//\{\{PASSWORD\}\}/$PASSWORD}
PROMPT=${PROMPT//\{\{RUN_ID\}\}/$RUN_ID}
printf '%s\n' "$PROMPT" > "$OUTPUT_DIR/prompt.txt"

if [[ "$RESET_STACK" == "true" ]]; then
  docker compose -f "$ROOT_DIR/docker-compose.yml" down --remove-orphans
  docker compose -f "$ROOT_DIR/docker-compose.yml" up -d --build
fi

READY="false"
for _ in $(seq 1 60); do
  if curl -fsS "http://localhost:8080/__detection/api/sessions" >/dev/null 2>&1; then
    READY="true"
    break
  fi
  sleep 1
done
if [[ "$READY" != "true" ]]; then
  echo "Detector did not become ready" >&2
  exit 1
fi

SCRATCH_DIR=$(mktemp -d)
trap 'rm -rf "$SCRATCH_DIR"' EXIT
TRACE_JSONL="$OUTPUT_DIR/추론과정.jsonl"

set +e
if [[ "$SUBJECT" == "codex" ]]; then
  codex exec \
    --ignore-user-config \
    --ephemeral \
    --skip-git-repo-check \
    --json \
    --color never \
    --dangerously-bypass-approvals-and-sandbox \
    -C "$SCRATCH_DIR" \
    - < "$OUTPUT_DIR/prompt.txt" | tee "$TRACE_JSONL"
  AGENT_EXIT=${PIPESTATUS[0]}
else
  (
    cd "$SCRATCH_DIR"
    claude --print \
      --output-format stream-json \
      --verbose \
      --no-session-persistence \
      --safe-mode \
      --tools Bash \
      --dangerously-skip-permissions \
      "$PROMPT"
  ) | tee "$TRACE_JSONL"
  AGENT_EXIT=${PIPESTATUS[0]}
fi
set -e

python3 "$SCRIPT_DIR/render_trace.py" "$TRACE_JSONL" "$OUTPUT_DIR/추론과정.txt"
printf '%s\n' "$AGENT_EXIT" > "$OUTPUT_DIR/agent-exit-code.txt"

curl -fsS "http://localhost:8080/__detection/api/export" > "$OUTPUT_DIR/detection-log-export.json"
curl -fsS "http://localhost:8080/__detection/api/actors" > "$OUTPUT_DIR/actors.json"
curl -fsS "http://localhost:8080/__detection/api/sessions" > "$OUTPUT_DIR/sessions.json"
curl -fsS "http://localhost:8080/__detection/api/auth-groups" > "$OUTPUT_DIR/auth-groups.json"
curl -fsS "http://localhost:8080/__detection/api/ip-entries" > "$OUTPUT_DIR/ip-entries.json"

python3 "$SCRIPT_DIR/capture_dashboard.py" --output-dir "$OUTPUT_DIR"
python3 "$SCRIPT_DIR/build_metadata.py" \
  --output-dir "$OUTPUT_DIR" \
  --run-id "$RUN_ID" \
  --subject "$SUBJECT" \
  --email "$EMAIL" \
  --agent-exit "$AGENT_EXIT"

echo "Experiment artifacts: $OUTPUT_DIR"
echo "Validation: $OUTPUT_DIR/validation.json"
exit "$AGENT_EXIT"
