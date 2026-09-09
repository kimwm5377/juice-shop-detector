#!/usr/bin/env python3
"""Build a challenge-run report from detector and verifier artifacts."""

import argparse
import json
import subprocess
from collections import Counter
from datetime import datetime
from pathlib import Path


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def requests_for(sessions, run_id):
    rows = []
    for session in sessions:
        for request in session.get("requests") or session.get("analysis", {}).get("requests", []):
            if request.get("experimentRunId") == run_id:
                rows.append(request)
    return sorted(rows, key=lambda row: row.get("ts", 0))


def has_run(record, run_id):
    features = record.get("features") or record.get("analysis", {}).get("features") or {}
    return run_id in features.get("experimentRunIds", [])


def format_time(timestamp):
    if not timestamp:
        return "-"
    return datetime.fromtimestamp(timestamp / 1000).astimezone().isoformat(timespec="milliseconds")


def git_value(output_dir, *args):
    try:
        return subprocess.check_output(["git", *args], cwd=output_dir, text=True).strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--agent-exit", required=True, type=int)
    parser.add_argument("--codex-version", required=True)
    args = parser.parse_args()

    sessions = load(args.output_dir / "detection-log-export.json")
    actors = load(args.output_dir / "actors.json")
    auth_groups = load(args.output_dir / "auth-groups.json")
    selection = load(args.output_dir / "selected-challenge.json")
    before = load(args.output_dir / "challenge-before.json")
    after = load(args.output_dir / "challenge-after.json")
    challenge = selection["challenge"]
    rows = requests_for(sessions, args.run_id)
    matched_sessions = [item for item in sessions if has_run(item, args.run_id)]
    matched_actors = [item for item in actors if has_run(item, args.run_id)]
    matched_auth = [item for item in auth_groups if has_run(item, args.run_id)]
    solved = not bool(before.get("solved")) and bool(after.get("solved"))

    method_counts = Counter(row.get("method") for row in rows)
    status_counts = Counter(str(row.get("status")) for row in rows)
    duration_ms = rows[-1]["ts"] - rows[0]["ts"] if len(rows) >= 2 else 0
    actor = matched_actors[0] if len(matched_actors) == 1 else None
    features = (actor or {}).get("features", {})

    validation = {
        "runId": args.run_id,
        "model": "gpt-5.6-sol",
        "reasoningEffort": "medium",
        "agentExitCode": args.agent_exit,
        "challengeId": challenge["id"],
        "challengeKey": challenge["key"],
        "challengeName": challenge["name"],
        "beforeSolved": bool(before.get("solved")),
        "afterSolved": bool(after.get("solved")),
        "solvedDuringRun": solved,
        "requestCount": len(rows),
        "sessionCount": len(matched_sessions),
        "actorCount": len(matched_actors),
        "authGroupCount": len(matched_auth),
    }
    (args.output_dir / "validation.json").write_text(
        json.dumps(validation, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    lines = [
        "# 랜덤 챌린지 실험 메타데이터",
        "",
        "## 실행 식별",
        "",
        f"- 모델: `gpt-5.6-sol`",
        f"- Reasoning Effort: `medium`",
        f"- Codex CLI: `{args.codex_version}`",
        f"- Experiment Run ID: `{args.run_id}`",
        f"- Git branch: `{git_value(args.output_dir, 'branch', '--show-current')}`",
        f"- Git commit: `{git_value(args.output_dir, 'rev-parse', '--short', 'HEAD')}`",
        f"- 랜덤 시드: `{selection['seed']}`",
        f"- 후보 수: {selection['candidateCount']}",
        "",
        "## 선택된 챌린지",
        "",
        f"- 이름: {challenge['name']}",
        f"- Key: `{challenge['key']}`",
        f"- 카테고리: {challenge['category']}",
        f"- 난이도: {challenge['difficulty']}",
        f"- 설명: {challenge['description']}",
        f"- 실행 전 solved: {bool(before.get('solved'))}",
        f"- 실행 후 solved: {bool(after.get('solved'))}",
        f"- 최종 판정: {'성공' if solved else '미해결'}",
        "",
        "## 요청 및 Grouping",
        "",
        f"- 요청 수: {len(rows)}",
        f"- 첫 요청: {format_time(rows[0]['ts']) if rows else '-'}",
        f"- 마지막 요청: {format_time(rows[-1]['ts']) if rows else '-'}",
        f"- 관찰 시간: {duration_ms / 1000:.3f}초",
        f"- Session 수: {len(matched_sessions)}",
        f"- Actor Candidate 수: {len(matched_actors)}",
        f"- Auth Group 수: {len(matched_auth)}",
        f"- Method 분포: {dict(method_counts)}",
        f"- Status 분포: {dict(status_counts)}",
        f"- Authorization 포함 요청: {sum(bool(row.get('hasAuthorization')) for row in rows)}",
        "",
    ]
    if actor:
        lines.extend([
            "## Actor 단위 Feature",
            "",
            f"- Automation Score: {actor.get('automationScore', 0) * 100:.1f}",
            f"- Attack Score: {actor.get('attackScore', 0) * 100:.1f}",
            f"- Temporal: `{json.dumps(features.get('temporal', {}), ensure_ascii=False)}`",
            f"- Behavior: `{json.dumps(features.get('behavior', {}), ensure_ascii=False)}`",
            f"- Exploration: `{json.dumps(features.get('exploration', {}), ensure_ascii=False)}`",
            f"- Client: `{json.dumps(features.get('client', {}), ensure_ascii=False)}`",
            f"- Attack: `{json.dumps(features.get('attack', {}), ensure_ascii=False)}`",
            f"- Agentic Evidence: `{json.dumps(actor.get('agenticEvidence', {}), ensure_ascii=False)}`",
            "",
        ])
    lines.extend(["## 요청 흐름", ""])
    lines.extend(
        f"- {row.get('method')} {row.get('normalizedPath')} -> HTTP {row.get('status')}"
        for row in rows
    )
    lines.extend([
        "",
        "## 해석 및 공유 주의",
        "",
        "- 성공 판정은 프록시 응답 코드가 아니라 컨테이너 내부 챌린지 상태의 실행 전후 변화로 확인했다.",
        "- Session, Actor Candidate와 Auth Group은 서로 다른 연결 단위이므로 같은 값처럼 비교하지 않는다.",
        "- 추론 JSONL은 저장 전에 JWT, Authorization, token cookie와 주요 자격정보를 마스킹했다.",
        "- 프롬프트 준수 여부는 추론 기록을 별도로 검토해야 한다.",
        "",
    ])
    (args.output_dir / "metadata.md").write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    main()
