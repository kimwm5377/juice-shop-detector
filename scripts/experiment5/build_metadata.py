#!/usr/bin/env python3
"""Validate experiment 5 artifacts and generate a compact metadata report."""

import argparse
import json
from pathlib import Path


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def has_run_id(record, run_id):
    features = record.get("features") or record.get("analysis", {}).get("features") or {}
    return run_id in features.get("experimentRunIds", [])


def request_rows(sessions, run_id):
    rows = []
    for session in sessions:
        analysis = session.get("analysis") or session
        requests = session.get("requests") or analysis.get("requests", [])
        for request in requests:
            if request.get("experimentRunId") == run_id:
                rows.append(request)
    return sorted(rows, key=lambda row: row.get("ts", 0))


def completed(rows, method, path, status):
    return any(
        row.get("method") == method
        and row.get("normalizedPath") == path
        and row.get("status") == status
        for row in rows
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--subject", required=True)
    parser.add_argument("--email", required=True)
    parser.add_argument("--agent-exit", type=int, required=True)
    args = parser.parse_args()

    sessions = load(args.output_dir / "detection-log-export.json")
    actors = load(args.output_dir / "actors.json")
    auth_groups = load(args.output_dir / "auth-groups.json")
    rows = request_rows(sessions, args.run_id)
    matching_sessions = [record for record in sessions if has_run_id(record, args.run_id)]
    matching_actors = [record for record in actors if has_run_id(record, args.run_id)]
    matching_auth = [record for record in auth_groups if has_run_id(record, args.run_id)]

    checks = {
        "signup201": completed(rows, "POST", "/api/Users/", 201),
        "login200": completed(rows, "POST", "/rest/user/login", 200),
        "review201": completed(rows, "PUT", "/rest/products/:id/reviews", 201),
    }
    valid = args.agent_exit == 0 and all(checks.values())
    validation = {
        "runId": args.run_id,
        "subject": args.subject,
        "agentExitCode": args.agent_exit,
        "requestCount": len(rows),
        "sessionCount": len(matching_sessions),
        "actorCount": len(matching_actors),
        "authGroupCount": len(matching_auth),
        "checks": checks,
        "protocolRequestStageSuccess": valid,
    }
    (args.output_dir / "validation.json").write_text(
        json.dumps(validation, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    lines = [
        "# 실험 5 실행 메타데이터",
        "",
        f"- 대상: {args.subject}",
        f"- Run ID: `{args.run_id}`",
        f"- 계정: `{args.email}`",
        f"- Agent 종료 코드: {args.agent_exit}",
        f"- Run 요청 수: {len(rows)}",
        f"- Session 수: {len(matching_sessions)}",
        f"- Actor Candidate 수: {len(matching_actors)}",
        f"- Auth Group 수: {len(matching_auth)}",
        "",
        "## 목표 요청 확인",
        "",
        f"- 회원가입 HTTP 201: {'확인' if checks['signup201'] else '미확인'}",
        f"- 로그인 HTTP 200: {'확인' if checks['login200'] else '미확인'}",
        f"- 리뷰 작성 HTTP 201: {'확인' if checks['review201'] else '미확인'}",
        f"- 요청 단계 판정: {'성공' if valid else '검토 필요'}",
        "",
        "## 요청 흐름",
        "",
    ]
    lines.extend(
        f"- {row.get('method')} {row.get('normalizedPath')} → HTTP {row.get('status')}"
        for row in rows
    )
    lines.extend(
        [
            "",
            "## 저장 파일",
            "",
            "- `prompt.txt`",
            "- `추론과정.jsonl`",
            "- `추론과정.txt`",
            "- `detection-log-export.json`",
            "- `actors.json` / `sessions.json` / `auth-groups.json` / `ip-entries.json`",
            "- `Traffic Detection Dashboard - Actor Candidates.html`",
            "- `Traffic Detection Dashboard - Sessions.html`",
            "- `Traffic Detection Dashboard - Actor Detail.html`",
            "- `dashboard-actor-detail.png`",
            "- `validation.json`",
            "",
        ]
    )
    (args.output_dir / "metadata.md").write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    main()
