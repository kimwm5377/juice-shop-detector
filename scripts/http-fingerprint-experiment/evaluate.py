#!/usr/bin/env python3
"""Evaluate sequential, out-of-band-labeled fingerprint experiment snapshots."""

import argparse
import json
from collections import defaultdict
from pathlib import Path


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def request_ids(export):
    return {
        request.get("requestId")
        for session in export
        for request in session.get("requests", [])
        if request.get("requestId")
    }


def summarize_phase(phase_path):
    phase = load(phase_path)
    before = load(phase_path.parent / phase["before"])
    after = load(phase_path.parent / phase["after"])
    previous = request_ids(before)
    requests = [
        request
        for session in after
        for request in session.get("requests", [])
        if request.get("requestId") not in previous
    ]
    touched_sessions = [
        session for session in after
        if any(request.get("requestId") not in previous for request in session.get("requests", []))
    ]
    automation_scores = [
        float(session.get("analysis", {}).get("automationScore", 0))
        for session in touched_sessions
    ]
    attack_scores = [
        float(session.get("analysis", {}).get("attackScore", 0))
        for session in touched_sessions
    ]
    crs_scores = [
        float(session.get("attackHistory", {}).get("maxCrsAnomalyScore", 0))
        for session in touched_sessions
    ]
    return {
        "round": phase["round"],
        "subject": phase["subject"],
        "requestCount": len(requests),
        "maxSessionAutomationScore": max(automation_scores, default=0),
        "maxSessionAttackScore": max(attack_scores, default=0),
        "maxCrsAnomalyScore": max(crs_scores, default=0),
        "sessionIds": sorted({item.get("sessionId") for item in requests if item.get("sessionId")}),
        "legacyActorIds": sorted({item.get("legacyActorId") for item in requests if item.get("legacyActorId")}),
        "v2ActorIds": sorted({item.get("actorId") for item in requests if item.get("actorId")}),
        "resolvedActorIds": sorted({item.get("resolvedActorId") for item in requests if item.get("resolvedActorId")}),
        "verifiedClientIds": sorted({
            item.get("clientId") for item in requests
            if item.get("clientId") and item.get("clientContinuityVerified")
        }),
        "clientFingerprintsV2": sorted({
            item.get("httpFingerprint", {}).get("clientFingerprint")
            for item in requests if item.get("httpFingerprint", {}).get("clientFingerprint")
        }),
        "requestFingerprintsV2": sorted({
            item.get("httpFingerprint", {}).get("requestFingerprint")
            for item in requests if item.get("httpFingerprint", {}).get("requestFingerprint")
        }),
        "experimentHeadersObserved": any(
            item.get("experimentRunId") is not None for item in requests
        ),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("output_dir", type=Path)
    args = parser.parse_args()
    phases = [summarize_phase(path) for path in sorted(args.output_dir.glob("round-*/phase-*.json"))]

    by_subject = defaultdict(list)
    for phase in phases:
        by_subject[phase["subject"]].append(phase)

    continuity = []
    for subject, rows in sorted(by_subject.items()):
        if len(rows) < 2:
            continue
        first, second = sorted(rows, key=lambda row: row["round"])[:2]
        continuity.append({
            "subject": subject,
            "sameLegacyActorSetAcrossRestart": bool(first["legacyActorIds"]) and set(first["legacyActorIds"]) == set(second["legacyActorIds"]),
            "sameV2ActorSetAcrossRestart": bool(first["v2ActorIds"]) and set(first["v2ActorIds"]) == set(second["v2ActorIds"]),
            "sameVerifiedClientAcrossRestart": bool(set(first["verifiedClientIds"]) & set(second["verifiedClientIds"])),
            "sameResolvedActorIdAcrossRestart": bool(set(first["resolvedActorIds"]) & set(second["resolvedActorIds"])),
        })

    collisions = []
    for index, left in enumerate(phases):
        for right in phases[index + 1:]:
            if left["round"] != right["round"] or left["subject"] == right["subject"]:
                continue
            shared = sorted(set(left["clientFingerprintsV2"]) & set(right["clientFingerprintsV2"]))
            if shared:
                collisions.append({
                    "round": left["round"],
                    "subjects": [left["subject"], right["subject"]],
                    "sharedClientFingerprintsV2": shared,
                    "sameVerifiedClient": bool(
                        set(left["verifiedClientIds"]) & set(right["verifiedClientIds"])
                    ),
                })

    result = {
        "method": "sequential before/after snapshots; no label header sent to target",
        "phases": phases,
        "continuityAcrossRestart": continuity,
        "v2FingerprintCollisions": collisions,
    }
    output = args.output_dir / "evaluation.json"
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    lines = [
        "# HTTP 핑거프린트 무라벨 실험 결과",
        "",
        "요청에는 X-Attacker-ID 또는 X-Experiment-Run-Id를 넣지 않았다. 정답은 순차 실행 전후 스냅샷으로 외부에서 계산했다.",
        "",
        "| Round | Subject | Requests | Sessions | Legacy Actors | V2 Actors | Verified Clients | Attack Score | CRS |",
        "|---:|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in phases:
        lines.append(
            f'| {row["round"]} | {row["subject"]} | {row["requestCount"]} | '
            f'{len(row["sessionIds"])} | {len(row["legacyActorIds"])} | '
            f'{len(row["v2ActorIds"])} | {len(row["verifiedClientIds"])} | '
            f'{row["maxSessionAttackScore"]:.3f} | {row["maxCrsAnomalyScore"]:g} |'
        )
    lines.extend(["", "## 재시작 연속성", ""])
    for row in continuity:
        lines.append(
            f'- {row["subject"]}: legacy-set={row["sameLegacyActorSetAcrossRestart"]}, '
            f'v2-set={row["sameV2ActorSetAcrossRestart"]}, dcid={row["sameVerifiedClientAcrossRestart"]}, '
            f'resolved-id={row["sameResolvedActorIdAcrossRestart"]}'
        )
    lines.extend(["", "## 서로 다른 주체의 V2 지문 충돌", ""])
    if collisions:
        for row in collisions:
            lines.append(
                f'- round {row["round"]}: {" / ".join(row["subjects"])} '
                f'(same verified client={row["sameVerifiedClient"]})'
            )
    else:
        lines.append("- 없음")
    browser_rows = [row for row in phases if row["subject"] == "browser-a"]
    lines.extend(["", "## 판정", ""])
    if browser_rows and all(
        len(row["legacyActorIds"]) > len(row["v2ActorIds"]) == 1 for row in browser_rows
    ):
        lines.append("- 브라우저의 자원별 Accept 변화로 발생한 기존 Candidate 분할을 V2가 줄였다.")
    if collisions:
        lines.append("- 동일 HTTP 구현을 쓰는 서로 다른 주체는 V2 지문만으로 구분되지 않았다.")
    if any(row["sameVerifiedClientAcrossRestart"] for row in continuity):
        lines.append("- 쿠키를 보존한 클라이언트는 고정 HMAC key 아래에서 재시작 후에도 동일 dcid가 검증됐다.")
    if any(
        row["sameVerifiedClientAcrossRestart"] and not row["sameResolvedActorIdAcrossRestart"]
        for row in continuity
    ):
        lines.append("- dcid가 유지됐지만 Resolved Actor ID가 바뀐 클라이언트가 있었다.")
    elif any(row["sameVerifiedClientAcrossRestart"] for row in continuity):
        lines.append("- 검증된 dcid가 있는 클라이언트는 재시작 후에도 동일 resolvedActorId를 재생성했다.")
        lines.append("- 저장소는 인메모리이므로 동일 ID의 과거 요청 이력 자체는 별도 영속 저장이 필요하다.")
    (args.output_dir / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
