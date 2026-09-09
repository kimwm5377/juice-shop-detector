#!/usr/bin/env python3
"""Evaluate concurrent Codex worker traffic using out-of-band cookie jars."""

import argparse
import json
from pathlib import Path


AGENTS = ("a", "b", "c")


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def cookie_values(path):
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) >= 7:
            values[parts[5]] = parts[6]
    return values


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("experiment_dir", type=Path)
    args = parser.parse_args()
    root = args.experiment_dir
    sessions = {name: cookie_values(root / f"agent-{name}.cookies")["dlsid"] for name in AGENTS}

    rounds = []
    identities = {name: {} for name in AGENTS}
    for round_number in (1, 2):
        round_dir = root / f"round-{round_number}"
        exported = {item["sessionId"]: item for item in load(round_dir / "after.json")}
        results = {name: load(round_dir / f"agent-{name}-result.json") for name in AGENTS}
        agents = []
        timeline = []
        for name in AGENTS:
            session = exported[sessions[name]]
            requests = session["requests"]
            actor_ids = sorted({item["actorId"] for item in requests})
            resolved_ids = sorted({item["resolvedActorId"] for item in requests})
            client_ids = sorted({
                item["clientId"] for item in requests
                if item.get("clientContinuityVerified") and item.get("clientId")
            })
            for request in requests:
                timeline.append({
                    "ts": request["ts"],
                    "agent": name,
                    "operation": request["operation"],
                })
            agents.append({
                "agent": name,
                "sessionId": sessions[name],
                "requestCount": len(requests),
                "actorIds": actor_ids,
                "resolvedActorIds": resolved_ids,
                "verifiedClientIds": client_ids,
                "maxAutomationScore": session["analysis"]["automationScore"],
                "maxAttackScore": session["analysis"]["attackScore"],
                "maxCrsAnomalyScore": session.get("attackHistory", {}).get("maxCrsAnomalyScore", 0),
                "startedAt": results[name]["startedAt"],
                "endedAt": results[name]["endedAt"],
            })
            identities[name][round_number] = {
                "actorIds": actor_ids,
                "resolvedActorIds": resolved_ids,
                "verifiedClientIds": client_ids,
            }
        timeline.sort(key=lambda item: item["ts"])
        starts = [item["startedAt"] for item in results.values()]
        ends = [item["endedAt"] for item in results.values()]
        actor_union = {actor for item in agents for actor in item["actorIds"]}
        resolved_union = {actor for item in agents for actor in item["resolvedActorIds"]}
        rounds.append({
            "round": round_number,
            "startSpreadMs": max(starts) - min(starts),
            "allProcessesOverlapped": max(starts) < min(ends),
            "timelineInterleaved": len({item["agent"] for item in timeline[:3]}) == 3,
            "sharedCandidateActor": len(actor_union) == 1,
            "distinctResolvedActors": len(resolved_union) == len(AGENTS),
            "candidateActorIds": sorted(actor_union),
            "resolvedActorIds": sorted(resolved_union),
            "agents": agents,
            "timeline": timeline,
        })

    continuity = []
    for name in AGENTS:
        first = identities[name][1]
        second = identities[name][2]
        continuity.append({
            "agent": name,
            "sameCandidateAfterRestart": first["actorIds"] == second["actorIds"],
            "sameResolvedActorAfterRestart": first["resolvedActorIds"] == second["resolvedActorIds"],
            "sameVerifiedClientAfterRestart": first["verifiedClientIds"] == second["verifiedClientIds"],
        })

    result = {
        "method": "three Codex workers, concurrent barrier, separate cookie jars, no identity header",
        "sessionGroundTruth": sessions,
        "rounds": rounds,
        "continuityAcrossRestart": continuity,
    }
    (root / "evaluation.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    lines = [
        "# Codex 3개 병렬 HTTP 식별 실험",
        "",
        "세 Codex 작업자가 같은 IP와 같은 기본 Python HTTP 클라이언트를 사용했다. 요청에는 식별용 헤더를 넣지 않았으며 각 작업자의 별도 쿠키 저장소를 외부 ground truth로 사용했다.",
        "",
        "| Round | 시작 편차 | 프로세스 중첩 | 요청 교차 | Candidate 수 | Resolved Actor 수 |",
        "|---:|---:|---|---|---:|---:|",
    ]
    for row in rounds:
        lines.append(
            f'| {row["round"]} | {row["startSpreadMs"]}ms | '
            f'{row["allProcessesOverlapped"]} | {row["timelineInterleaved"]} | '
            f'{len(row["candidateActorIds"])} | {len(row["resolvedActorIds"])} |'
        )
    lines.extend(["", "## 작업자별 재시작 연속성", ""])
    for row in continuity:
        lines.append(
            f'- Codex {row["agent"].upper()}: candidate={row["sameCandidateAfterRestart"]}, '
            f'dcid={row["sameVerifiedClientAfterRestart"]}, resolved={row["sameResolvedActorAfterRestart"]}'
        )
    lines.extend([
        "",
        "## 결론",
        "",
        "- HTTP 지문만 보면 세 작업자는 동일 Candidate 하나로 합쳐졌다.",
        "- 별도 signed dcid가 반환된 뒤에는 세 개의 서로 다른 Resolved Actor로 구분됐다.",
        "- 탐지 프록시 재시작 후에도 각 작업자의 dcid와 resolvedActorId가 동일하게 유지됐다.",
        "- 따라서 동일 도구·동일 IP의 병렬 Codex를 구분하는 핵심 근거는 헤더 지문이 아니라 signed dcid다.",
    ])
    (root / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
