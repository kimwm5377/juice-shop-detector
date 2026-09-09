#!/usr/bin/env python3
"""Select one bounded random Juice Shop challenge and render the prompt."""

import argparse
import html
import json
import random
import secrets
from pathlib import Path


EXCLUDED_TAGS = ("Danger Zone", "OSINT", "Brute Force", "Requires ", "Web3")


def eligible(challenge):
    tags = challenge.get("tags") or ""
    description = challenge.get("description") or ""
    dependencies = challenge.get("ChallengeDependencies") or []
    return (
        not challenge.get("solved", False)
        and 1 <= int(challenge.get("difficulty", 99)) <= 3
        and not dependencies
        and not any(tag in tags for tag in EXCLUDED_TAGS)
        and "potentially harmful" not in description.lower()
    )


def plain_description(value):
    value = value.replace("<code>", "`").replace("</code>", "`")
    value = value.replace("<i>", "").replace("</i>", "")
    value = value.replace("<strong>", "").replace("</strong>", "")
    value = value.replace("<em>", "").replace("</em>", "")
    return html.unescape(value)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--challenges", required=True, type=Path)
    parser.add_argument("--template", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--seed", type=int)
    args = parser.parse_args()

    payload = json.loads(args.challenges.read_text(encoding="utf-8"))
    candidates = [item for item in payload.get("data", []) if eligible(item)]
    candidates.sort(key=lambda item: int(item["id"]))
    if not candidates:
        raise SystemExit("No eligible random challenges")

    seed = args.seed if args.seed is not None else secrets.randbits(63)
    selected = random.Random(seed).choice(candidates)
    compact_candidates = [
        {
            "id": item["id"],
            "key": item["key"],
            "name": item["name"],
            "category": item["category"],
            "difficulty": item["difficulty"],
            "tags": item.get("tags"),
        }
        for item in candidates
    ]
    selection = {
        "seed": seed,
        "candidateCount": len(candidates),
        "selectionPolicy": {
            "difficulty": "1-3",
            "unsolvedOnly": True,
            "noDependencies": True,
            "excludedTags": list(EXCLUDED_TAGS),
            "excludePotentiallyHarmful": True,
        },
        "challenge": selected,
    }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "challenge-candidates.json").write_text(
        json.dumps(compact_candidates, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (args.output_dir / "selected-challenge.json").write_text(
        json.dumps(selection, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    prompt = args.template.read_text(encoding="utf-8")
    replacements = {
        "{{RUN_ID}}": args.run_id,
        "{{CHALLENGE_NAME}}": selected["name"],
        "{{CHALLENGE_CATEGORY}}": selected["category"],
        "{{CHALLENGE_DIFFICULTY}}": str(selected["difficulty"]),
        "{{CHALLENGE_DESCRIPTION}}": plain_description(selected["description"]),
    }
    for source, target in replacements.items():
        prompt = prompt.replace(source, target)
    (args.output_dir / "prompt.txt").write_text(prompt, encoding="utf-8")

    print(json.dumps({"seed": seed, "challenge": selected}, ensure_ascii=False))


if __name__ == "__main__":
    main()
