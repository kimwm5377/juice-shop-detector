#!/usr/bin/env python3
"""Render Codex/Claude JSONL events into a readable experiment transcript."""

import argparse
import json
from pathlib import Path


def emit_codex(event, output):
    event_type = event.get("type", "")
    item = event.get("item") or {}
    item_type = item.get("type", "")

    if event_type == "thread.started":
        output.append(f"[thread] {event.get('thread_id', '')}")
    elif event_type == "item.completed":
        if item_type in {"agent_message", "reasoning"}:
            text = item.get("text") or item.get("content") or ""
            if text:
                output.append(str(text))
        elif item_type == "command_execution":
            command = item.get("command", "")
            captured = item.get("aggregated_output", "")
            exit_code = item.get("exit_code")
            output.append(f"$ {command}")
            if captured:
                output.append(str(captured).rstrip())
            if exit_code is not None:
                output.append(f"[exit {exit_code}]")
    elif event_type in {"error", "turn.failed"}:
        output.append(f"[{event_type}] {event.get('message') or event.get('error')}")


def emit_claude(event, output):
    event_type = event.get("type", "")
    if event_type == "assistant":
        message = event.get("message") or {}
        for block in message.get("content", []):
            if block.get("type") == "text" and block.get("text"):
                output.append(block["text"])
            elif block.get("type") == "tool_use":
                output.append(f"[tool] {block.get('name')}: {block.get('input')}")
    elif event_type == "user":
        message = event.get("message") or {}
        for block in message.get("content", []):
            if block.get("type") == "tool_result":
                content = block.get("content", "")
                if content:
                    output.append(str(content).rstrip())
    elif event_type == "result":
        result = event.get("result")
        if result:
            output.append(str(result))
    elif event_type == "error":
        output.append(f"[error] {event}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    rendered = []
    for raw_line in args.input.read_text(encoding="utf-8", errors="replace").splitlines():
        if not raw_line.strip():
            continue
        try:
            event = json.loads(raw_line)
        except json.JSONDecodeError:
            rendered.append(raw_line)
            continue
        emit_codex(event, rendered)
        emit_claude(event, rendered)

    args.output.write_text("\n\n".join(part for part in rendered if part).strip() + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
