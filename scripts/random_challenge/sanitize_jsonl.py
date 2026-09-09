#!/usr/bin/env python3
"""Remove credentials from streamed Codex JSONL before it reaches disk."""

import json
import re
import sys


JWT = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
BEARER = re.compile(r"(?i)(Authorization:\s*Bearer\s+)[^\s'\"\\]+")
TOKEN_COOKIE = re.compile(r"(?i)(Cookie:\s*token=)[^;\s'\"\\]+")
MNEMONIC = re.compile(
    r'(?i)(wallet at /juicy-nft\s*:\s*\\?")([a-z]+(?:\s+[a-z]+){11})'
)
JSON_SECRET = re.compile(
    r'(?i)("(?:password|passwordRepeat|securityAnswer|answer|token|deluxeToken|totpSecret|tmpToken|access_token)"\s*:\s*")[^"]*'
)
ESCAPED_JSON_SECRET = re.compile(
    r'(?i)(\\+"(?:password|passwordRepeat|securityAnswer|answer|token|deluxeToken|totpSecret|tmpToken|access_token)\\+"\s*:\s*\\+")[^\\"]*'
)


def clean_string(value):
    value = JWT.sub("[REDACTED_JWT]", value)
    value = BEARER.sub(r"\1[REDACTED_SECRET]", value)
    value = TOKEN_COOKIE.sub(r"\1[REDACTED_SECRET]", value)
    value = MNEMONIC.sub(r"\1[REDACTED_MNEMONIC]", value)
    value = JSON_SECRET.sub(r"\1[REDACTED_SECRET]", value)
    return ESCAPED_JSON_SECRET.sub(r"\1[REDACTED_SECRET]", value)


def clean(value):
    if isinstance(value, str):
        return clean_string(value)
    if isinstance(value, list):
        return [clean(item) for item in value]
    if isinstance(value, dict):
        return {key: clean(item) for key, item in value.items()}
    return value


for line in sys.stdin:
    try:
        value = json.loads(line)
    except json.JSONDecodeError:
        print(clean_string(line), end="")
        continue
    print(json.dumps(clean(value), ensure_ascii=False))
