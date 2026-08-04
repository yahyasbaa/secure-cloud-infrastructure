"""Bearer-token authentication with constant-time comparison."""

from __future__ import annotations

import hmac
from typing import Iterable


def extract_bearer(header_value: str | None) -> str | None:
    if not header_value:
        return None
    scheme, _, token = header_value.partition(" ")
    if scheme.lower() != "bearer" or not token or len(token) > 512:
        return None
    return token.strip()


def token_is_valid(presented: str | None, valid_tokens: Iterable[str]) -> bool:
    if not presented:
        return False
    presented_b = presented.encode()
    ok = False
    # Compare against every token without short-circuiting to keep timing uniform.
    for candidate in valid_tokens:
        ok |= hmac.compare_digest(presented_b, candidate.encode())
    return ok
