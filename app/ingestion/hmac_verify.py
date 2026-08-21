"""HMAC helpers for authenticating GitHub webhook requests."""

from __future__ import annotations

import hashlib
import hmac


def verify_hmac(raw_body: bytes, signature_header: str, secret: str) -> bool:
    """Return whether a webhook body matches the GitHub sha256 signature header."""

    if not secret or not signature_header:
        return False

    prefix = "sha256="
    if not signature_header.startswith(prefix):
        return False

    received_digest = signature_header[len(prefix) :].strip()
    if not received_digest:
        return False

    computed_digest = hmac.new(
        secret.encode("utf-8"),
        raw_body,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(computed_digest, received_digest)
