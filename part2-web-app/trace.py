"""
trace.py
--------
A small helper for carrying a human-readable "what just happened" log through
the redirect chain between the Identity Provider and the Relying Party.

This has no equivalent in a real OIDC deployment -- it exists purely so this
demo can show you, in the browser, exactly which step of the flow you're on
and which cryptographic operation just happened. Real identity providers don't
narrate themselves to the browser like this.

The trace is a small JSON list of {"actor", "icon", "message"} entries,
base64url-encoded so it can travel safely as a URL query parameter across the
redirect from the Identity Provider back to the Relying Party.
"""

import base64
import json


def encode_trace(entries: list) -> str:
    raw = json.dumps(entries).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii")


def decode_trace(value: str | None) -> list:
    if not value:
        return []
    try:
        raw = base64.urlsafe_b64decode(value.encode("ascii"))
        return json.loads(raw)
    except Exception:
        # If the trace is missing or malformed, fail open to an empty trace --
        # this is cosmetic-only data, never used for a security decision.
        return []


def add(entries: list, actor: str, icon: str, message: str) -> list:
    """Return a NEW list with one more entry appended. actor is 'browser', 'idp', or 'app'."""
    return entries + [{"actor": actor, "icon": icon, "message": message}]
