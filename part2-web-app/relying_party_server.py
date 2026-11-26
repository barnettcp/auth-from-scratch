"""
relying_party_server.py
========================
A minimal, educational Relying Party ("Lighthouse Notes" in this demo) -- the
role your own app (e.g. something running on your Raspberry Pi) plays when it
lets Okta, Auth0, or any OIDC provider handle login on its behalf.

Run this alongside idp_server.py (see part2-web-app/README.md).
This process listens on port 5002.

WHAT'S SIMPLIFIED HERE:
  - Plain HTTP on localhost, not HTTPS.
  - No PKCE, no token refresh, no persistent session after this demo ends.
  - The Identity Provider's public key is fetched fresh on every login, purely
    for clarity. A real client typically caches it and refreshes on a schedule
    or on key-rotation signals.
  - "client_id" is a fixed placeholder string -- no real client registration
    or client secret is used, since this demo's authorization code exchange
    doesn't require one (a real confidential client typically presents a
    client secret or a signed client assertion at the token endpoint).
"""

from __future__ import annotations

import json
import secrets
import time
import base64

import requests
from flask import Flask, request, redirect, render_template, session

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

from trace import decode_trace, encode_trace, add as trace_add

app = Flask(__name__)
# A real deployment loads this from a secret manager and keeps it stable
# across restarts. Here, a fresh random key each run is fine -- it only
# needs to survive for the lifetime of one login attempt.
app.secret_key = secrets.token_hex(32)

IDP_BASE_URL = "http://localhost:5001"
OUR_REDIRECT_URI = "http://localhost:5002/callback"
OUR_CLIENT_ID = "lighthouse-notes-demo"
TRUSTED_ISSUER = IDP_BASE_URL

# A toy policy table: same user can authenticate as themselves, but only some
# users are allowed to call certain tools on certain resources.
# This mirrors the real “identity + authorization” split in a production system.
POLICY_TABLE = {
    "alice": {
        "team-alpha": {"read_note": True, "write_note": False, "delete_note": False, "deploy_release": False},
        "team-beta": {"read_note": False, "write_note": False, "delete_note": False, "deploy_release": False},
    },
    "bob": {
        "team-alpha": {"read_note": True, "write_note": True, "delete_note": False, "deploy_release": False},
        "team-beta": {"read_note": True, "write_note": True, "delete_note": False, "deploy_release": False},
    },
    "charlie": {
        "team-alpha": {"read_note": False, "write_note": False, "delete_note": False, "deploy_release": False},
        "team-beta": {"read_note": False, "write_note": False, "delete_note": False, "deploy_release": False},
    },
    "admin": {
        "team-alpha": {"read_note": True, "write_note": True, "delete_note": True, "deploy_release": True},
        "team-beta": {"read_note": True, "write_note": True, "delete_note": True, "deploy_release": True},
    },
}

TOOL_ORDER = [
    ("read_note", "team-alpha"),
    ("write_note", "team-alpha"),
    ("delete_note", "team-alpha"),
    ("deploy_release", "team-alpha"),
    ("read_note", "team-beta"),
    ("write_note", "team-beta"),
]


def b64url_decode(s: str) -> bytes:
    padding_needed = 4 - (len(s) % 4)
    if padding_needed != 4:
        s += "=" * padding_needed
    return base64.urlsafe_b64decode(s)


def user_can_call_tool(username: str, tool: str, resource: str) -> bool:
    return bool(POLICY_TABLE.get(username, {}).get(resource, {}).get(tool, False))


def build_policy_checks(username: str) -> list[dict]:
    rows = []
    for tool, resource in TOOL_ORDER:
        allowed = user_can_call_tool(username, tool, resource)
        if allowed:
            reason = f"Policy allows this subject to call {tool} on {resource}."
        else:
            reason = f"Identity is valid, but policy denies {tool} on {resource}."
        rows.append({
            "tool": tool,
            "resource": resource,
            "allowed": allowed,
            "reason": reason,
        })
    return rows


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/login")
def login():
    """Starts the flow: remember a random 'state' value, then send the
    browser to the Identity Provider's authorization endpoint."""
    state = secrets.token_urlsafe(16)
    session["expected_state"] = state

    trace = trace_add(
        [], "app", "➡️",
        "Lighthouse Notes is redirecting your browser to Aegis ID, with a random "
        "'state' value it will check when you come back (this defends against "
        "cross-site request forgery).",
    )

    params = {
        "client_id": OUR_CLIENT_ID,
        "redirect_uri": OUR_REDIRECT_URI,
        "state": state,
        "trace": encode_trace(trace),
    }
    query = "&".join(f"{k}={requests.utils.quote(v)}" for k, v in params.items())
    return redirect(f"{IDP_BASE_URL}/authorize?{query}")


@app.route("/callback")
def callback():
    """The Identity Provider redirects the browser back here with an
    authorization code after a successful login."""
    code = request.args.get("code", "")
    returned_state = request.args.get("state", "")
    trace = decode_trace(request.args.get("trace"))

    expected_state = session.pop("expected_state", None)
    if not expected_state or expected_state != returned_state:
        trace = trace_add(trace, "app", "⛔", "State value did NOT match -- rejecting this login attempt.")
        return render_template("error.html", message="State mismatch. This login attempt was rejected for your protection.", trace=trace)

    trace = trace_add(
        trace, "app", "🔒",
        "State value matched what we sent -- this really is a response to our own request.",
    )

    # --- Server-to-server exchange: the browser is not involved in this call. ---
    trace = trace_add(
        trace, "app", "📡",
        "Contacting Aegis ID directly (server-to-server) to exchange the code for a signed token.",
    )
    try:
        token_response = requests.post(f"{IDP_BASE_URL}/token", json={"code": code}, timeout=5)
        token_response.raise_for_status()
        id_token = token_response.json()["id_token"]
    except Exception as exc:
        trace = trace_add(trace, "app", "⛔", f"Token exchange failed: {exc}")
        return render_template("error.html", message="Could not exchange the authorization code for a token.", trace=trace)

    trace = trace_add(trace, "app", "🎟️", "Received a signed identity token (a JWT) from Aegis ID.")

    # --- Fetch the IdP's public key and verify the token ourselves. ---
    trace = trace_add(trace, "app", "🔍", "Fetching Aegis ID's public key so we can verify the token independently.")
    try:
        jwks_response = requests.get(f"{IDP_BASE_URL}/jwks", timeout=5)
        jwks_response.raise_for_status()
        public_pem = jwks_response.json()["public_key_pem"]
        public_key = serialization.load_pem_public_key(public_pem.encode())
    except Exception as exc:
        trace = trace_add(trace, "app", "⛔", f"Could not fetch or parse Aegis ID's public key: {exc}")
        return render_template("error.html", message="Could not retrieve the identity provider's public key.", trace=trace)

    try:
        header_b64, payload_b64, sig_b64 = id_token.split(".")
        header = json.loads(b64url_decode(header_b64))
        payload = json.loads(b64url_decode(payload_b64))

        if header.get("alg") != "RS256":
            raise ValueError(f"Unexpected algorithm: {header.get('alg')!r}")

        signing_input = f"{header_b64}.{payload_b64}".encode()
        public_key.verify(b64url_decode(sig_b64), signing_input, padding.PKCS1v15(), hashes.SHA256())

        if payload.get("exp", 0) < time.time():
            raise ValueError("Token has expired")
        if payload.get("iss") != TRUSTED_ISSUER:
            raise ValueError(f"Untrusted issuer: {payload.get('iss')!r}")

    except Exception as exc:
        trace = trace_add(trace, "app", "⛔", f"Token verification FAILED: {exc}")
        return render_template("error.html", message="This token failed verification and was rejected.", trace=trace)

    trace = trace_add(
        trace, "app", "🔏",
        "Signature verified with Aegis ID's public key. This token genuinely came from Aegis ID and was not altered.",
    )
    trace = trace_add(trace, "app", "🟢", f"Session established for {payload.get('name')}. Login complete.")

    session["claims"] = payload
    session["authenticated"] = True
    session["trace"] = trace
    policy_checks = build_policy_checks(payload.get("sub"))
    trace = trace_add(
        trace, "app", "🛡️",
        f"Evaluating authorization policy for {payload.get('sub')} before any tool call is permitted.",
    )
    return render_template(
        "welcome.html",
        claims=payload,
        header=header,
        raw_token=id_token,
        trace=trace,
        policy_checks=policy_checks,
    )


@app.route("/tool/<tool>")
def invoke_tool(tool: str):
    if not session.get("authenticated"):
        return redirect("/")

    resource = request.args.get("resource", "team-alpha")
    username = session["claims"].get("sub")
    allowed = user_can_call_tool(username, tool, resource)
    trace = session.get("trace", [])

    if allowed:
        trace = trace_add(
            trace, "app", "✅",
            f"Authorization check passed: {username} may call {tool} on {resource}.",
        )
        message = f"Tool call allowed. {tool} executed on {resource}."
        status = "allowed"
    else:
        trace = trace_add(
            trace, "app", "⛔",
            f"Authorization check denied: {username} is not allowed to call {tool} on {resource}.",
        )
        message = f"Tool call denied. {tool} is not permitted on {resource}."
        status = "denied"

    session["trace"] = trace
    return render_template(
        "tool_result.html",
        tool=tool,
        resource=resource,
        allowed=allowed,
        status=status,
        message=message,
        trace=trace,
        username=username,
    )


if __name__ == "__main__":
    print(f"Lighthouse Notes (toy Relying Party) running at {OUR_REDIRECT_URI.rsplit('/', 1)[0]}")
    print(f"Expecting Aegis ID to be running at {IDP_BASE_URL}")
    app.run(port=5002, debug=True)
