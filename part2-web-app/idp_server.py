"""
idp_server.py
=============
A minimal, educational Identity Provider ("Aegis ID" in this demo). Stands in
for the role Okta, Auth0, or any OIDC-compliant provider plays in a real
system: it owns user credentials, authenticates users, and issues signed
tokens -- but never hands its private key or a user's password to anyone.

Run this alongside relying_party_server.py (see part2-web-app/README.md).
This process listens on port 5001.

WHAT'S SIMPLIFIED HERE (read this before assuming any of it is production-safe):
  - Runs over plain HTTP on localhost, not HTTPS. Real deployments require TLS.
  - Two hardcoded demo users, stored in memory. A real IdP uses a persistent,
    access-controlled user store.
  - No PKCE, no nonce replay protection, no consent screen, no refresh tokens,
    no rate limiting on login attempts.
  - The signing key is generated fresh every time this script starts, and
    lives only in memory. A real IdP's signing key is a long-lived, carefully
    protected secret (often held in a hardware security module).
  - The "trace" data threaded through this app is a teaching aid, not part of
    any real protocol.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import time

from flask import Flask, request, redirect, render_template, jsonify

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

import base64
from trace import decode_trace, encode_trace, add as trace_add

app = Flask(__name__)

ISSUER_URL = "http://localhost:5001"

# ---------------------------------------------------------------------------
# Signing key -- generated once when the server starts. This is the single
# most important secret in the whole demo: everything downstream trusts
# tokens BECAUSE only this process can produce a valid signature with it.
# (See part1-foundations/04_digital_signatures.ipynb for the underlying idea.)
# ---------------------------------------------------------------------------
_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_public_key = _private_key.public_key()
_public_pem = _public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
).decode("ascii")


# ---------------------------------------------------------------------------
# A tiny in-memory user directory. Passwords are salted and hashed exactly as
# in part1-foundations/03_hashing.ipynb -- never stored in plaintext, even
# in a throwaway demo.
# ---------------------------------------------------------------------------
def _hash_password(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)


def _make_user(password: str, name: str, email: str) -> dict:
    salt = os.urandom(16)
    return {"salt": salt, "hash": _hash_password(password, salt), "name": name, "email": email}


USERS = {
    "alice": _make_user("correct-horse-battery-staple", "Alice Example", "alice@example.com"),
    "bob": _make_user("hunter2-but-better", "Bob Example", "bob@example.com"),
}


def check_credentials(username: str, password: str) -> bool:
    user = USERS.get(username)
    if not user:
        return False
    return _hash_password(password, user["salt"]) == user["hash"]


# ---------------------------------------------------------------------------
# Authorization codes: short-lived, single-use tokens that stand between a
# successful login and an actual signed identity token. Handing the browser
# only a CODE (not the final token) means the final token exchange can happen
# server-to-server, over a channel the browser never sees.
# ---------------------------------------------------------------------------
PENDING_CODES: dict[str, dict] = {}


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def issue_id_token(username: str) -> str:
    user = USERS[username]
    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {
        "iss": ISSUER_URL,
        "sub": username,
        "name": user["name"],
        "email": user["email"],
        "iat": now,
        "exp": now + 3600,
    }
    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()
    signature = _private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{header_b64}.{payload_b64}.{b64url_encode(signature)}"


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def home():
    return render_template("idp_home.html", issuer_url=ISSUER_URL, users=USERS.keys())


@app.route("/authorize")
def authorize():
    """
    The browser lands here after the Relying Party redirects it, carrying
    client_id / redirect_uri / state as query parameters -- this mirrors a
    real OIDC 'authorization request'.
    """
    client_id = request.args.get("client_id", "")
    redirect_uri = request.args.get("redirect_uri", "")
    state = request.args.get("state", "")
    trace = decode_trace(request.args.get("trace"))

    trace = trace_add(
        trace, "idp", "🪪",
        "Aegis ID received an authorization request and is presenting a login form.",
    )

    return render_template(
        "login.html",
        client_id=client_id,
        redirect_uri=redirect_uri,
        state=state,
        trace_b64=encode_trace(trace),
        trace=trace,
        error=None,
    )


@app.route("/authorize/login", methods=["POST"])
def authorize_login():
    """Handles the submitted login form and, on success, redirects back to the
    Relying Party with a one-time authorization code."""
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    redirect_uri = request.form.get("redirect_uri", "")
    state = request.form.get("state", "")
    client_id = request.form.get("client_id", "")
    trace = decode_trace(request.form.get("trace_b64"))

    if not check_credentials(username, password):
        trace = trace_add(trace, "idp", "⛔", f"Login failed for '{username}' -- incorrect credentials.")
        return render_template(
            "login.html",
            client_id=client_id,
            redirect_uri=redirect_uri,
            state=state,
            trace_b64=encode_trace(trace),
            trace=trace,
            error="Incorrect username or password.",
        )

    trace = trace_add(
        trace, "idp", "✅",
        f"Credentials for '{username}' verified against the salted, hashed user directory.",
    )

    code = secrets.token_urlsafe(24)
    PENDING_CODES[code] = {"username": username, "expires": time.time() + 60, "used": False}

    trace = trace_add(
        trace, "idp", "🎫",
        "Issued a short-lived, single-use authorization code (not the identity token itself).",
    )
    trace = trace_add(
        trace, "idp", "➡️",
        "Redirecting the browser back to the app with that code and the original state value.",
    )

    if not redirect_uri:
        return "Missing redirect_uri", 400

    separator = "&" if "?" in redirect_uri else "?"
    target = f"{redirect_uri}{separator}code={code}&state={state}&trace={encode_trace(trace)}"
    return redirect(target)


@app.route("/token", methods=["POST"])
def token():
    """
    The 'token endpoint'. Called SERVER-TO-SERVER by the Relying Party -- the
    browser is never involved in this request. This is what makes it safe to
    hand back a real identity token here: only the Relying Party's backend,
    which the browser can't inspect, ever sees this response directly.
    """
    data = request.get_json(silent=True) or request.form
    code = data.get("code", "")

    entry = PENDING_CODES.get(code)
    if entry is None or entry["used"]:
        return jsonify({"error": "invalid_grant", "detail": "Unknown or already-used authorization code."}), 400
    if entry["expires"] < time.time():
        return jsonify({"error": "invalid_grant", "detail": "Authorization code expired."}), 400

    entry["used"] = True
    id_token = issue_id_token(entry["username"])
    return jsonify({"id_token": id_token, "token_type": "Bearer"})


@app.route("/jwks")
def jwks():
    """
    A simplified stand-in for a real OIDC provider's JWKS (JSON Web Key Set)
    endpoint. Real providers publish keys in a structured JWK format so
    multiple key types and rotations can be described; here we simply publish
    the PEM-encoded public key directly, since the goal is to show the
    PRINCIPLE (public keys are meant to be published) rather than reproduce
    the full JWK specification.
    """
    return jsonify({"issuer": ISSUER_URL, "public_key_pem": _public_pem})


if __name__ == "__main__":
    print(f"Aegis ID (toy Identity Provider) running at {ISSUER_URL}")
    print("Demo users: alice / correct-horse-battery-staple, bob / hunter2-but-better")
    app.run(port=5001, debug=True)
