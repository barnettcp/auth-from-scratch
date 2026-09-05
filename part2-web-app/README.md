# Part 2 — The Toy Web App

Two small Flask servers, playing the two roles in an SSO login:

- **`idp_server.py`** — "Aegis ID," the toy Identity Provider (stands in for
  Okta/Auth0). Runs on port **5001**.
- **`relying_party_server.py`** — "Lighthouse Notes," the toy Relying Party
  (stands in for your own app). Runs on port **5002**.

They talk to each other exactly the way a real app and a real Identity
Provider do: the browser bounces between them, while the actual token
exchange happens directly between the two servers, out of the browser's
view.

## Running it

You'll need two terminal windows/tabs, both from the `part2-web-app/`
directory, with dependencies installed (`pip install -r ../requirements.txt`
from here, or `pip install -r requirements.txt` from the repo root).

**Terminal 1:**
```bash
python3 idp_server.py
```

**Terminal 2:**
```bash
python3 relying_party_server.py
```

Then open **http://localhost:5002/** in your browser and click "Continue
with Aegis ID."

Demo accounts (shown on the login page too):

| Username | Password |
|---|---|
| `alice` | `correct-horse-battery-staple` |
| `bob` | `hunter2-but-better` |

## What to watch for

As you click through, a live trace panel narrates each step in real time —
including which cryptographic operation is happening and why. Specifically,
watch for:

1. Lighthouse Notes redirects you to Aegis ID with a random `state` value.
2. Aegis ID asks for your password directly — Lighthouse Notes never sees it.
3. After a successful login, Aegis ID redirects you back with a short-lived,
   single-use **authorization code** (not a token yet).
4. Lighthouse Notes' *server* — not your browser — exchanges that code for a
   signed identity token, by calling Aegis ID directly.
5. Lighthouse Notes fetches Aegis ID's *public* key and verifies the token's
   signature itself, without needing to ask Aegis ID "is this real?"
6. Only after that verification succeeds are you shown as logged in.

Try breaking it, too: stop the IdP server mid-flow, or start a login and let
more than 60 seconds pass before submitting the form (authorization codes
expire) — you should see a clear rejection, not a silent failure.

## Files

```
part2-web-app/
├── idp_server.py              The toy Identity Provider
├── relying_party_server.py    The toy Relying Party
├── trace.py                   Shared helper for the on-page process trace
├── templates/                 Jinja2 HTML templates for both servers
└── static/
    ├── css/style.css
    └── js/trace.js
```

See the top-level [`README.md`](../README.md) for what's intentionally
simplified in this demo compared to a real deployment.
