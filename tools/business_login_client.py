"""Explicit login bootstrap for disposable HTTP fixtures and local drills.

This helper performs the documented protocol once. It never retries credentials
or supplies an authentication bypass; protocol rejection tests use raw requests.
"""

from urllib.parse import urlsplit


def context_headers(client, *, origin=None, cookie=None):
    origin = origin or str(client.base_url).rstrip("/")
    headers = {"Origin": origin}
    if cookie is not None:
        headers["Cookie"] = cookie
    observed = client.get("/api/session", headers=headers)
    if observed.status_code == 200 and observed.json().get("user"):
        headers["X-CSRF-Token"] = observed.json()["csrf"]
    context = client.post("/api/login/context", json={}, headers=headers)
    if context.status_code != 200:
        return context, None
    result = {"Origin": origin, "X-Login-CSRF": context.json()["csrf"]}
    if cookie is not None:
        name = "__Host-westbridge_login_flow" if urlsplit(origin).scheme == "https" else "westbridge_login_flow"
        # A deliberately supplied old session cookie still needs the flow
        # cookie installed by this explicit bootstrap in the credential POST.
        installed = context.cookies.get(name)
        if installed is None:
            # Reusing a valid explicitly supplied F does not send Set-Cookie
            # and need not populate this synthetic client's cookie jar.
            result["Cookie"] = cookie
        else:
            parts = [part for part in cookie.split(";") if part.partition("=")[0].strip() != name]
            parts.append(f"{name}={installed}")
            result["Cookie"] = "; ".join(parts)
    return context, result


def login_post(client, path="/api/login", **kwargs):
    """Bootstrap then send exactly one password POST or passkey-options POST."""
    supplied = dict(kwargs.pop("headers", {}))
    cookie = next((value for key, value in supplied.items() if key.lower() == "cookie"), None)
    context, headers = context_headers(client, cookie=cookie)
    if headers is None:
        return context
    # Preserve deliberate origin/CSRF negatives in the requested POST.
    headers.pop("Origin")
    if cookie is not None:
        supplied = {key: value for key, value in supplied.items() if key.lower() != "cookie"}
    return client.post(path, headers={**headers, **supplied}, **kwargs)
