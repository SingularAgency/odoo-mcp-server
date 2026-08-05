"""Shared fixtures for the Odoo MCP server test suite."""

import base64
import hashlib
import os
import secrets
from typing import Dict, Tuple

import pytest

# Odoo credentials must exist before any handler builds a Config.  Nothing here
# reaches a real Odoo instance: the OAuth tests never invoke a tool body.
os.environ.setdefault("ODOO_URL", "https://example.odoo.com")
os.environ.setdefault("ODOO_DB", "testdb")
os.environ.setdefault("ODOO_USERNAME", "test@example.com")
os.environ.setdefault("ODOO_API_KEY", "fake-odoo-key")

PUBLIC_URL = "https://mcp.example.com"
STATIC_API_KEY = "static-api-key-for-claude"
CONSENT_PASSWORD = "consent-secret-123"
CALLBACK = "https://hyperagent.com/oauth/callback"

# The complete OAuth surface: four variables, of which only the last two are
# normally set in a deployment.
_OAUTH_ENV_KEYS = (
    "MCP_API_KEY",
    "MCP_OAUTH_PASSWORD",
    "MCP_PUBLIC_URL",
    "MCP_OAUTH_ALLOWED_REDIRECTS",
)

DEFAULT_OAUTH_ENV = {
    "MCP_API_KEY": STATIC_API_KEY,
    "MCP_OAUTH_PASSWORD": CONSENT_PASSWORD,
    "MCP_PUBLIC_URL": PUBLIC_URL,
    "MCP_OAUTH_ALLOWED_REDIRECTS": CALLBACK,
}


def signing_key_for(password: str) -> str:
    """The HMAC key the server derives from a consent password."""
    return hashlib.sha256(f"mcp-oauth-v1:{password}".encode()).hexdigest()

INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {"protocolVersion": "2025-06-18", "capabilities": {}},
}


def tools_list(request_id: int = 2) -> Dict:
    """A tools/list JSON-RPC request body."""
    return {"jsonrpc": "2.0", "id": request_id, "method": "tools/list"}


def pkce_pair() -> Tuple[str, str]:
    """Return a fresh ``(verifier, S256 challenge)`` pair."""
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


@pytest.fixture
def oauth_env(monkeypatch):
    """Apply a clean OAuth environment; returns a setter for per-test overrides.

    The module-level rate limiters and the memoized config are reset so tests
    cannot leak lockout state into each other.
    """
    from mcp_server_odoo import oauth

    def apply(**overrides):
        for key in _OAUTH_ENV_KEYS:
            monkeypatch.delenv(key, raising=False)
        for key, value in {**DEFAULT_OAUTH_ENV, **overrides}.items():
            if value is None:
                monkeypatch.delenv(key, raising=False)
            else:
                monkeypatch.setenv(key, value)
        oauth.reset_oauth_config()
        for limiter in (
            oauth._request_limiter,
            oauth._failure_limiter,
            oauth._global_failure_limiter,
        ):
            limiter._events.clear()
        oauth._used_codes.clear()
        return oauth.get_oauth_config()

    apply()
    yield apply
    oauth.reset_oauth_config()


@pytest.fixture
def client(oauth_env):
    """A TestClient bound to the public URL the OAuth config advertises."""
    from fastapi.testclient import TestClient

    from mcp_server_odoo import http_server

    with TestClient(http_server.app, base_url=PUBLIC_URL) as test_client:
        yield test_client


@pytest.fixture
def registered_client_id(client):
    """A dynamically registered client id pointing at the allowlisted callback."""
    response = client.post(
        "/register",
        json={"client_name": "Hyperagent", "redirect_uris": [CALLBACK]},
    )
    assert response.status_code == 201, response.text
    return response.json()["client_id"]


@pytest.fixture
def access_token(client, registered_client_id):
    """Complete the full OAuth flow and return ``(token, granted_scopes)``."""
    verifier, challenge = pkce_pair()
    form = {
        "client_id": registered_client_id,
        "redirect_uri": CALLBACK,
        "state": "xyz",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "resource": f"{PUBLIC_URL}/mcp",
        "password": CONSENT_PASSWORD,
        "scope_choice": ["odoo:read", "odoo:write"],
    }
    redirect = client.post("/authorize", data=form, follow_redirects=False)
    assert redirect.status_code == 302, redirect.text

    from urllib.parse import parse_qs, urlparse

    code = parse_qs(urlparse(redirect.headers["location"]).query)["code"][0]
    tokens = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": verifier,
            "client_id": registered_client_id,
            "redirect_uri": CALLBACK,
        },
    )
    assert tokens.status_code == 200, tokens.text
    payload = tokens.json()
    return payload["access_token"], payload
