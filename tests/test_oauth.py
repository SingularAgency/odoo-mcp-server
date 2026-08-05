"""Tests for the OAuth 2.1 authorization shim.

Grouped by concern: discovery, registration, the redirect allowlist (the control
that actually protects the flow), the code exchange, scope enforcement, token
validation, and backwards compatibility with the static API key.
"""

from urllib.parse import parse_qs, urlparse

import jwt as pyjwt
import pytest

from mcp_server_odoo import oauth

from .conftest import (
    CALLBACK,
    CONSENT_PASSWORD,
    INITIALIZE,
    PUBLIC_URL,
    SIGNING_SECRET,
    STATIC_API_KEY,
    pkce_pair,
    tools_list,
)


def _authorize_form(client_id, **overrides):
    verifier, challenge = pkce_pair()
    form = {
        "client_id": client_id,
        "redirect_uri": CALLBACK,
        "state": "xyz",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "resource": f"{PUBLIC_URL}/mcp",
        "password": CONSENT_PASSWORD,
        "scope_choice": ["odoo:read", "odoo:write"],
    }
    form.update(overrides)
    return verifier, form


# ── Challenge and discovery ──────────────────────────────────────────────────


class TestDiscovery:
    def test_unauthenticated_request_returns_challenge(self, client):
        """The WWW-Authenticate header is what starts OAuth discovery."""
        response = client.post("/mcp", json=INITIALIZE)
        assert response.status_code == 401
        challenge = response.headers["WWW-Authenticate"]
        assert challenge.startswith("Bearer ")
        assert "/.well-known/oauth-protected-resource" in challenge

    @pytest.mark.parametrize(
        "path",
        [
            "/.well-known/oauth-protected-resource",
            "/.well-known/oauth-protected-resource/mcp",
            "/.well-known/oauth-authorization-server",
            "/.well-known/oauth-authorization-server/mcp",
            "/.well-known/openid-configuration",
        ],
    )
    def test_metadata_is_public(self, client, path):
        """Discovery must work before a token exists, or nothing can bootstrap."""
        assert client.get(path).status_code == 200

    @pytest.mark.parametrize("path", ["/.well-known/oauth-protected-resource/", "/health/"])
    def test_trailing_slash_does_not_trigger_auth(self, client, path):
        """Starlette redirects during routing, downstream of the auth middleware."""
        response = client.get(path, follow_redirects=False)
        assert response.status_code != 401

    def test_protected_resource_metadata(self, client):
        body = client.get("/.well-known/oauth-protected-resource").json()
        assert body["resource"] == f"{PUBLIC_URL}/mcp"
        assert body["authorization_servers"] == [PUBLIC_URL]
        assert body["bearer_methods_supported"] == ["header"]

    def test_authorization_server_metadata(self, client):
        body = client.get("/.well-known/oauth-authorization-server").json()
        assert body["issuer"] == PUBLIC_URL
        assert body["authorization_endpoint"] == f"{PUBLIC_URL}/authorize"
        assert body["token_endpoint"] == f"{PUBLIC_URL}/token"
        assert body["registration_endpoint"] == f"{PUBLIC_URL}/register"
        assert body["code_challenge_methods_supported"] == ["S256"]
        assert body["authorization_response_iss_parameter_supported"] is True

    def test_issuer_follows_forwarded_headers_without_public_url(self, client, oauth_env):
        """Behind a proxy the request URL is internal, so headers decide."""
        oauth_env(MCP_PUBLIC_URL=None)
        body = client.get(
            "/.well-known/oauth-authorization-server",
            headers={"X-Forwarded-Proto": "https", "X-Forwarded-Host": "public.example.com"},
        ).json()
        assert body["issuer"] == "https://public.example.com"

    def test_forwarded_headers_ignored_when_untrusted(self, client, oauth_env):
        oauth_env(MCP_PUBLIC_URL=None, MCP_TRUST_PROXY_HEADERS="false")
        body = client.get(
            "/.well-known/oauth-authorization-server",
            headers={"X-Forwarded-Host": "attacker.example.com"},
        ).json()
        assert "attacker" not in body["issuer"]


# ── Dynamic client registration ──────────────────────────────────────────────


class TestRegistration:
    def test_registration_issues_a_public_client(self, client):
        response = client.post(
            "/register", json={"client_name": "Hyperagent", "redirect_uris": [CALLBACK]}
        )
        assert response.status_code == 201
        body = response.json()
        assert body["client_id"].startswith("mcp_")
        assert body["token_endpoint_auth_method"] == "none"
        assert "client_secret" not in body

    def test_registration_is_deterministic(self, client):
        """Re-registering after a restart must not orphan the previous id."""
        payload = {"client_name": "Hyperagent", "redirect_uris": [CALLBACK]}
        first = client.post("/register", json=payload).json()["client_id"]
        second = client.post("/register", json=payload).json()["client_id"]
        assert first == second

    def test_registration_requires_redirect_uris(self, client):
        response = client.post("/register", json={"client_name": "x"})
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_redirect_uri"

    def test_registration_rejects_unlisted_redirect(self, client):
        response = client.post(
            "/register", json={"client_name": "evil", "redirect_uris": ["https://evil.com/cb"]}
        )
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_redirect_uri"


# ── The redirect allowlist ───────────────────────────────────────────────────


class TestRedirectAllowlist:
    def test_authorize_refuses_unlisted_redirect_without_redirecting(
        self, client, registered_client_id
    ):
        """The phishing path: an attacker's callback must never receive a code.

        The refusal is rendered, not redirected — sending even an error to an
        unvetted URI would make this endpoint an open redirector.
        """
        _, challenge = pkce_pair()
        response = client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": registered_client_id,
                "redirect_uri": "https://evil.com/cb",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
            follow_redirects=False,
        )
        assert response.status_code == 400
        assert "location" not in response.headers

    def test_authorize_post_refuses_unlisted_redirect(self, client, registered_client_id):
        """Even with the correct password, an unlisted callback gets nothing."""
        _, form = _authorize_form(registered_client_id, redirect_uri="https://evil.com/cb")
        response = client.post("/authorize", data=form, follow_redirects=False)
        assert response.status_code == 400
        assert "location" not in response.headers

    @pytest.mark.parametrize(
        "candidate,expected",
        [
            ("https://hyperagent.com/any/path", True),
            ("https://HYPERAGENT.com/cb", True),
            ("https://hyperagent.com:8443/cb", True),
            ("https://hyperagent.com.evil.com/cb", False),
            ("http://hyperagent.com/cb", False),          # scheme must match
            ("https://hyperagent.com/cb#frag", False),    # fragments are forbidden
            ("not-a-url", False),
        ],
    )
    def test_host_wildcard_bounds_the_host(self, oauth_env, candidate, expected):
        config = oauth_env(MCP_OAUTH_ALLOWED_REDIRECTS="https://hyperagent.com/*")
        assert oauth._redirect_allowed(candidate, config.allowed_redirects) is expected

    def test_localhost_is_opt_in(self, oauth_env):
        config = oauth_env(MCP_OAUTH_ALLOWED_REDIRECTS=None)
        assert not oauth._redirect_allowed("http://localhost:6274/cb", config.allowed_redirects)

        config = oauth_env(MCP_OAUTH_ALLOWED_REDIRECTS=None, MCP_OAUTH_ALLOW_LOCALHOST="true")
        assert oauth._redirect_allowed("http://localhost:6274/cb", config.allowed_redirects)
        assert oauth._redirect_allowed("http://127.0.0.1:9999/cb", config.allowed_redirects)
        assert not oauth._redirect_allowed(
            "https://localhost.evil.com/cb", config.allowed_redirects
        )


# ── Consent screen and code exchange ─────────────────────────────────────────


class TestAuthorizationCodeFlow:
    def test_consent_page_shows_the_callback_and_scopes(self, client, registered_client_id):
        _, challenge = pkce_pair()
        response = client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": registered_client_id,
                "redirect_uri": CALLBACK,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "scope": "odoo:read odoo:write",
            },
        )
        assert response.status_code == 200
        assert CALLBACK in response.text
        assert 'type=password' in response.text
        for scope in oauth.SUPPORTED_SCOPES:
            assert scope in response.text

    def test_wrong_password_re_renders_the_form(self, client, registered_client_id):
        _, form = _authorize_form(registered_client_id, password="wrong")
        response = client.post("/authorize", data=form, follow_redirects=False)
        assert response.status_code == 200
        assert "Incorrect access key" in response.text
        assert "location" not in response.headers

    def test_successful_authorization_redirects_with_code_state_and_iss(
        self, client, registered_client_id
    ):
        _, form = _authorize_form(registered_client_id)
        response = client.post("/authorize", data=form, follow_redirects=False)
        assert response.status_code == 302

        query = parse_qs(urlparse(response.headers["location"]).query)
        assert response.headers["location"].startswith(CALLBACK)
        assert query["code"]
        assert query["state"] == ["xyz"]
        assert query["iss"] == [PUBLIC_URL]  # RFC 9207

    def test_token_exchange_returns_bearer_and_refresh(self, access_token):
        _, payload = access_token
        assert payload["token_type"] == "Bearer"
        assert payload["refresh_token"]
        assert payload["scope"] == "odoo:read odoo:write"
        assert payload["expires_in"] > 0

    def test_code_cannot_be_replayed(self, client, registered_client_id):
        verifier, form = _authorize_form(registered_client_id)
        redirect = client.post("/authorize", data=form, follow_redirects=False)
        code = parse_qs(urlparse(redirect.headers["location"]).query)["code"][0]
        exchange = {
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": verifier,
            "client_id": registered_client_id,
            "redirect_uri": CALLBACK,
        }
        assert client.post("/token", data=exchange).status_code == 200
        replay = client.post("/token", data=exchange)
        assert replay.status_code == 400
        assert replay.json()["error"] == "invalid_grant"

    def test_wrong_pkce_verifier_is_rejected(self, client, registered_client_id):
        _, form = _authorize_form(registered_client_id)
        redirect = client.post("/authorize", data=form, follow_redirects=False)
        code = parse_qs(urlparse(redirect.headers["location"]).query)["code"][0]
        response = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "code_verifier": "a-completely-different-verifier-value",
                "client_id": registered_client_id,
                "redirect_uri": CALLBACK,
            },
        )
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_grant"

    def test_plain_pkce_is_rejected(self, client, registered_client_id):
        """S256 only — a downgrade to `plain` must not be accepted."""
        _, form = _authorize_form(registered_client_id, code_challenge_method="plain")
        response = client.post("/authorize", data=form, follow_redirects=False)
        assert response.status_code == 302
        query = parse_qs(urlparse(response.headers["location"]).query)
        assert query["error"] == ["invalid_request"]
        assert "code" not in query

    def test_resource_for_another_server_is_rejected(self, client, registered_client_id):
        _, form = _authorize_form(registered_client_id, resource="https://other-server.com/mcp")
        response = client.post("/authorize", data=form, follow_redirects=False)
        query = parse_qs(urlparse(response.headers["location"]).query)
        assert query["error"] == ["invalid_target"]

    def test_unsupported_grant_type(self, client):
        response = client.post("/token", data={"grant_type": "password"})
        assert response.status_code == 400
        assert response.json()["error"] == "unsupported_grant_type"


class TestRefreshFlow:
    def test_refresh_issues_a_new_access_token(self, client, access_token):
        _, payload = access_token
        response = client.post(
            "/token",
            data={"grant_type": "refresh_token", "refresh_token": payload["refresh_token"]},
        )
        assert response.status_code == 200
        assert response.json()["access_token"]

    def test_refresh_may_narrow_but_not_widen_scope(self, client, access_token):
        _, payload = access_token
        narrowed = client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": payload["refresh_token"],
                "scope": "odoo:read",
            },
        )
        assert narrowed.json()["scope"] == "odoo:read"

        widened = client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": payload["refresh_token"],
                "scope": "odoo:admin",
            },
        )
        assert widened.status_code == 400
        assert widened.json()["error"] == "invalid_scope"


# ── Scope enforcement ────────────────────────────────────────────────────────


class TestScopes:
    def test_every_tool_has_an_explicit_scope(self, client):
        """A tool missing from TOOL_SCOPES would silently default to admin."""
        from mcp_server_odoo.http_server import get_all_tools
        import asyncio

        names = {tool["name"] for tool in asyncio.run(get_all_tools())}
        assert names <= set(oauth.TOOL_SCOPES), names - set(oauth.TOOL_SCOPES)

    def test_tools_list_hides_ungranted_tools(self, client, access_token):
        token, _ = access_token
        response = client.post(
            "/mcp", json=tools_list(), headers={"Authorization": f"Bearer {token}"}
        )
        names = [tool["name"] for tool in response.json()["result"]["tools"]]
        assert "search_records" in names
        assert "create_record" in names
        # Granted odoo:read + odoo:write, so the admin-only tools stay hidden.
        assert "delete_record" not in names
        assert "execute_method" not in names

    def test_calling_an_ungranted_tool_is_forbidden(self, client, access_token):
        token, _ = access_token
        response = client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "delete_record", "arguments": {"model": "res.partner", "ids": [1]}},
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        error = response.json()["error"]
        assert error["code"] == -32003
        assert "odoo:admin" in error["message"]

    def test_admin_scope_implies_write_and_read(self):
        assert oauth.expand_scopes(["odoo:admin"]) == {
            "odoo:admin",
            "odoo:write",
            "odoo:read",
        }
        assert oauth.expand_scopes(["odoo:write"]) == {"odoo:write", "odoo:read"}

    def test_unknown_tool_fails_closed(self):
        assert oauth.scope_for_tool("some_future_tool") == oauth.SCOPE_ADMIN


# ── Token validation ─────────────────────────────────────────────────────────


class TestTokenValidation:
    def test_valid_token_authenticates_and_negotiates_version(self, client, access_token):
        token, _ = access_token
        response = client.post(
            "/mcp", json=INITIALIZE, headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        assert response.json()["result"]["protocolVersion"] == "2025-06-18"

    def test_unknown_protocol_version_falls_back_to_newest(self, client, access_token):
        token, _ = access_token
        body = dict(INITIALIZE, params={"protocolVersion": "1999-01-01", "capabilities": {}})
        response = client.post("/mcp", json=body, headers={"Authorization": f"Bearer {token}"})
        assert response.json()["result"]["protocolVersion"] == "2025-06-18"

    def _forge(self, key, **claims):
        payload = {
            "iss": PUBLIC_URL,
            "aud": f"{PUBLIC_URL}/mcp",
            "typ": "access",
            "scope": "odoo:admin",
            "client_id": "forged",
            "iat": 0,
            "exp": 9999999999,
        }
        payload.update(claims)
        return pyjwt.encode(payload, key, algorithm="HS256")

    def test_token_signed_with_another_key_is_rejected(self, client):
        forged = self._forge("a-different-signing-key-entirely-32b")
        response = client.post(
            "/mcp", json=INITIALIZE, headers={"Authorization": f"Bearer {forged}"}
        )
        assert response.status_code == 401

    def test_token_for_another_audience_is_rejected(self, client):
        """RFC 8707 audience binding: a token minted for another server fails."""
        import hashlib

        key = hashlib.sha256(f"mcp-oauth-v1:{SIGNING_SECRET}".encode()).hexdigest()
        forged = self._forge(key, aud="https://other-server.com/mcp")
        response = client.post(
            "/mcp", json=INITIALIZE, headers={"Authorization": f"Bearer {forged}"}
        )
        assert response.status_code == 401

    def test_expired_token_is_rejected(self, client):
        import hashlib

        key = hashlib.sha256(f"mcp-oauth-v1:{SIGNING_SECRET}".encode()).hexdigest()
        forged = self._forge(key, exp=1)
        response = client.post(
            "/mcp", json=INITIALIZE, headers={"Authorization": f"Bearer {forged}"}
        )
        assert response.status_code == 401

    def test_refresh_token_is_not_accepted_as_an_access_token(self, client, access_token):
        _, payload = access_token
        response = client.post(
            "/mcp",
            json=INITIALIZE,
            headers={"Authorization": f"Bearer {payload['refresh_token']}"},
        )
        assert response.status_code == 401

    def test_signing_key_is_always_full_length(self, oauth_env):
        """A short MCP_OAUTH_SECRET must not yield a weak HMAC key."""
        config = oauth_env(MCP_OAUTH_SECRET="tiny")
        assert len(config.signing_key) == 64


# ── Backwards compatibility ──────────────────────────────────────────────────


class TestStaticApiKey:
    @pytest.mark.parametrize(
        "make_request",
        [
            pytest.param(lambda c, k: c.post("/mcp", params={"key": k}, json=tools_list()),
                         id="query-param"),
            pytest.param(lambda c, k: c.post("/mcp", headers={"X-API-Key": k}, json=tools_list()),
                         id="x-api-key"),
            pytest.param(lambda c, k: c.post("/mcp", headers={"Authorization": f"Bearer {k}"},
                                             json=tools_list()),
                         id="bearer"),
        ],
    )
    def test_existing_credential_paths_still_work(self, client, make_request):
        """Claude Desktop and Cursor setups must not break."""
        response = make_request(client, STATIC_API_KEY)
        assert response.status_code == 200

    def test_api_key_grants_every_scope(self, client):
        response = client.post("/mcp", params={"key": STATIC_API_KEY}, json=tools_list())
        names = [tool["name"] for tool in response.json()["result"]["tools"]]
        assert "delete_record" in names
        assert "execute_method" in names

    def test_wrong_api_key_is_rejected(self, client):
        assert client.post("/mcp", params={"key": "wrong"}, json=INITIALIZE).status_code == 401

    def test_open_mode_when_nothing_is_configured(self, client, oauth_env):
        """Local development with no secrets set keeps the old open behaviour."""
        oauth_env(MCP_API_KEY=None, MCP_OAUTH_PASSWORD=None, MCP_OAUTH_SECRET=None)
        assert client.post("/mcp", json=INITIALIZE).status_code == 200

    def test_oauth_can_be_disabled_without_breaking_the_api_key(self, client, oauth_env):
        oauth_env(MCP_OAUTH_ENABLED="false")
        assert not oauth.get_oauth_config().configured
        assert client.post("/mcp", params={"key": STATIC_API_KEY}, json=tools_list()).status_code == 200
        assert client.post("/mcp", json=INITIALIZE).status_code == 401


# ── Transport and rate limiting ──────────────────────────────────────────────


class TestTransport:
    def test_health_and_root_stay_open(self, client):
        assert client.get("/health").status_code == 200
        assert client.get("/").status_code == 200

    def test_get_mcp_reports_no_server_stream(self, client, access_token):
        token, _ = access_token
        response = client.get("/mcp", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 405
        assert "POST" in response.headers["Allow"]

    def test_delete_mcp_tears_down_the_session(self, client, access_token):
        token, _ = access_token
        response = client.delete(
            "/mcp",
            headers={"Authorization": f"Bearer {token}", "Mcp-Session-Id": "abc"},
        )
        assert response.status_code == 204

    def test_cors_preflight_needs_no_credentials(self, client):
        response = client.options(
            "/mcp",
            headers={
                "Origin": "https://hyperagent.com",
                "Access-Control-Request-Method": "POST",
            },
        )
        assert response.status_code == 200

    def test_brute_force_lockout(self, client, registered_client_id):
        """Repeated wrong passwords lock the caller out before the limit is useless."""
        _, form = _authorize_form(registered_client_id, password="nope")
        locked = False
        for _ in range(8):
            response = client.post("/authorize", data=form, follow_redirects=False)
            if "Too many attempts" in response.text:
                locked = True
                break
        assert locked

    def test_lockout_does_not_count_successes(self, client, registered_client_id):
        """A busy, correct client must never lock itself out."""
        for _ in range(8):
            _, form = _authorize_form(registered_client_id)
            response = client.post("/authorize", data=form, follow_redirects=False)
            assert response.status_code == 302, response.text
