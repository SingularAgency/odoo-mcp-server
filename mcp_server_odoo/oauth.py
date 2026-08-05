"""OAuth 2.1 authorization shim for the Odoo MCP HTTP server.

Why this exists
---------------
Some MCP clients (Hyperagent, and increasingly others) will only connect to a
remote MCP server through the flow described in the MCP Authorization spec.
They never send ``?key=`` or ``X-API-Key``, so the API-key auth that Claude
Desktop uses is invisible to them.

This module makes the server its *own* OAuth 2.1 authorization server, so no
external identity provider is needed.  Odoo credentials are untouched — they
stay in the server environment exactly as before.  What OAuth replaces is only
*how a client proves it may talk to this server*.

Security model
--------------
The gate is a single shared secret (``MCP_OAUTH_PASSWORD``, falling back to
``MCP_API_KEY``) typed once by a human into the consent screen.  That is the
same blast radius as the previous ``?key=`` scheme — the secret simply stops
travelling in URLs, where reverse-proxy access logs record it.

Dynamic client registration is deliberately open: an OAuth ``client_id`` is a
public identifier, not a credential, and registering one grants no access.  The
control that actually matters is the redirect-URI allowlist
(``MCP_OAUTH_ALLOWED_REDIRECTS``).  Without it, anyone could register a client
pointing at their own callback, phish an operator into approving it, and walk
away with the authorization code — PKCE does not help there, because the
attacker generated the challenge.  Since the allowlist bounds the host a code
can ever be delivered to, we do not additionally need to prove the caller
"owns" the ``client_id``.

Tokens are stateless HS256 JWTs signed with ``MCP_OAUTH_SECRET``, so they
survive container restarts without a database.  The trade-off is that there is
no per-token revocation: to invalidate a leaked token before it expires, rotate
``MCP_OAUTH_SECRET`` (which invalidates every token at once).
"""

import hashlib
import hmac
import os
import secrets
import time
from base64 import urlsafe_b64encode
from html import escape
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode, urlparse, urlunparse

import jwt
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from .logger import get_logger

logger = get_logger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Scopes
# ─────────────────────────────────────────────────────────────────────────────

SCOPE_READ = "odoo:read"
SCOPE_WRITE = "odoo:write"
SCOPE_ADMIN = "odoo:admin"

SUPPORTED_SCOPES = [SCOPE_READ, SCOPE_WRITE, SCOPE_ADMIN]

# Pre-ticked on the consent screen.  ``odoo:admin`` is deliberately left off:
# it gates delete_record and execute_method (arbitrary model methods), which is
# not something an unattended agent should get by simply clicking Approve.
DEFAULT_SCOPES = [SCOPE_READ, SCOPE_WRITE]

# Broader scopes imply narrower ones (spec: "Servers MUST account for scope
# hierarchies, where a broader scope implies narrower ones").
_SCOPE_IMPLIES: Dict[str, List[str]] = {
    SCOPE_ADMIN: [SCOPE_ADMIN, SCOPE_WRITE, SCOPE_READ],
    SCOPE_WRITE: [SCOPE_WRITE, SCOPE_READ],
    SCOPE_READ: [SCOPE_READ],
}

# Which scope each tool requires.  Anything unlisted falls back to odoo:admin,
# so a newly added tool is locked down until it is classified here on purpose.
TOOL_SCOPES: Dict[str, str] = {
    "search_records": SCOPE_READ,
    "search_count": SCOPE_READ,
    "get_record": SCOPE_READ,
    "list_models": SCOPE_READ,
    "get_model_fields": SCOPE_READ,
    "model_info": SCOPE_READ,
    "server_status": SCOPE_READ,
    "cache_stats": SCOPE_READ,
    "create_record": SCOPE_WRITE,
    "update_record": SCOPE_WRITE,
    "delete_record": SCOPE_ADMIN,
    "execute_method": SCOPE_ADMIN,
}

SCOPE_DESCRIPTIONS = {
    SCOPE_READ: "Read Odoo records, models and field definitions",
    SCOPE_WRITE: "Create and update Odoo records",
    SCOPE_ADMIN: "Delete records and execute arbitrary model methods",
}


def expand_scopes(granted: List[str]) -> set:
    """Expand granted scopes to include everything they imply."""
    effective = set()
    for scope in granted:
        effective.update(_SCOPE_IMPLIES.get(scope, [scope]))
    return effective


def scope_for_tool(tool_name: str) -> str:
    """Return the scope required to call ``tool_name`` (fails closed)."""
    return TOOL_SCOPES.get(tool_name, SCOPE_ADMIN)


# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

# Callbacks we ship as trusted defaults.  Hyperagent's callback is not public
# knowledge, so the first connection attempt will be rejected and logged — read
# the WARNING line and add the URL to MCP_OAUTH_ALLOWED_REDIRECTS.
_DEFAULT_ALLOWED_REDIRECTS = [
    "https://claude.ai/api/mcp/auth_callback",
    "https://claude.com/api/mcp/auth_callback",
]

_LOCALHOST_REDIRECTS = [
    "http://localhost/*",
    "http://127.0.0.1/*",
]

_ACCESS_TTL_DEFAULT = 30 * 24 * 3600      # 30 days
_REFRESH_TTL_DEFAULT = 365 * 24 * 3600    # 1 year
_CODE_TTL = 60                            # authorization codes are short-lived


def _env_flag(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        logger.warning(f"{name}={raw!r} is not an integer; using default {default}")
        return default


class OAuthConfig:
    """OAuth settings resolved from the environment."""

    def __init__(self) -> None:
        self.enabled = _env_flag("MCP_OAUTH_ENABLED", True)

        # The secret a human types into the consent screen.  Kept separate from
        # MCP_API_KEY so the long-lived programmatic key never has to be pasted
        # into a browser form (history, password managers, shared machines).
        self.password = (
            os.environ.get("MCP_OAUTH_PASSWORD", "").strip()
            or os.environ.get("MCP_API_KEY", "").strip()
        )

        # Token signing key.  Without an explicit value we fall back to the
        # password so tokens still survive restarts; a standalone secret is
        # better because rotating it does not force clients to re-enter the
        # password.
        #
        # Whatever we are given is stretched through SHA-256 so the HMAC key is
        # always a full 32 bytes: RFC 7518 §3.2 requires at least the hash
        # length for HS256, and an operator who sets a short MCP_OAUTH_SECRET
        # should not silently end up with weak signatures.
        seed = os.environ.get("MCP_OAUTH_SECRET", "").strip() or self.password
        self.signing_key = (
            hashlib.sha256(f"mcp-oauth-v1:{seed}".encode()).hexdigest() if seed else ""
        )

        self.public_url = self._resolve_public_url()
        self.allowed_redirects = self._resolve_allowed_redirects()
        self.access_ttl = _env_int("MCP_OAUTH_ACCESS_TTL", _ACCESS_TTL_DEFAULT)
        self.refresh_ttl = _env_int("MCP_OAUTH_REFRESH_TTL", _REFRESH_TTL_DEFAULT)
        self.trust_proxy_headers = _env_flag("MCP_TRUST_PROXY_HEADERS", True)

    @staticmethod
    def _resolve_public_url() -> str:
        """The externally reachable base URL, without trailing slash.

        OAuth requires the issuer and endpoint URLs to match exactly, and behind
        a reverse proxy the request URL is the internal one.  Setting
        MCP_PUBLIC_URL explicitly is strongly preferred; otherwise we fall back
        to forwarded headers per request.
        """
        return os.environ.get("MCP_PUBLIC_URL", "").strip().rstrip("/")

    @staticmethod
    def _resolve_allowed_redirects() -> List[str]:
        raw = os.environ.get("MCP_OAUTH_ALLOWED_REDIRECTS", "").strip()
        if raw:
            entries = [item.strip() for item in raw.split(",") if item.strip()]
        else:
            entries = list(_DEFAULT_ALLOWED_REDIRECTS)
        if _env_flag("MCP_OAUTH_ALLOW_LOCALHOST", False):
            entries.extend(_LOCALHOST_REDIRECTS)
        return entries

    @property
    def configured(self) -> bool:
        """OAuth can only run if there is a secret to check against."""
        return self.enabled and bool(self.password) and bool(self.signing_key)


_config: Optional[OAuthConfig] = None


def get_oauth_config() -> OAuthConfig:
    """Get (and memoize) the OAuth configuration."""
    global _config
    if _config is None:
        _config = OAuthConfig()
        if not _config.enabled:
            logger.info("OAuth is disabled (MCP_OAUTH_ENABLED=false)")
        elif not _config.configured:
            logger.warning(
                "OAuth is enabled but no secret is set — set MCP_OAUTH_PASSWORD "
                "(or MCP_API_KEY). The OAuth endpoints will refuse all requests."
            )
        else:
            if not _config.public_url:
                logger.warning(
                    "MCP_PUBLIC_URL is not set; falling back to forwarded headers "
                    "to build OAuth metadata. Set it to your public HTTPS URL "
                    "(e.g. https://odoo-mcp.example.com) for reliable discovery."
                )
            logger.info(
                f"OAuth enabled — {len(_config.allowed_redirects)} allowed redirect "
                f"pattern(s), access token TTL {_config.access_ttl}s"
            )
    return _config


def reset_oauth_config() -> None:
    """Drop the memoized config (used by tests)."""
    global _config
    _config = None


# ─────────────────────────────────────────────────────────────────────────────
# URL helpers
# ─────────────────────────────────────────────────────────────────────────────


def canonical_uri(uri: str) -> str:
    """Normalize a URI for comparison: lowercase scheme/host, no trailing slash.

    The MCP spec says clients SHOULD send lowercase scheme and host but servers
    SHOULD accept uppercase for interoperability, and that the trailing-slash
    free form is preferred.
    """
    try:
        parts = urlparse(uri)
    except ValueError:
        return uri
    path = parts.path.rstrip("/")
    return urlunparse(
        (parts.scheme.lower(), parts.netloc.lower(), path, "", parts.query, "")
    )


def base_url_for(request: Request) -> str:
    """Resolve this server's public base URL for the current request."""
    config = get_oauth_config()
    if config.public_url:
        return config.public_url

    headers = request.headers
    scheme = request.url.scheme
    host = request.url.netloc

    if config.trust_proxy_headers:
        forwarded_proto = headers.get("X-Forwarded-Proto", "").split(",")[0].strip()
        forwarded_host = headers.get("X-Forwarded-Host", "").split(",")[0].strip()
        if forwarded_proto:
            scheme = forwarded_proto
        if forwarded_host:
            host = forwarded_host

    return f"{scheme}://{host}".rstrip("/")


def acceptable_audiences(base: str) -> set:
    """Resource identifiers a token may legitimately be addressed to.

    A client may have been configured with either the bare origin or the /mcp
    path, and RFC 8707 tells it to send the most specific URI it knows.  Both
    identify this same server, so both are accepted.
    """
    base = base.rstrip("/")
    return {canonical_uri(base), canonical_uri(f"{base}/mcp")}


def _redirect_allowed(redirect_uri: str, patterns: List[str]) -> bool:
    """Check a redirect URI against the allowlist.

    Two forms are supported:
      * an exact URL             — ``https://host/path/callback``
      * a host wildcard          — ``https://host/*`` (any path on that host)

    Host matching is what actually bounds the attack: a code can only ever be
    delivered to a host the operator named.
    """
    candidate = urlparse(redirect_uri)
    if not candidate.scheme or not candidate.netloc:
        return False
    # Fragments are forbidden in redirect URIs by OAuth 2.1.
    if candidate.fragment:
        return False

    for pattern in patterns:
        if pattern.endswith("/*"):
            allowed = urlparse(pattern[:-2])
            if not allowed.scheme or not allowed.netloc:
                continue
            # Host wildcards ignore the port only when the pattern omits one,
            # so http://localhost/* covers any local dev port.
            host_matches = (
                candidate.netloc.lower() == allowed.netloc.lower()
                or (
                    ":" not in allowed.netloc
                    and candidate.hostname
                    and candidate.hostname.lower() == allowed.netloc.lower()
                )
            )
            if candidate.scheme.lower() == allowed.scheme.lower() and host_matches:
                return True
        elif canonical_uri(redirect_uri) == canonical_uri(pattern):
            return True

    return False


# ─────────────────────────────────────────────────────────────────────────────
# Rate limiting
# ─────────────────────────────────────────────────────────────────────────────


class _SlidingWindow:
    """Minimal in-memory sliding-window counter.

    In-process state is fine here: this bounds online brute force, and a
    restart that clears it also drops every in-flight authorization code.
    """

    def __init__(self, limit: int, window: int) -> None:
        self.limit = limit
        self.window = window
        self._events: Dict[str, List[float]] = {}

    def _prune(self, cutoff: float) -> None:
        """Drop expired entries so idle keys do not accumulate forever."""
        if len(self._events) <= 1024:
            return
        self._events = {
            k: [ts for ts in v if ts > cutoff]
            for k, v in self._events.items()
            if any(ts > cutoff for ts in v)
        }

    def record(self, key: str) -> None:
        """Count an event against ``key``."""
        now = time.time()
        cutoff = now - self.window
        events = [ts for ts in self._events.get(key, []) if ts > cutoff]
        events.append(now)
        self._events[key] = events
        self._prune(cutoff)

    def blocked(self, key: str) -> bool:
        """True if ``key`` has already reached the limit, without counting a hit."""
        cutoff = time.time() - self.window
        events = [ts for ts in self._events.get(key, []) if ts > cutoff]
        return len(events) >= self.limit

    def hit(self, key: str) -> bool:
        """Count an event and report whether it stayed within the limit."""
        blocked = self.blocked(key)
        self.record(key)
        return not blocked


# Coarse limit on all traffic to the interactive endpoints.
_request_limiter = _SlidingWindow(limit=60, window=300)
# Tight limit on wrong-password attempts, per IP and globally.
_failure_limiter = _SlidingWindow(limit=5, window=900)
_global_failure_limiter = _SlidingWindow(limit=50, window=900)


def client_ip(request: Request) -> str:
    """Best-effort client IP for rate limiting.

    Behind a trusted reverse proxy the *rightmost* X-Forwarded-For entry is the
    one the proxy itself appended, so it is the only one a caller cannot spoof.
    """
    config = get_oauth_config()
    if config.trust_proxy_headers:
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            hops = [hop.strip() for hop in forwarded.split(",") if hop.strip()]
            if hops:
                return hops[-1]
    return request.client.host if request.client else "unknown"


# ─────────────────────────────────────────────────────────────────────────────
# Tokens
# ─────────────────────────────────────────────────────────────────────────────

_ALGORITHM = "HS256"

# Authorization codes are single-use.  They live for 60 seconds, so an
# in-memory replay cache is sufficient — anything a restart forgets has expired.
_used_codes: Dict[str, float] = {}


def _remember_code(jti: str, expires_at: float) -> bool:
    """Mark a code as consumed; return False if it was already used."""
    now = time.time()
    for key, expiry in list(_used_codes.items()):
        if expiry < now:
            del _used_codes[key]
    if jti in _used_codes:
        return False
    _used_codes[jti] = expires_at
    return True


def _issue(
    token_type: str,
    *,
    issuer: str,
    audience: str,
    scopes: List[str],
    client_id: str,
    ttl: int,
    extra: Optional[Dict[str, Any]] = None,
) -> str:
    config = get_oauth_config()
    now = int(time.time())
    payload: Dict[str, Any] = {
        "iss": issuer,
        "aud": audience,
        "sub": f"mcp-client:{client_id}",
        "client_id": client_id,
        "scope": " ".join(scopes),
        "typ": token_type,
        "iat": now,
        "exp": now + ttl,
        "jti": secrets.token_urlsafe(16),
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, config.signing_key, algorithm=_ALGORITHM)


def _decode(token: str, *, audiences: set, token_type: str) -> Dict[str, Any]:
    """Decode and validate a token, raising ``jwt.InvalidTokenError`` on failure.

    ``algorithms`` is pinned to HS256 so a token claiming ``alg: none`` (or an
    asymmetric algorithm) can never be accepted.
    """
    config = get_oauth_config()
    if not config.signing_key:
        raise jwt.InvalidTokenError("OAuth is not configured")

    payload = jwt.decode(
        token,
        config.signing_key,
        algorithms=[_ALGORITHM],
        audience=list(audiences),
        options={"require": ["exp", "iat", "aud", "iss", "typ"]},
    )
    if payload.get("typ") != token_type:
        raise jwt.InvalidTokenError(
            f"expected a {token_type} token, got {payload.get('typ')!r}"
        )
    return payload


def validate_access_token(token: str, request: Request) -> Optional[Dict[str, Any]]:
    """Validate a Bearer access token. Returns its claims, or None if invalid."""
    config = get_oauth_config()
    if not config.configured:
        return None

    base = base_url_for(request)
    try:
        payload = _decode(
            token, audiences=acceptable_audiences(base), token_type="access"
        )
    except jwt.InvalidTokenError as exc:
        logger.debug(f"Access token rejected: {exc}")
        return None

    if payload.get("iss") != base:
        logger.debug("Access token rejected: issuer mismatch")
        return None

    return payload


def _verify_pkce(verifier: str, challenge: str) -> bool:
    """Verify an S256 PKCE code verifier against the stored challenge."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    computed = urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return hmac.compare_digest(computed, challenge)


# ─────────────────────────────────────────────────────────────────────────────
# Metadata + endpoints
# ─────────────────────────────────────────────────────────────────────────────

router = APIRouter()

# Paths that must stay reachable without a token, or the handshake can never
# get started.  http_server's auth middleware consults this set.
PUBLIC_PATHS = {
    "/.well-known/oauth-protected-resource",
    "/.well-known/oauth-protected-resource/mcp",
    "/.well-known/oauth-authorization-server",
    "/.well-known/oauth-authorization-server/mcp",
    "/.well-known/openid-configuration",
    "/authorize",
    "/token",
    "/register",
}

_NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}


def www_authenticate_header(base: str, *, error: Optional[str] = None,
                            scope: Optional[str] = None,
                            description: Optional[str] = None) -> str:
    """Build the WWW-Authenticate challenge that kicks off discovery."""
    parts = [f'Bearer resource_metadata="{base}/.well-known/oauth-protected-resource"']
    if error:
        parts.append(f'error="{error}"')
    if scope:
        parts.append(f'scope="{scope}"')
    if description:
        parts.append(f'error_description="{description}"')
    return ", ".join(parts)


@router.get("/.well-known/oauth-protected-resource")
@router.get("/.well-known/oauth-protected-resource/mcp")
async def protected_resource_metadata(request: Request) -> JSONResponse:
    """RFC 9728 — tells the client which authorization server to use."""
    base = base_url_for(request)
    return JSONResponse(
        {
            "resource": f"{base}/mcp",
            "authorization_servers": [base],
            "scopes_supported": SUPPORTED_SCOPES,
            "bearer_methods_supported": ["header"],
            "resource_name": "Odoo MCP Server",
        },
        headers=_NO_STORE,
    )


@router.get("/.well-known/oauth-authorization-server")
@router.get("/.well-known/oauth-authorization-server/mcp")
@router.get("/.well-known/openid-configuration")
async def authorization_server_metadata(request: Request) -> JSONResponse:
    """RFC 8414 / OIDC Discovery — where authorize, token and register live."""
    base = base_url_for(request)
    return JSONResponse(
        {
            "issuer": base,
            "authorization_endpoint": f"{base}/authorize",
            "token_endpoint": f"{base}/token",
            "registration_endpoint": f"{base}/register",
            "scopes_supported": SUPPORTED_SCOPES,
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_methods_supported": ["none"],
            "code_challenge_methods_supported": ["S256"],
            "authorization_response_iss_parameter_supported": True,
            "service_documentation": f"{base}/",
        },
        headers=_NO_STORE,
    )


@router.post("/register")
async def register_client(request: Request) -> JSONResponse:
    """RFC 7591 Dynamic Client Registration.

    Open by design — a client_id is a public identifier, and holding one grants
    no access to anything.  Redirect URIs are still validated here so a
    misconfigured client fails at registration with a clear message instead of
    halfway through a browser flow.
    """
    config = get_oauth_config()
    if not config.configured:
        return _oauth_error("invalid_request", "OAuth is not configured on this server", 503)

    if not _request_limiter.hit(f"register:{client_ip(request)}"):
        return _oauth_error("invalid_request", "Too many requests", 429)

    try:
        body = await request.json()
    except Exception:
        return _oauth_error("invalid_client_metadata", "Body must be JSON")

    redirect_uris = body.get("redirect_uris") or []
    if not isinstance(redirect_uris, list) or not redirect_uris:
        return _oauth_error("invalid_redirect_uri", "redirect_uris is required")

    for uri in redirect_uris:
        if not isinstance(uri, str) or not _redirect_allowed(uri, config.allowed_redirects):
            logger.warning(
                f"Rejected client registration for redirect_uri {uri!r} — add it to "
                f"MCP_OAUTH_ALLOWED_REDIRECTS if this client is expected"
            )
            return _oauth_error(
                "invalid_redirect_uri",
                f"redirect_uri {uri!r} is not allowlisted on this server",
            )

    client_name = str(body.get("client_name") or "Unnamed MCP client")[:120]

    # Deterministic client_id: the same client re-registering (after a restart
    # on either side) gets the same id back, with no server-side storage.
    fingerprint = hmac.new(
        config.signing_key.encode(),
        ("client:" + "|".join(sorted(redirect_uris))).encode(),
        hashlib.sha256,
    ).digest()
    client_id = "mcp_" + urlsafe_b64encode(fingerprint).rstrip(b"=").decode()[:32]

    logger.info(f"Registered OAuth client {client_id} ({client_name})")

    return JSONResponse(
        {
            "client_id": client_id,
            "client_id_issued_at": int(time.time()),
            "client_name": client_name,
            "redirect_uris": redirect_uris,
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
            "scope": " ".join(SUPPORTED_SCOPES),
        },
        status_code=201,
        headers=_NO_STORE,
    )


def _oauth_error(error: str, description: str, status: int = 400) -> JSONResponse:
    return JSONResponse(
        {"error": error, "error_description": description},
        status_code=status,
        headers=_NO_STORE,
    )


def _validate_authorize_params(
    request: Request, params: Dict[str, str]
) -> Tuple[Optional[str], Optional[str]]:
    """Return ``(error, description)`` for anything wrong with the request."""
    if params.get("response_type") != "code":
        return "unsupported_response_type", "Only response_type=code is supported"
    if not params.get("client_id"):
        return "invalid_request", "client_id is required"
    if params.get("code_challenge_method") != "S256":
        return "invalid_request", "code_challenge_method must be S256"

    challenge = params.get("code_challenge", "")
    if not 43 <= len(challenge) <= 128:
        return "invalid_request", "A valid S256 code_challenge is required"

    requested = params.get("scope", "").split()
    unknown = [s for s in requested if s not in SUPPORTED_SCOPES]
    if unknown:
        return "invalid_scope", f"Unsupported scope(s): {', '.join(unknown)}"

    resource = params.get("resource")
    if resource:
        base = base_url_for(request)
        if canonical_uri(resource) not in acceptable_audiences(base):
            return (
                "invalid_target",
                f"resource {resource!r} does not identify this server",
            )
    return None, None


@router.get("/authorize")
async def authorize_form(request: Request) -> Any:
    """Render the consent screen."""
    config = get_oauth_config()
    if not config.configured:
        return _error_page("OAuth is not configured on this server.", 503)

    if not _request_limiter.hit(f"authorize:{client_ip(request)}"):
        return _error_page("Too many requests. Try again in a few minutes.", 429)

    params = dict(request.query_params)
    redirect_uri = params.get("redirect_uri", "")

    # The redirect URI is checked before anything else and errors are rendered
    # rather than redirected: sending an error to an unvetted URI would make
    # this endpoint an open redirector.
    if not redirect_uri or not _redirect_allowed(redirect_uri, config.allowed_redirects):
        logger.warning(
            f"Rejected /authorize for redirect_uri {redirect_uri!r} — add it to "
            f"MCP_OAUTH_ALLOWED_REDIRECTS if this client is expected"
        )
        return _error_page(
            "This client's redirect URI is not allowlisted on this server, so the "
            "request was refused. If you are the operator, check the server logs "
            "for the exact URI and add it to MCP_OAUTH_ALLOWED_REDIRECTS.",
            400,
        )

    error, description = _validate_authorize_params(request, params)
    if error:
        return _redirect_with_error(request, redirect_uri, params.get("state"), error, description)

    return _consent_page(request, params)


@router.post("/authorize")
async def authorize_submit(request: Request) -> Any:
    """Check the operator's secret and hand back an authorization code."""
    config = get_oauth_config()
    if not config.configured:
        return _error_page("OAuth is not configured on this server.", 503)

    ip = client_ip(request)
    if not _request_limiter.hit(f"authorize:{ip}"):
        return _error_page("Too many requests. Try again in a few minutes.", 429)

    form = await request.form()
    password = str(form.get("password", ""))
    redirect_uri = str(form.get("redirect_uri", ""))
    state = str(form.get("state", ""))
    resource = str(form.get("resource", ""))

    if not redirect_uri or not _redirect_allowed(redirect_uri, config.allowed_redirects):
        return _error_page("This client's redirect URI is not allowlisted.", 400)

    # Scopes come from the consent checkboxes, so the operator can narrow what
    # the client asked for (notably by leaving odoo:admin unchecked).
    selected = [s for s in form.getlist("scope_choice") if s in SUPPORTED_SCOPES]

    params = {
        "response_type": "code",
        "client_id": str(form.get("client_id", "")),
        "redirect_uri": redirect_uri,
        "state": state,
        "code_challenge": str(form.get("code_challenge", "")),
        "code_challenge_method": str(form.get("code_challenge_method", "")),
        "resource": resource,
        "scope": " ".join(selected),
    }
    error, description = _validate_authorize_params(request, params)
    if error:
        return _redirect_with_error(request, redirect_uri, state, error, description)

    # Brute-force guard.  Checked before the comparison so a locked-out caller
    # gets no signal about whether the secret was right.
    if _failure_limiter.blocked(f"fail:{ip}") or _global_failure_limiter.blocked("fail:global"):
        logger.warning(f"Authorization rate limit tripped for {ip}")
        return _consent_page(
            request, params, message="Too many attempts. Try again in a few minutes."
        )

    if not hmac.compare_digest(password, config.password):
        _failure_limiter.record(f"fail:{ip}")
        _global_failure_limiter.record("fail:global")
        logger.warning(f"Failed /authorize attempt from {ip}")
        return _consent_page(request, params, message="Incorrect access key.")

    granted = selected or [SCOPE_READ]
    client_id = params["client_id"]

    base = base_url_for(request)
    audience = canonical_uri(resource) if resource else canonical_uri(f"{base}/mcp")
    code = _issue(
        "code",
        issuer=base,
        audience=audience,
        scopes=granted,
        client_id=client_id,
        ttl=_CODE_TTL,
        extra={
            "code_challenge": params["code_challenge"],
            "redirect_uri": redirect_uri,
        },
    )

    logger.info(
        f"Issued authorization code to {client_id} for scopes {' '.join(granted)}"
    )

    query = {"code": code, "iss": base}
    if state:
        query["state"] = state
    return RedirectResponse(
        f"{redirect_uri}{'&' if urlparse(redirect_uri).query else '?'}{urlencode(query)}",
        status_code=302,
        headers=_NO_STORE,
    )


def _redirect_with_error(
    request: Request,
    redirect_uri: str,
    state: Optional[str],
    error: str,
    description: Optional[str],
) -> RedirectResponse:
    """Send an OAuth error back to an already-validated redirect URI."""
    query = {"error": error, "iss": base_url_for(request)}
    if description:
        query["error_description"] = description
    if state:
        query["state"] = state
    separator = "&" if urlparse(redirect_uri).query else "?"
    return RedirectResponse(
        f"{redirect_uri}{separator}{urlencode(query)}", status_code=302, headers=_NO_STORE
    )


@router.post("/token")
async def token_endpoint(request: Request) -> JSONResponse:
    """Exchange an authorization code (or refresh token) for an access token."""
    config = get_oauth_config()
    if not config.configured:
        return _oauth_error("invalid_request", "OAuth is not configured", 503)

    if not _request_limiter.hit(f"token:{client_ip(request)}"):
        return _oauth_error("invalid_request", "Too many requests", 429)

    form = await request.form()
    grant_type = form.get("grant_type", "")
    base = base_url_for(request)
    audiences = acceptable_audiences(base)

    if grant_type == "authorization_code":
        code = form.get("code", "")
        verifier = form.get("code_verifier", "")
        client_id = form.get("client_id", "")
        redirect_uri = form.get("redirect_uri", "")

        if not code or not verifier:
            return _oauth_error("invalid_request", "code and code_verifier are required")

        try:
            claims = _decode(code, audiences=audiences, token_type="code")
        except jwt.InvalidTokenError as exc:
            logger.warning(f"Rejected authorization code: {exc}")
            return _oauth_error("invalid_grant", "The authorization code is invalid or expired")

        if claims.get("iss") != base:
            return _oauth_error("invalid_grant", "Issuer mismatch")
        if client_id and claims.get("client_id") != client_id:
            return _oauth_error("invalid_grant", "client_id does not match the code")
        if redirect_uri and claims.get("redirect_uri") != redirect_uri:
            return _oauth_error("invalid_grant", "redirect_uri does not match the code")
        if not _verify_pkce(verifier, claims.get("code_challenge", "")):
            logger.warning("Rejected authorization code: PKCE verification failed")
            return _oauth_error("invalid_grant", "PKCE verification failed")
        if not _remember_code(claims["jti"], claims["exp"]):
            logger.warning("Rejected authorization code: already used")
            return _oauth_error("invalid_grant", "This authorization code was already used")

        scopes = claims.get("scope", "").split()
        return _token_response(claims["aud"], base, scopes, claims["client_id"])

    if grant_type == "refresh_token":
        refresh_token = form.get("refresh_token", "")
        if not refresh_token:
            return _oauth_error("invalid_request", "refresh_token is required")
        try:
            claims = _decode(refresh_token, audiences=audiences, token_type="refresh")
        except jwt.InvalidTokenError as exc:
            logger.debug(f"Rejected refresh token: {exc}")
            return _oauth_error("invalid_grant", "The refresh token is invalid or expired")
        if claims.get("iss") != base:
            return _oauth_error("invalid_grant", "Issuer mismatch")

        requested = form.get("scope", "")
        scopes = claims.get("scope", "").split()
        if requested:
            # A refresh may narrow the scope set but never widen it.
            narrowed = [s for s in requested.split() if s in scopes]
            if not narrowed:
                return _oauth_error("invalid_scope", "Requested scopes exceed the grant")
            scopes = narrowed

        return _token_response(claims["aud"], base, scopes, claims["client_id"])

    return _oauth_error(
        "unsupported_grant_type", f"grant_type {grant_type!r} is not supported"
    )


def _token_response(
    audience: str, issuer: str, scopes: List[str], client_id: str
) -> JSONResponse:
    config = get_oauth_config()
    access_token = _issue(
        "access",
        issuer=issuer,
        audience=audience,
        scopes=scopes,
        client_id=client_id,
        ttl=config.access_ttl,
    )
    refresh_token = _issue(
        "refresh",
        issuer=issuer,
        audience=audience,
        scopes=scopes,
        client_id=client_id,
        ttl=config.refresh_ttl,
    )
    return JSONResponse(
        {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": config.access_ttl,
            "refresh_token": refresh_token,
            "scope": " ".join(scopes),
        },
        headers=_NO_STORE,
    )


# ─────────────────────────────────────────────────────────────────────────────
# HTML
# ─────────────────────────────────────────────────────────────────────────────

_PAGE_CSS = """
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body {
  margin: 0; min-height: 100vh; display: flex; align-items: center;
  justify-content: center; padding: 24px;
  font: 15px/1.55 ui-sans-serif, -apple-system, "Segoe UI", Roboto, sans-serif;
  background: #f5f5f7; color: #1d1d1f;
}
.card {
  width: 100%; max-width: 460px; background: #fff; border-radius: 14px;
  padding: 32px; box-shadow: 0 1px 3px rgba(0,0,0,.08), 0 8px 32px rgba(0,0,0,.06);
}
h1 { font-size: 20px; margin: 0 0 6px; letter-spacing: -.01em; }
.sub { color: #6e6e73; margin: 0 0 24px; font-size: 14px; }
.field { margin-bottom: 18px; }
label { display: block; font-weight: 600; font-size: 13px; margin-bottom: 6px; }
input[type=password] {
  width: 100%; padding: 10px 12px; font-size: 15px; border-radius: 8px;
  border: 1px solid #d2d2d7; background: #fff; color: inherit;
}
input[type=password]:focus { outline: 2px solid #0071e3; outline-offset: -1px; border-color: #0071e3; }
.callout {
  background: #f5f5f7; border: 1px solid #e5e5ea; border-radius: 8px;
  padding: 12px 14px; margin-bottom: 22px; font-size: 13px;
}
.callout dt { color: #6e6e73; font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
.callout dd { margin: 2px 0 10px; word-break: break-all; font-family: ui-monospace, monospace; }
.callout dd:last-child { margin-bottom: 0; }
.scopes { list-style: none; padding: 0; margin: 0 0 22px; }
.scopes li { display: flex; gap: 10px; align-items: flex-start; padding: 8px 0; border-top: 1px solid #f0f0f2; }
.scopes li:first-child { border-top: none; }
.scopes input { margin-top: 3px; flex-shrink: 0; }
.scopes code { font-size: 12px; color: #6e6e73; display: block; }
.warn { color: #bf4800; font-weight: 600; }
button {
  width: 100%; padding: 11px; font-size: 15px; font-weight: 600; cursor: pointer;
  border: none; border-radius: 8px; background: #0071e3; color: #fff;
}
button:hover { background: #0077ed; }
.error {
  background: #fff2f0; border: 1px solid #ffc7bf; color: #b3261e;
  padding: 10px 12px; border-radius: 8px; margin-bottom: 18px; font-size: 14px;
}
.foot { margin: 20px 0 0; font-size: 12px; color: #86868b; text-align: center; }
@media (prefers-color-scheme: dark) {
  body { background: #000; color: #f5f5f7; }
  .card { background: #1c1c1e; box-shadow: none; border: 1px solid #2c2c2e; }
  .sub, .callout dt, .scopes code, .foot { color: #98989d; }
  .callout { background: #2c2c2e; border-color: #38383a; }
  .scopes li { border-color: #2c2c2e; }
  input[type=password] { background: #2c2c2e; border-color: #48484a; }
  .error { background: #3b1512; border-color: #5e2018; color: #ff9a8f; }
  .warn { color: #ff9f0a; }
}
"""


def _page(title: str, body: str, status: int = 200) -> HTMLResponse:
    return HTMLResponse(
        f"<!doctype html><html lang=en><head><meta charset=utf-8>"
        f"<meta name=viewport content='width=device-width,initial-scale=1'>"
        f"<title>{escape(title)}</title><style>{_PAGE_CSS}</style></head>"
        f"<body><main class=card>{body}</main></body></html>",
        status_code=status,
        headers=_NO_STORE,
    )


def _error_page(message: str, status: int) -> HTMLResponse:
    return _page(
        "Authorization refused",
        f"<h1>Authorization refused</h1><p class=sub>{escape(message)}</p>",
        status,
    )


def _consent_page(
    request: Request, params: Dict[str, str], message: Optional[str] = None
) -> HTMLResponse:
    """The one interactive screen: shows what is being granted, asks for the key."""
    base = base_url_for(request)
    redirect_uri = params.get("redirect_uri", "")
    client_id = params.get("client_id", "")

    requested = [s for s in params.get("scope", "").split() if s in SUPPORTED_SCOPES]
    preselected = set(requested or DEFAULT_SCOPES)

    scope_items = []
    for scope in SUPPORTED_SCOPES:
        checked = " checked" if scope in preselected else ""
        label = escape(SCOPE_DESCRIPTIONS[scope])
        if scope == SCOPE_ADMIN:
            label = f'<span class=warn>{label}</span>'
        scope_items.append(
            f"<li><input type=checkbox name=scope_choice value='{escape(scope)}'"
            f" id='sc-{escape(scope)}'{checked}>"
            f"<label for='sc-{escape(scope)}' style='font-weight:500;margin:0'>{label}"
            f"<code>{escape(scope)}</code></label></li>"
        )

    hidden = "".join(
        f"<input type=hidden name='{escape(name)}' value='{escape(params.get(key, ''))}'>"
        for name, key in (
            ("client_id", "client_id"),
            ("redirect_uri", "redirect_uri"),
            ("state", "state"),
            ("code_challenge", "code_challenge"),
            ("code_challenge_method", "code_challenge_method"),
            ("resource", "resource"),
        )
    )

    error_html = f"<p class=error>{escape(message)}</p>" if message else ""

    body = f"""
    <h1>Connect to Odoo MCP</h1>
    <p class=sub>A client is asking for access to this Odoo MCP server.</p>
    {error_html}
    <dl class=callout>
      <dt>Client</dt><dd>{escape(client_id or 'unknown')}</dd>
      <dt>Will receive the code at</dt><dd>{escape(redirect_uri)}</dd>
      <dt>Server</dt><dd>{escape(base)}</dd>
    </dl>
    <form method=post action="{escape(base)}/authorize">
      {hidden}
      <p style="font-weight:600;font-size:13px;margin:0 0 4px">Permissions</p>
      <ul class=scopes>{''.join(scope_items)}</ul>
      <div class=field>
        <label for=pw>Access key</label>
        <input type=password id=pw name=password autocomplete=current-password
               autofocus required>
      </div>
      <button type=submit>Approve access</button>
    </form>
    <p class=foot>Check the callback URL above before approving. Only approve
    requests you started yourself.</p>
    """
    return _page("Connect to Odoo MCP", body)
