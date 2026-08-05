# OAuth for OAuth-only MCP clients

Some MCP clients — Hyperagent among them — will only connect to a remote MCP
server through the OAuth flow in the
[MCP Authorization spec](https://modelcontextprotocol.io/specification/draft/basic/authorization).
They never send `?key=` or `X-API-Key`, so the API-key auth that Claude Desktop
uses is invisible to them.

This server therefore acts as **its own OAuth 2.1 authorization server**. There
is no external identity provider, and **Odoo credentials are not part of this**:
they stay in the server environment exactly as before. OAuth governs only *how a
client proves it may talk to this server*.

Both credential paths run side by side, so existing Claude Desktop and Cursor
setups keep working unchanged.

## What the client sees

```
1. POST /mcp with no token          →  401 + WWW-Authenticate: Bearer resource_metadata="…"
2. GET  /.well-known/oauth-protected-resource   →  which authorization server to use
3. GET  /.well-known/oauth-authorization-server →  where authorize/token/register live
4. POST /register                   →  a client_id (public client, PKCE, no secret)
5. GET  /authorize                  →  consent screen: shows the callback, asks for the key
6. POST /authorize                  →  302 to the callback with ?code=…&state=…&iss=…
7. POST /token                      →  { access_token, refresh_token, scope }
8. POST /mcp with Authorization: Bearer …  →  works
```

## Configuration

| Variable | Required | Purpose |
|---|---|---|
| `MCP_OAUTH_ENABLED` | no (`true`) | Master switch. `false` leaves only API-key auth. |
| `MCP_PUBLIC_URL` | **yes in production** | Public HTTPS base URL, no trailing slash. OAuth requires the issuer to match exactly, and behind a reverse proxy the request URL is the internal one. |
| `MCP_OAUTH_PASSWORD` | yes | The secret a human types once into the consent screen. Falls back to `MCP_API_KEY`. |
| `MCP_OAUTH_SECRET` | recommended | Signs the tokens. Falls back to a value derived from `MCP_OAUTH_PASSWORD`. |
| `MCP_OAUTH_ALLOWED_REDIRECTS` | **yes** | Comma-separated redirect-URI allowlist. See below — this is the control that protects the flow. |
| `MCP_OAUTH_ALLOW_LOCALHOST` | no (`false`) | Permit `http://localhost` / `127.0.0.1` callbacks on any port, for the MCP Inspector. Keep `false` in production. |
| `MCP_OAUTH_ACCESS_TTL` | no (30 days) | Access token lifetime in seconds. |
| `MCP_OAUTH_REFRESH_TTL` | no (1 year) | Refresh token lifetime in seconds. |
| `MCP_TRUST_PROXY_HEADERS` | no (`true`) | Honour `X-Forwarded-Proto/Host/For`. Correct behind Hostinger, Traefik or nginx. |

Generate the two secrets with:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

## The redirect allowlist is the real security control

Dynamic client registration is open by design: an OAuth `client_id` is a public
identifier, not a credential, and holding one grants no access. What stops abuse
is `MCP_OAUTH_ALLOWED_REDIRECTS`.

Without an allowlist, this attack works:

1. An attacker registers a client whose `redirect_uri` is `https://evil.com/cb`.
2. They send an operator a link to **your own** `/authorize` endpoint with that
   `redirect_uri`.
3. The operator sees a trusted domain, types the access key, and approves.
4. The authorization code is delivered to `evil.com`.

PKCE does **not** help here, because the attacker generated the challenge. The
allowlist does, because a code can only ever be delivered to a host you named.

Entries may be exact URLs or host wildcards:

```bash
MCP_OAUTH_ALLOWED_REDIRECTS=https://claude.ai/api/mcp/auth_callback,https://hyperagent.com/*
```

A `https://host/*` entry allows any path on that exact host, on that exact
scheme. `https://hyperagent.com.evil.com/cb` does not match.

## Finding a new client's callback URL

Client callback URLs are not always documented. Attempt the connection once and
read the rejected URI from the server logs:

```
WARNING  Rejected /authorize for redirect_uri 'https://…' — add it to
         MCP_OAUTH_ALLOWED_REDIRECTS if this client is expected
```

Add that URI to the allowlist and retry.

## Scopes

| Scope | Grants | Tools |
|---|---|---|
| `odoo:read` | Read-only access | `search_records`, `search_count`, `get_record`, `list_models`, `get_model_fields`, `model_info`, `server_status`, `cache_stats` |
| `odoo:write` | Implies read | `create_record`, `update_record` |
| `odoo:admin` | Implies write | `delete_record`, `execute_method` |

`odoo:admin` is deliberately **not** pre-ticked on the consent screen. It gates
record deletion and arbitrary model-method execution, which is not something an
unattended agent should acquire by clicking Approve. Tools outside the granted
scopes are hidden from `tools/list` entirely, so a read-only client never sees
`delete_record` at all.

A tool not listed in `TOOL_SCOPES` defaults to `odoo:admin`, so newly added
tools are locked down until classified on purpose.

The static API key path grants every scope, preserving pre-OAuth behaviour.

## Token revocation

Tokens are stateless JWTs, which is what lets them survive container restarts
without a database. The trade-off: **there is no per-token revocation.** To
invalidate a leaked token before it expires, rotate `MCP_OAUTH_SECRET` — this
invalidates every issued token at once and all clients must re-authorize.

If you need to revoke individual tokens, that is the point at which to add a
small persistent store; do not pay for it before you need it.

Lowering `MCP_OAUTH_ACCESS_TTL` shrinks the exposure window from a leak. It is
safe to lower when the client refreshes reliably (the metadata advertises the
`refresh_token` grant); a client that does not refresh will prompt for
re-authorization at the end of each window.

## Verifying a deployment

```bash
BASE=https://your-mcp-domain.com

# 1. An unauthenticated call must challenge, not just fail.
curl -si -X POST "$BASE/mcp" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' | grep -i www-authenticate

# 2. Discovery must be public and report your real public URL.
curl -s "$BASE/.well-known/oauth-protected-resource" | jq
curl -s "$BASE/.well-known/oauth-authorization-server" | jq '.issuer, .token_endpoint'

# 3. A non-allowlisted callback must be refused without a redirect.
curl -si "$BASE/authorize?response_type=code&client_id=x&redirect_uri=https://evil.com/cb\
&code_challenge=$(python3 -c 'print("a"*43)')&code_challenge_method=S256" | head -1
```

If `issuer` in step 2 does not exactly match the URL your client connects to,
set `MCP_PUBLIC_URL`.

For an interactive walkthrough of the whole flow, point the
[MCP Inspector](https://github.com/modelcontextprotocol/inspector) at the server
with `MCP_OAUTH_ALLOW_LOCALHOST=true`.

## Requirements

- **HTTPS is mandatory.** OAuth redirects and discovery do not work over plain
  HTTP, and clients reject non-HTTPS MCP endpoints. Make sure TLS terminates in
  front of this server before configuring a client.
- The `/health` and `GET /` endpoints stay unauthenticated for health checks.
- With neither `MCP_API_KEY` nor an OAuth password configured, the server stays
  fully open — intended for local development only.
