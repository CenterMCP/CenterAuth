# CenterAuth

A runnable Go example of OAuth between an LLM's MCP host and an MCP server, backed by SQLite. It follows the CenterCDP / CenterUI project structure and uses the same `mcp-go` Streamable HTTP transport.

CenterAuth contains two logical roles in one process:

- **OAuth authorization server:** client registration, browser login and consent, authorization code exchange, refresh, and revocation.
- **MCP resource server:** validates the access token and loads the current user from SQLite on **every** `/mcp` request. Its `get_my_profile` tool returns that authenticated user's profile.

The LLM does not receive the user's password. The MCP host manages OAuth and attaches `Authorization: Bearer <access_token>` to requests. User identity never comes from tool arguments, an email supplied in chat, or a shared MCP session.

## Run locally

Requires Go 1.26 and a C compiler for `go-sqlite3` (Xcode Command Line Tools on macOS; GCC on Linux).

```sh
go mod download
go run ./cmd/server
```

Open **http://127.0.0.1:3002/demo**. Click **Connect with OAuth**, sign in with a mock account, and allow profile access. The demo acts as an MCP client: it dynamically registers itself, uses PKCE S256, validates state and issuer, exchanges the code, and calls `get_my_profile` over HTTP. Use **Get my profile**, **Refresh tokens**, and **Revoke and disconnect** to exercise subsequent authenticated requests.

| Mock user | Password | Name |
| --- | --- | --- |
| `alice@example.com` | `AliceDemo123!` | Alice Demo |
| `bob@example.com` | `BobDemo123!` | Bob Demo |

These synthetic accounts are inserted on first startup. Passwords are stored as bcrypt hashes, never plaintext. Restarting preserves existing users and tokens; seeding never overwrites an existing password. There is no public user signup endpoint. OAuth **client registration** at `/oauth/register` is separate from the mock user accounts.

The default database is `build/centerauth.db`. Open the demo in separate browser profiles or tabs and sign in as different users to compare profiles. Tokens are kept in the playground tab's session storage; LLM hosts manage their own token storage.

## Connect an LLM host

1. Expose this server using a stable HTTPS origin reachable by the host.
2. Start CenterAuth with that exact origin as `PUBLIC_URL`:

   ```sh
   PUBLIC_URL=https://auth.example.com HOST=0.0.0.0 go run ./cmd/server
   ```

3. Add `https://auth.example.com/mcp` as an OAuth-protected MCP connection in your host. Its client must support OAuth Authorization Code + PKCE and dynamic client registration (DCR).
4. Complete the browser sign-in when the host opens CenterAuth's authorization page.
5. Ask: **“Use CenterAuth to get my profile.”**

For ChatGPT, use its custom MCP connection setup with OAuth authentication. Host setup labels and features vary; see the official authentication documentation linked below. This project does not call an LLM API and needs no OpenAI API key. It exposes the endpoints used when a host registers and connects; it does not automatically add itself to an external account.

A host that requires preconfigured client credentials can register a client ahead of time and use the returned `client_id` / `client_secret`. CenterAuth supports `none`, `client_secret_basic`, and `client_secret_post` token endpoint authentication. It implements DCR, not Client ID Metadata Documents (CIMD). Callback URIs must match the registration exactly and use HTTPS, except for HTTP loopback callbacks.

The server uses the configured public origin for issuer and audience values, not untrusted forwarded headers. Local reverse proxies may preserve that public Host header. Unknown Host values and cross-origin browser POSTs are rejected. Use the public URL for the browser flow when configured; `/health` also accepts loopback Host values for local probes.

## OAuth / MCP request flow

```text
MCP host -> /mcp without token
         <- 401 + WWW-Authenticate with resource_metadata URL
MCP host -> /.well-known/oauth-protected-resource/mcp
         -> /.well-known/oauth-authorization-server
         -> POST /oauth/register (client metadata and redirect URI)
Browser  -> GET /oauth/authorize (client, redirect, resource, scope, PKCE, state)
User     -> POST /oauth/authorize (email/password + consent + browser flow cookie)
Browser  <- redirect to the host callback with code, state, and issuer
MCP host -> POST /oauth/token (code + PKCE verifier + client authentication + resource)
         <- access_token + refresh_token
MCP host -> /mcp with Authorization: Bearer ...
Server   -> SQLite token + audience + expiry + revocation + user + scope validation
LLM      -> tools/call: get_my_profile, arguments: {}
         <- authenticated user's profile
```

“Every request” means all HTTP methods and MCP operations on `/mcp`, including initialization, `tools/list`, and `tools/call`. Discovery, OAuth endpoints, health, and demo pages remain public so authorization can begin. No unauthenticated stdio transport is offered.

## Endpoints

| Endpoint | Purpose |
| --- | --- |
| `GET /.well-known/oauth-protected-resource/mcp` | Resource metadata for the MCP endpoint |
| `GET /.well-known/oauth-protected-resource` | Root discovery compatibility alias |
| `GET /.well-known/oauth-authorization-server` | OAuth issuer metadata and endpoint discovery |
| `POST /oauth/register` | Dynamic OAuth client registration |
| `GET /oauth/authorize` | Validate authorization request and show browser login/consent |
| `POST /oauth/authorize` | Validate browser flow cookie and credentials, then issue a code |
| `POST /oauth/token` | Exchange a code or rotate a refresh token |
| `POST /oauth/revoke` | Revoke the matching client's token family |
| `/mcp` | Protected Streamable HTTP MCP endpoint |
| `GET /demo` | Local end-to-end OAuth / MCP playground |
| `GET /demo/callback` | Playground OAuth callback |
| `GET /health` | SQLite connectivity and health |

Only `profile:read` is supported. Supply `resource=<PUBLIC_URL>/mcp` in both authorization and token requests. Token and revocation requests use `application/x-www-form-urlencoded`; client registration uses JSON. This is OAuth, not OpenID Connect: there is no `openid` scope or ID token.

Register a public client:

```sh
curl http://127.0.0.1:3002/oauth/register \
  -H 'Content-Type: application/json' \
  -d '{"client_name":"My MCP host","redirect_uris":["http://127.0.0.1:4000/callback"],"token_endpoint_auth_method":"none","grant_types":["authorization_code","refresh_token"],"response_types":["code"]}'
```

## `get_my_profile` response

Call the tool with empty arguments:

```json
{"name":"get_my_profile","arguments":{}}
```

Example `structuredContent` for Alice (the actual creation timestamp comes from SQLite):

```json
{
  "user": {
    "id": 1,
    "email": "alice@example.com",
    "name": "Alice Demo",
    "created_at": "2026-11-09T00:00:00Z"
  },
  "scope": "profile:read",
  "message": "Authenticated request confirmed by CenterAuth."
}
```

The tool also includes an equivalent text JSON fallback. It returns no passwords, password hashes, tokens, or client secrets. Alice's token always selects Alice; Bob's token always selects Bob. Changing the database user name affects the next request. Setting `users.disabled=1` rejects that user's next request immediately.

## Token lifecycle and validation

- Authorization Code + PKCE **S256** only; no password or implicit grant.
- Authorization codes expire after 2 minutes and are atomically single-use. Codes bind the user, client, exact redirect URI, PKCE challenge, scope, and resource.
- Login flow cookies are HttpOnly, SameSite=Lax, Secure on HTTPS, and expire after 10 minutes. Browser forms require the associated flow cookie. Consent can be declined.
- Five failed passwords lock an existing account for five minutes. Unknown accounts receive the same login failure message.
- Access tokens expire after 15 minutes. Refresh tokens expire after seven days and rotate on every refresh. Rotation invalidates the old access token as well.
- Reusing an old refresh token revokes the entire token family, including replacement tokens. The user must reconnect after replay or revocation.
- Access tokens, refresh tokens, authorization codes, and client secrets are stored only as SHA-256 hashes. These are random high-entropy secrets; user passwords use bcrypt instead.
- Each `/mcp` request checks the token against SQLite and validates audience, expiry, revocation, current user availability, and `profile:read` scope. Invalid tokens return HTTP 401 with OAuth discovery information; insufficient scope returns HTTP 403.
- MCP uses stateless transport to avoid attaching one user's identity to a shared server session.

This is a teaching/demo implementation with public mock credentials and open DCR. Use synthetic data and a controlled environment. Production deployments should use an established identity provider, hardened ingress and rate limits, account lifecycle controls, and operational audit/cleanup policies. No third-party deployment or live-host registration has been performed by creating this project.

## Configuration and build

| Flag | Environment | Default |
| --- | --- | --- |
| `--address` | `HOST`, `PORT` | `127.0.0.1:3002` |
| `--public-url` | `PUBLIC_URL` | `http://127.0.0.1:3002` |
| `--database` | `DATABASE_PATH` | `build/centerauth.db` |
| `--version` | — | Print semantic/build version |

When changing the local port, also set the matching public URL.

```sh
go test -race ./...
go vet ./...
go build -o build/centerauth ./cmd/server
# Or: task check, task build, task run-dev

docker build -t centerauth .
docker run --rm -p 3002:3002 -v centerauth-data:/data centerauth
# For a remote HTTPS origin, also pass -e PUBLIC_URL=https://auth.example.com
```

`docker-build.sh` is adapted from CenterCDP. It accepts repository, tag, and Docker Hub username as positional arguments, reads a Docker Hub token from stdin, and builds **and pushes** using Buildx. Default platform is `linux/amd64`; configure `PLATFORMS` as needed. Local `docker build` / `task docker-build` do not publish.

## Code map

| File | Responsibility |
| --- | --- |
| `cmd/server/main.go` | Configuration, SQLite startup, HTTP server, shutdown |
| `internal/auth/server.go` | MCP tool registration, per-request authentication middleware, metadata and routes |
| `internal/auth/oauth.go` | Client registration, login/consent, code exchange, refresh rotation, revocation |
| `internal/auth/store.go` | SQLite schema, bcrypt users, token validation and storage |
| `internal/auth/login.html` | Browser sign-in and consent |
| `internal/auth/demo.html`, `demo.js` | Browser client for the complete OAuth / MCP flow |
| `internal/auth/auth_test.go` | End-to-end authorization and isolation tests |

Tests cover two-user isolation, hashed storage, discovery, authenticated MCP initialization and tool calls, wrong/expired/replayed codes, PKCE and redirect/client binding, concurrent code redemption, CSRF and consent denial, account locks, token expiry/audience/scope, disabled users, confidential client secrets, refresh rotation/replay, revocation, and SQLite persistence.

References: [MCP authorization specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization), [OpenAI MCP authentication guide](https://developers.openai.com/plugins/build/auth), [RFC 7591 client registration](https://www.rfc-editor.org/rfc/rfc7591), and [RFC 9728 protected resource metadata](https://www.rfc-editor.org/rfc/rfc9728).
