# Connecting the Murray Context Ledger to Claude and ChatGPT

This walks you from a fresh Auth0 tenant to a working custom connector in both
Claude and ChatGPT. The ledger speaks MCP over Streamable HTTP at `/mcp` and
uses Auth0 for sign-in; both clients discover that automatically — you only
paste one URL.

## Part 1 — One-time Auth0 tenant setup

The ledger never issues tokens itself; Auth0 is the authorization server.
Three tenant settings make the connector OAuth flows work end to end.

### 1. Create the ledger API (the token audience)

Auth0 Dashboard → **Applications → APIs → Create API**

- **Name:** Murray Context Ledger
- **Identifier:** the value you run the server with as `AUTH0_API_AUDIENCE`,
  e.g. `https://ledger.yourdomain.com/mcp`. The identifier is a label, not a
  URL Auth0 calls — but using the real MCP URL keeps things legible.
- **Signing algorithm:** RS256 (required).

> [screenshot placeholder: API creation form]

### 2. Enable Dynamic Client Registration

Claude and ChatGPT register themselves as OAuth clients (RFC 7591); ChatGPT
requires this and rejects static bearer tokens.

Auth0 Dashboard → **Settings → Advanced** → enable
**OIDC Dynamic Application Registration**.

> [screenshot placeholder: advanced tenant settings toggle]

Dynamically registered apps are *third-party* apps in Auth0, which means:

- **Connections must be domain-level.** Promote the database/social connection
  users sign in with: Authentication → Database → *your connection* →
  Settings, or via the Management API
  (`PATCH /api/v2/connections/{id}` with `{"is_domain_connection": true}`).
- **Users will see a consent screen** during connect. That's expected; the
  "Allow Skipping User Consent" API setting applies only to first-party apps.

> [screenshot placeholder: connection promoted to domain level]

### 3. Set the tenant Default Audience

Auth0 Dashboard → **Settings → General → API Authorization Settings →
Default Audience** → the API identifier from step 1.

Why: connector clients follow the MCP spec and send an OAuth `resource`
parameter, but Auth0 does not read `resource` (RFC 8707) and the clients don't
know to send Auth0's proprietary `audience` parameter. The default audience
makes every token request without an explicit audience resolve to the ledger
API, so tokens arrive as RS256 JWTs the server can verify.

> [screenshot placeholder: default audience field]

**Callbacks:** none to configure. DCR clients register their own redirect URIs
when they self-register.

## Part 2 — Run the server and expose it

```sh
make dev                # uvicorn on :8080 (uses your .env)
make tunnel             # cloudflared/ngrok quick HTTPS tunnel
```

`make tunnel` prints the public URL plus the exact strings for both connector
forms, and the one important extra step: restart the server with
`RESOURCE_SERVER_URL=https://<public-host>/mcp` so the OAuth resource metadata
advertises the URL the clients actually see.

## Part 3 — Claude

Claude → **Settings → Connectors → Add custom connector**

- **Name:** Murray Context Ledger
- **Remote MCP server URL:** `https://<public-host>/mcp`
- Leave the OAuth client ID/secret fields empty.

Click **Connect**: Claude fetches
`/.well-known/oauth-protected-resource/mcp`, discovers the Auth0 tenant,
registers via DCR, and opens the Auth0 login + consent screen. After consent
the connector shows the six ledger tools.

**Test:** ask Claude *"What do you know about me from my ledger?"* — it should
call `get_profile` (and often `search_context`) and answer from your facts.

> [screenshot placeholder: Claude connector dialog + first tool call]

## Part 4 — ChatGPT

ChatGPT → **Settings → Apps & Connectors → Advanced settings** → enable
**Developer mode**, then **Create connector**:

- **Name:** Murray Context Ledger
- **MCP server URL:** `https://<public-host>/mcp`
- **Authentication:** OAuth

Complete the Auth0 login + consent. In a conversation, enable the connector
(Developer mode tools, and Deep Research can use `search`/`fetch`).

**Test:** *"Search my ledger for what you know about me."*

> [screenshot placeholder: ChatGPT developer-mode connector form]

## Part 5 — Verifying calls landed

Every tool call is audited. To see the proof:

```sql
select ts, tool, c.display_name as client, array_length(fact_ids, 1) as facts
from audit_log a join clients c on c.id = a.client_id
where a.user_id = '<your auth0 sub>'
order by a.ts desc limit 20;
```

You should see one row per tool invocation, attributed to a distinct client
row per connector (Claude and ChatGPT register separate OAuth clients).

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| Client loops on login / immediate 401 after consent | Tenant **Default Audience** not set — tokens are minted without the ledger audience |
| "Registration failed" during connect | **OIDC Dynamic Application Registration** not enabled on the tenant |
| Auth0 login page shows "no connections" | Connection not promoted to **domain level** (third-party apps see only domain-level connections) |
| Tool calls fail with "revoked" message | The client row in `clients` was revoked; re-enable it in the ledger dashboard (P2) or update the row |
| Connector connects but tools see no facts | Facts must be `status = 'active'` and share a scope with the client's `granted_scopes` (default `{personal, work}`) |
