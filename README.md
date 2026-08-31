# Bento for ChatGPT

This package publishes Bento's existing remote MCP server through a ChatGPT-compatible OAuth 2.1 bridge.

ChatGPT cannot send customer-provided API keys as custom headers. The bridge handles that constraint without putting credentials in chat prompts:

1. ChatGPT discovers OAuth metadata from the bridge.
2. The user enters a Bento publishable key, secret key, and site UUID on the bridge's HTTPS consent page.
3. The bridge returns a short-lived encrypted bearer token.
4. The bridge decrypts the token per MCP request and forwards the three Bento headers to `https://mcp.bentonow.com/mcp`.

The bridge stores no credentials in KV, D1, R2, cookies, logs, or the repository. Rotating `AUTH_SECRET` immediately invalidates all issued tokens. Access tokens expire after one hour; users can reauthorize after expiry.

## Local development

Use Node 22 or newer:

```bash
npm install
cp .dev.vars.example .dev.vars
# Replace AUTH_SECRET in .dev.vars with a random value of at least 32 characters.
npm run check
npm test
npm run dev
```

The local MCP URL is `http://localhost:8787/mcp`. The default authorization callback allowlist is the current ChatGPT callback shape. Set `OAUTH_REDIRECT_URIS` in `.dev.vars` when testing with another OAuth client.

## Deploy

The default production hostname is `chatgpt-mcp.bentonow.com`; change `PUBLIC_BASE_URL` and the custom-domain route together if Bento chooses another hostname.

```bash
npx wrangler login
npx wrangler secret put AUTH_SECRET
npm run dry-run
npm run deploy
```

Verify the public endpoints:

```bash
curl -fsS https://chatgpt-mcp.bentonow.com/health
curl -fsS https://chatgpt-mcp.bentonow.com/.well-known/oauth-protected-resource
curl -fsS https://chatgpt-mcp.bentonow.com/.well-known/oauth-authorization-server
```

The deployment must be reachable over public HTTPS before submission. The plugin portal may also require the exact token it supplies at `/.well-known/openai-apps-challenge`; set that value as the `OPENAI_APPS_CHALLENGE` Worker variable for the duration of verification.

## Codex connection and publication

For local development in the current Codex build, register the local bridge and authorize it:

```bash
codex mcp add bento-local --url http://localhost:8787/mcp
codex mcp login bento-local --scopes bento
```

The checked-in plugin package uses `.mcp.json` to point at the production HTTPS bridge. The local `bento-local` connection is the safe local smoke-test path; the package connection becomes usable after the bridge is deployed at `https://chatgpt-mcp.bentonow.com`.

For public publication, use the OpenAI Platform plugin submission portal:

- Choose `With MCP` and the `Universal` server URL `https://chatgpt-mcp.bentonow.com/mcp`.
- Scan the deployed endpoint and review the imported OAuth metadata, tools, schemas, and annotations.
- Provide Bento's verified developer/business identity, logo, website, support, privacy, and terms URLs.
- Provide a fully featured Bento demo site and reviewer-ready credentials. OpenAI review cannot be completed without working test credentials for the authenticated MCP server.
- Add five positive and three negative test cases, country availability, release notes, and the policy attestations, then submit for review.

The checked-in `.codex-plugin/plugin.json` is the package manifest and includes the icon/logo assets plus `.mcp.json` wiring. `.app.json` is intentionally omitted because no registered `plugin_asdk_app...` connection ID is available; the MCP server's OAuth metadata is the canonical authentication path for this package.

The network-flow diagram is available as [`assets/oauth-bridge-flow.png`](./assets/oauth-bridge-flow.png) and as an editable [`assets/oauth-bridge-flow.svg`](./assets/oauth-bridge-flow.svg).

## Security boundary

The bridge is the ChatGPT-facing resource server and OAuth authorization server. The existing Bento Worker remains the upstream MCP server and receives only short-lived per-request header values from the bridge. Do not add Bento credentials to Wrangler vars, source files, test fixtures, screenshots, or prompts.

The token design is stateless and encrypted with AES-GCM. This keeps the deployment small and avoids a credential database. The deliberate ceiling is that individual token revocation is not available before expiry; add a KV-backed token denylist or per-user credential store if immediate revocation, refresh tokens, or multi-instance account management becomes a requirement.
