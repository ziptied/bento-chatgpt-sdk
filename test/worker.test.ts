import { afterEach, describe, expect, it, vi } from "vitest";
import { getOAuthConfig, issueAuthorizationCode, exchangeAuthorizationCode } from "../src/oauth";
import worker, { type Env } from "../src/worker";

const env: Env = {
  AUTH_SECRET: "local-test-secret-that-is-long-enough-123456",
  BENTO_MCP_URL: "https://mcp.bentonow.com/mcp",
  PUBLIC_BASE_URL: "https://chatgpt-mcp.bentonow.com",
};

afterEach(() => {
  vi.restoreAllMocks();
});

describe("Bento ChatGPT worker", () => {
  it("advertises OAuth resource metadata", async () => {
    const response = await worker.fetch(
      new Request("https://chatgpt-mcp.bentonow.com/.well-known/oauth-protected-resource"),
      env,
    );

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      resource: "https://chatgpt-mcp.bentonow.com/mcp",
      authorization_servers: ["https://chatgpt-mcp.bentonow.com"],
      scopes_supported: ["bento"],
    });
  });

  it("allows Codex loopback callbacks from the consent form", async () => {
    const response = await worker.fetch(
      new Request(
        "https://chatgpt-mcp.bentonow.com/authorize?client_id=https%3A%2F%2Fchatgpt.com%2Foauth%2Fcodex%2Ftest%2Fclient.json&code_challenge=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&code_challenge_method=S256&redirect_uri=http%3A%2F%2F127.0.0.1%3A49668%2Fcallback%2Ftest&resource=https%3A%2F%2Fchatgpt-mcp.bentonow.com%2Fmcp&response_type=code&scope=bento",
      ),
      env,
    );

    expect(response.status).toBe(200);
    expect(response.headers.get("Content-Security-Policy")).toContain(
      "http://127.0.0.1:*",
    );
  });

  it("returns an OAuth challenge before forwarding unauthenticated MCP requests", async () => {
    const response = await worker.fetch(
      new Request("https://chatgpt-mcp.bentonow.com/mcp", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{}",
      }),
      env,
    );

    expect(response.status).toBe(401);
    expect(response.headers.get("WWW-Authenticate")).toContain(
      "oauth-protected-resource",
    );
  });

  it("translates an access token into per-request Bento headers", async () => {
    const request = new Request("https://chatgpt-mcp.bentonow.com/authorize");
    const config = getOAuthConfig(request, env);
    const codeVerifier = "verifier-abcdefghijklmnopqrstuvwxyz-0123456789";
    const codeChallenge = base64Url(
      new Uint8Array(
        await crypto.subtle.digest("SHA-256", new TextEncoder().encode(codeVerifier)),
      ),
    );
    const authorization = {
      clientId: "https://chatgpt.com/oauth/client.json",
      codeChallenge,
      redirectUri: "https://chatgpt.com/connector_platform_oauth_redirect",
      resource: config.resource,
      scope: "bento",
      state: "",
    };
    const code = await issueAuthorizationCode(
      authorization,
      {
        publishableKey: "pub_test_123456",
        secretKey: "sec_test_123456",
        siteUuid: "site_test_123456",
      },
      config,
    );
    const token = await exchangeAuthorizationCode(
      new URLSearchParams({
        client_id: authorization.clientId,
        code,
        code_verifier: codeVerifier,
        grant_type: "authorization_code",
        redirect_uri: authorization.redirectUri,
        resource: authorization.resource,
      }),
      config,
    );
    const upstream = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response("ok", { status: 200 }),
    );

    const response = await worker.fetch(
      new Request("https://chatgpt-mcp.bentonow.com/mcp", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token.accessToken}`,
          "Content-Type": "application/json",
        },
        body: "{\"jsonrpc\":\"2.0\"}",
      }),
      env,
    );

    expect(response.status).toBe(200);
    const [, init] = upstream.mock.calls[0] || [];
    const headers = new Headers(init?.headers);
    expect(headers.get("Authorization")).toBeNull();
    expect(headers.get("X-Bento-Publishable-Key")).toBe("pub_test_123456");
    expect(headers.get("X-Bento-Secret-Key")).toBe("sec_test_123456");
    expect(headers.get("X-Bento-Site-UUID")).toBe("site_test_123456");
  });
});

function base64Url(bytes: Uint8Array) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
