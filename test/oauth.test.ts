import { describe, expect, it } from "vitest";
import {
  decodeAccessToken,
  exchangeAuthorizationCode,
  getOAuthConfig,
  issueAuthorizationCode,
  parseAuthorizationRequest,
  type BentoCredentials,
} from "../src/oauth";

const request = new Request("https://chatgpt-mcp.bentonow.com/authorize");
const env = {
  AUTH_SECRET: "local-test-secret-that-is-long-enough-123456",
  BENTO_MCP_URL: "https://mcp.bentonow.com/mcp",
  PUBLIC_BASE_URL: "https://chatgpt-mcp.bentonow.com",
};

describe("Bento OAuth bridge", () => {
  it("round-trips Bento credentials through a PKCE authorization code", async () => {
    const config = getOAuthConfig(request, env);
    const codeVerifier = "verifier-abcdefghijklmnopqrstuvwxyz-0123456789";
    const codeChallenge = base64Url(
      new Uint8Array(
        await crypto.subtle.digest(
          "SHA-256",
          new TextEncoder().encode(codeVerifier),
        ),
      ),
    );
    const authorization = parseAuthorizationRequest(
      new URLSearchParams({
        client_id: "https://chatgpt.com/oauth/client.json",
        code_challenge: codeChallenge,
        code_challenge_method: "S256",
        redirect_uri: "https://chatgpt.com/connector_platform_oauth_redirect",
        response_type: "code",
        resource: config.resource,
        scope: "bento",
        state: "state-123",
      }),
      config,
    );
    const credentials: BentoCredentials = {
      publishableKey: "pub_test_123456",
      secretKey: "sec_test_123456",
      siteUuid: "site_test_123456",
    };

    const code = await issueAuthorizationCode(authorization, credentials, config);
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

    await expect(decodeAccessToken(token.accessToken, config)).resolves.toEqual(credentials);
  });

  it("rejects a wrong PKCE verifier", async () => {
    const config = getOAuthConfig(request, env);
    const codeVerifier = "verifier-abcdefghijklmnopqrstuvwxyz-0123456789";
    const codeChallenge = base64Url(
      new Uint8Array(
        await crypto.subtle.digest(
          "SHA-256",
          new TextEncoder().encode(codeVerifier),
        ),
      ),
    );
    const authorization = parseAuthorizationRequest(
      new URLSearchParams({
        client_id: "https://chatgpt.com/oauth/client.json",
        code_challenge: codeChallenge,
        code_challenge_method: "S256",
        redirect_uri: "https://chatgpt.com/connector_platform_oauth_redirect",
        response_type: "code",
        resource: config.resource,
        scope: "bento",
      }),
      config,
    );
    const code = await issueAuthorizationCode(
      authorization,
      {
        publishableKey: "pub_test_123456",
        secretKey: "sec_test_123456",
        siteUuid: "site_test_123456",
      },
      config,
    );

    await expect(
      exchangeAuthorizationCode(
        new URLSearchParams({
          client_id: authorization.clientId,
          code,
          code_verifier: `${codeVerifier}wrong`,
          grant_type: "authorization_code",
          redirect_uri: authorization.redirectUri,
          resource: authorization.resource,
        }),
        config,
      ),
    ).rejects.toThrow("PKCE verifier is invalid");
  });

  it("allows Codex loopback OAuth callbacks", () => {
    const config = getOAuthConfig(request, env);
    const authorization = parseAuthorizationRequest(
      new URLSearchParams({
        client_id: "https://chatgpt.com/oauth/codex/test/client.json",
        code_challenge: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        code_challenge_method: "S256",
        redirect_uri: "http://127.0.0.1:65344/callback/test-token",
        response_type: "code",
        resource: config.resource,
        scope: "bento",
      }),
      config,
    );

    expect(authorization.redirectUri).toBe(
      "http://127.0.0.1:65344/callback/test-token",
    );
  });
});

function base64Url(bytes: Uint8Array) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
