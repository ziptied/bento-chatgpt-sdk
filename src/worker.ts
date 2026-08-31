import {
  BENTO_SCOPE,
  decodeAccessToken,
  exchangeAuthorizationCode,
  getOAuthConfig,
  issueAuthorizationCode,
  OAuthRequestError,
  parseAuthorizationRequest,
  type AuthorizationRequest,
  type OAuthConfig,
  type OAuthEnvironment,
} from "./oauth";

const VERSION = "0.1.0";

export interface Env extends OAuthEnvironment {
  OPENAI_APPS_CHALLENGE?: string;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/health") {
      return json({ ok: true });
    }

    if (url.pathname === "/version") {
      return json({
        name: "bento-chatgpt-mcp",
        version: VERSION,
        transport: "streamable-http",
        authentication: "oauth2-pkce",
      });
    }

    try {
      const config = getOAuthConfig(request, env);

      if (url.pathname === "/.well-known/oauth-protected-resource") {
        return json({
          resource: config.resource,
          authorization_servers: [config.publicBaseUrl],
          scopes_supported: [BENTO_SCOPE],
          resource_documentation: "https://docs.bentonow.com/developer_guides/introduction",
          resource_policy_uri: "https://bentonow.com/legal/privacy",
          resource_tos_uri: "https://bentonow.com/legal/terms",
        });
      }

      if (
        url.pathname === "/.well-known/oauth-authorization-server" ||
        url.pathname === "/.well-known/openid-configuration"
      ) {
        return json({
          issuer: config.publicBaseUrl,
          authorization_response_iss_parameter_supported: true,
          authorization_endpoint: `${config.publicBaseUrl}/authorize`,
          token_endpoint: `${config.publicBaseUrl}/token`,
          client_id_metadata_document_supported: true,
          token_endpoint_auth_methods_supported: ["none"],
          code_challenge_methods_supported: ["S256"],
          scopes_supported: [BENTO_SCOPE],
        });
      }

      if (url.pathname === "/.well-known/openai-apps-challenge") {
        return env.OPENAI_APPS_CHALLENGE
          ? text(env.OPENAI_APPS_CHALLENGE)
          : new Response("Not found", { status: 404 });
      }

      if (url.pathname === "/authorize") {
        return handleAuthorize(request, config);
      }

      if (url.pathname === "/token") {
        return handleToken(request, config);
      }

      if (url.pathname === "/mcp") {
        return handleMcp(request, config);
      }

      return new Response("Not found", { status: 404 });
    } catch (error) {
      if (error instanceof OAuthRequestError) {
        return json(
          { error: error.error, error_description: error.message },
          error.status,
        );
      }

      return json({ error: "server_error", error_description: "Bento ChatGPT bridge is not configured" }, 500);
    }
  },
};

async function handleAuthorize(request: Request, config: OAuthConfig) {
  if (request.method !== "GET" && request.method !== "POST") {
    return methodNotAllowed("GET, POST");
  }

  const params =
    request.method === "GET"
      ? new URL(request.url).searchParams
      : await readForm(request);
  const authorization = parseAuthorizationRequest(params, config);

  if (request.method === "GET") {
    return html(renderAuthorizePage(authorization, config), formActionSources(config));
  }

  if (params.get("approval") !== "approve") {
    return redirectWithError(authorization, config, "access_denied", "Bento access was not approved");
  }

  const code = await issueAuthorizationCode(
    authorization,
    {
      publishableKey: params.get("bento_publishable_key") || "",
      secretKey: params.get("bento_secret_key") || "",
      siteUuid: params.get("bento_site_uuid") || "",
    },
    config,
  );

  const redirect = new URL(authorization.redirectUri);
  redirect.searchParams.set("code", code);
  if (authorization.state) {
    redirect.searchParams.set("state", authorization.state);
  }
  redirect.searchParams.set("iss", config.publicBaseUrl);

  return new Response(null, {
    status: 302,
    headers: {
      Location: redirect.toString(),
      "Cache-Control": "no-store",
      "Referrer-Policy": "no-referrer",
    },
  });
}

async function handleToken(request: Request, config: OAuthConfig) {
  if (request.method !== "POST") {
    return methodNotAllowed("POST");
  }

  const params = await readForm(request);
  try {
    const result = await exchangeAuthorizationCode(params, config);
    return json({
      access_token: result.accessToken,
      token_type: "Bearer",
      expires_in: result.expiresIn,
      scope: result.scope,
    });
  } catch (error) {
    if (error instanceof OAuthRequestError) {
      return json(
        { error: error.error, error_description: error.message },
        error.status,
      );
    }
    return json({ error: "invalid_grant", error_description: "The authorization code is invalid" }, 400);
  }
}

async function handleMcp(request: Request, config: OAuthConfig) {
  if (request.method === "OPTIONS") {
    return cors(new Response(null, { status: 204 }));
  }

  if (!["GET", "POST", "DELETE"].includes(request.method)) {
    return methodNotAllowed("GET, POST, DELETE");
  }

  const token = readBearerToken(request.headers.get("Authorization"));
  if (!token) {
    return unauthorized(config, "Bento authorization is required");
  }

  let credentials;
  try {
    credentials = await decodeAccessToken(token, config);
  } catch {
    return unauthorized(config, "The Bento access token is invalid or expired");
  }

  const headers = new Headers(request.headers);
  headers.delete("Authorization");
  headers.delete("Host");
  headers.delete("Content-Length");
  headers.set("X-Bento-Publishable-Key", credentials.publishableKey);
  headers.set("X-Bento-Secret-Key", credentials.secretKey);
  headers.set("X-Bento-Site-UUID", credentials.siteUuid);

  const upstream = await fetch(config.bentoMcpUrl, {
    method: request.method,
    headers,
    body: request.method === "GET" ? undefined : request.body,
  });
  const response = new Response(upstream.body, upstream);
  response.headers.set("Cache-Control", "no-store");
  response.headers.set("Referrer-Policy", "no-referrer");
  return cors(response);
}

function renderAuthorizePage(authorization: AuthorizationRequest, config: OAuthConfig) {
  const hiddenFields = [
    ["client_id", authorization.clientId],
    ["redirect_uri", authorization.redirectUri],
    ["response_type", "code"],
    ["code_challenge", authorization.codeChallenge],
    ["code_challenge_method", "S256"],
    ["resource", authorization.resource],
    ["scope", authorization.scope],
    ["state", authorization.state],
  ]
    .map(([name, value]) => `<input type="hidden" name="${escapeHtml(name)}" value="${escapeHtml(value)}">`)
    .join("");

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Connect Bento to ChatGPT</title>
    <meta name="referrer" content="no-referrer">
  </head>
  <body>
    <main>
      <h1>Connect Bento to ChatGPT</h1>
      <p>Enter the credentials for the Bento site ChatGPT should manage.</p>
      <p>Your values are encrypted before the access token is issued and are not shown to ChatGPT.</p>
      <form method="post" action="/authorize">
        ${hiddenFields}
        <label>Publishable key<br><input name="bento_publishable_key" required autocomplete="off"></label><br><br>
        <label>Secret key<br><input name="bento_secret_key" type="password" required autocomplete="new-password"></label><br><br>
        <label>Site UUID<br><input name="bento_site_uuid" required autocomplete="off"></label><br><br>
        <button name="approval" value="approve" type="submit">Allow Bento access</button>
      </form>
      <p><a href="https://bentonow.com/legal/privacy">Privacy policy</a> · <a href="https://bentonow.com/legal/terms">Terms</a></p>
    </main>
  </body>
</html>`;
}

function redirectWithError(
  authorization: AuthorizationRequest,
  config: OAuthConfig,
  error: string,
  description: string,
) {
  const redirect = new URL(authorization.redirectUri);
  redirect.searchParams.set("error", error);
  redirect.searchParams.set("error_description", description);
  if (authorization.state) {
    redirect.searchParams.set("state", authorization.state);
  }
  redirect.searchParams.set("iss", config.publicBaseUrl);
  return new Response(null, {
    status: 302,
    headers: {
      Location: redirect.toString(),
      "Cache-Control": "no-store",
      "Referrer-Policy": "no-referrer",
    },
  });
}

function unauthorized(config: OAuthConfig, description: string) {
  return new Response("Authentication required", {
    status: 401,
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "no-store",
      "WWW-Authenticate": `Bearer resource_metadata="${config.publicBaseUrl}/.well-known/oauth-protected-resource", scope="${BENTO_SCOPE}", error="invalid_token", error_description="${description}"`,
    },
  });
}

function readBearerToken(value: string | null) {
  if (!value?.startsWith("Bearer ")) {
    return null;
  }
  const token = value.slice("Bearer ".length).trim();
  return token && !/\s/.test(token) ? token : null;
}

function cors(response: Response) {
  response.headers.set("Access-Control-Allow-Origin", "*");
  response.headers.set(
    "Access-Control-Allow-Headers",
    "Accept, Content-Type, Authorization, Mcp-Session-Id, MCP-Protocol-Version",
  );
  response.headers.set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
  response.headers.set("Access-Control-Expose-Headers", "Mcp-Session-Id");
  return response;
}

function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
    },
  });
}

function html(body: string, formActions = "'self'") {
  return new Response(body, {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "Content-Security-Policy": `default-src 'none'; form-action ${formActions}; base-uri 'none'; frame-ancestors 'none'`,
      "Referrer-Policy": "no-referrer",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

function formActionSources(config: OAuthConfig) {
  const sources = new Set([
    "'self'",
    "https://chatgpt.com",
    "http://localhost:*",
    "http://127.0.0.1:*",
    "http://[::1]:*",
  ]);

  for (const redirectUri of config.redirectUris) {
    const redirect = new URL(redirectUri);
    sources.add(`${redirect.protocol}//${redirect.host}`);
  }

  return [...sources].join(" ");
}

function text(body: string) {
  return new Response(body, {
    headers: { "Content-Type": "text/plain; charset=utf-8" },
  });
}

function methodNotAllowed(allow: string) {
  return new Response("Method not allowed", { status: 405, headers: { Allow: allow } });
}

async function readForm(request: Request) {
  const contentType = request.headers.get("Content-Type") || "";
  if (
    contentType &&
    !contentType.toLowerCase().startsWith("application/x-www-form-urlencoded")
  ) {
    throw new OAuthRequestError(
      "invalid_request",
      "OAuth requests must use form-encoded data",
    );
  }

  const length = Number(request.headers.get("Content-Length") || "0");
  if (length > 16_384) {
    throw new OAuthRequestError("invalid_request", "OAuth request is too large");
  }

  const body = await request.text();
  if (body.length > 16_384) {
    throw new OAuthRequestError("invalid_request", "OAuth request is too large");
  }
  return new URLSearchParams(body);
}

function escapeHtml(value: string) {
  return value.replace(/[&<>"']/g, (character) =>
    ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    })[character] || character,
  );
}
