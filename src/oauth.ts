export const BENTO_SCOPE = "bento";
export const DEFAULT_BENTO_MCP_URL = "https://mcp.bentonow.com/mcp";
const AUTH_CODE_TTL_SECONDS = 300;
const ACCESS_TOKEN_TTL_SECONDS = 3600;
const CHATGPT_REDIRECT_ORIGIN = "https://chatgpt.com";
const LOOPBACK_REDIRECT_HOSTS = new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);

export interface OAuthEnvironment {
  AUTH_SECRET?: string;
  BENTO_MCP_URL?: string;
  OAUTH_REDIRECT_URIS?: string;
  PUBLIC_BASE_URL?: string;
}

export interface OAuthConfig {
  authSecret: string;
  bentoMcpUrl: string;
  publicBaseUrl: string;
  resource: string;
  redirectUris: string[];
}

export interface BentoCredentials {
  publishableKey: string;
  secretKey: string;
  siteUuid: string;
}

export interface AuthorizationRequest {
  clientId: string;
  codeChallenge: string;
  redirectUri: string;
  resource: string;
  scope: string;
  state: string;
}

export class OAuthRequestError extends Error {
  constructor(
    public readonly error: string,
    message: string,
    public readonly status = 400,
  ) {
    super(message);
    this.name = "OAuthRequestError";
  }
}

export function getOAuthConfig(
  request: Request,
  env: OAuthEnvironment,
): OAuthConfig {
  const publicBaseUrl = normalizePublicBaseUrl(
    env.PUBLIC_BASE_URL || new URL(request.url).origin,
  );
  const bentoMcpUrl = normalizeMcpUrl(env.BENTO_MCP_URL || DEFAULT_BENTO_MCP_URL);
  const authSecret = env.AUTH_SECRET?.trim();

  if (!authSecret || authSecret.length < 32) {
    throw new Error("AUTH_SECRET must be at least 32 characters long");
  }

  const redirectUris = (env.OAUTH_REDIRECT_URIS || "")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
  if (redirectUris.some((value) => !isSafeConfiguredRedirectUri(value))) {
    throw new Error("OAUTH_REDIRECT_URIS must contain HTTPS redirect URIs");
  }

  return {
    authSecret,
    bentoMcpUrl,
    publicBaseUrl,
    resource: `${publicBaseUrl}/mcp`,
    redirectUris,
  };
}

export function parseAuthorizationRequest(
  params: URLSearchParams,
  config: OAuthConfig,
): AuthorizationRequest {
  const clientId = requiredParam(params, "client_id");
  const redirectUri = requiredParam(params, "redirect_uri");
  const responseType = requiredParam(params, "response_type");
  const codeChallenge = requiredParam(params, "code_challenge");
  const codeChallengeMethod = requiredParam(params, "code_challenge_method");
  const resource = requiredParam(params, "resource");
  const scope = parseScope(params.get("scope"));

  if (responseType !== "code") {
    throw new OAuthRequestError(
      "unsupported_response_type",
      "Only the authorization code response type is supported",
    );
  }

  assertClientId(clientId);
  if (!isAllowedRedirectUri(redirectUri, config)) {
    throw new OAuthRequestError("invalid_request", "The redirect URI is not allowed");
  }

  if (codeChallengeMethod !== "S256" || !/^[A-Za-z0-9_-]{43,128}$/.test(codeChallenge)) {
    throw new OAuthRequestError(
      "invalid_request",
      "A valid S256 PKCE code challenge is required",
    );
  }

  if (resource !== config.resource) {
    throw new OAuthRequestError("invalid_target", "The OAuth resource is invalid");
  }

  return {
    clientId,
    codeChallenge,
    redirectUri,
    resource,
    scope,
    state: params.get("state") || "",
  };
}

export async function issueAuthorizationCode(
  request: AuthorizationRequest,
  credentials: BentoCredentials,
  config: OAuthConfig,
) {
  // ponytail: stateless encrypted codes/tokens; add KV-backed revocation if immediate revoke/refresh becomes required.
  return encryptPayload(
    {
      kind: "authorization_code",
      ...request,
      credentials: validateCredentials(credentials),
      exp: now() + AUTH_CODE_TTL_SECONDS,
    },
    config.authSecret,
  );
}

export async function exchangeAuthorizationCode(
  params: URLSearchParams,
  config: OAuthConfig,
) {
  if (params.get("grant_type") !== "authorization_code") {
    throw new OAuthRequestError(
      "unsupported_grant_type",
      "Only the authorization_code grant is supported",
    );
  }

  const code = requiredParam(params, "code");
  const clientId = requiredParam(params, "client_id");
  const redirectUri = requiredParam(params, "redirect_uri");
  const codeVerifier = requiredParam(params, "code_verifier");
  const resource = requiredParam(params, "resource");
  const payload = await decryptPayload<AuthorizationCodePayload>(
    code,
    config.authSecret,
  );

  if (
    payload.kind !== "authorization_code" ||
    payload.exp <= now() ||
    payload.clientId !== clientId ||
    payload.redirectUri !== redirectUri ||
    payload.resource !== resource ||
    payload.scope !== BENTO_SCOPE
  ) {
    throw new OAuthRequestError("invalid_grant", "The authorization code is invalid or expired");
  }

  if (!/^[A-Za-z0-9._~-]{43,128}$/.test(codeVerifier)) {
    throw new OAuthRequestError("invalid_grant", "The PKCE verifier is invalid");
  }

  const expectedChallenge = encodeBase64Url(
    new Uint8Array(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(codeVerifier)),
    ),
  );
  if (expectedChallenge !== payload.codeChallenge) {
    throw new OAuthRequestError("invalid_grant", "The PKCE verifier is invalid");
  }

  const accessToken = await encryptPayload(
    {
      kind: "access_token",
      credentials: payload.credentials,
      exp: now() + ACCESS_TOKEN_TTL_SECONDS,
      resource: config.resource,
      scope: BENTO_SCOPE,
      tokenId: randomId(),
    },
    config.authSecret,
  );

  return {
    accessToken,
    expiresIn: ACCESS_TOKEN_TTL_SECONDS,
    scope: BENTO_SCOPE,
  };
}

export async function decodeAccessToken(
  token: string,
  config: OAuthConfig,
): Promise<BentoCredentials> {
  const payload = await decryptPayload<AccessTokenPayload>(token, config.authSecret);
  if (
    payload.kind !== "access_token" ||
    payload.exp <= now() ||
    payload.resource !== config.resource ||
    payload.scope !== BENTO_SCOPE
  ) {
    throw new OAuthRequestError("invalid_token", "The access token is invalid or expired", 401);
  }

  return validateCredentials(payload.credentials);
}

export function parseScope(value: string | null) {
  const scopes = (value || BENTO_SCOPE).split(/\s+/).filter(Boolean);
  if (scopes.length !== 1 || scopes[0] !== BENTO_SCOPE) {
    throw new OAuthRequestError("invalid_scope", `Only the ${BENTO_SCOPE} scope is supported`);
  }
  return BENTO_SCOPE;
}

export function isAllowedRedirectUri(value: string, config: OAuthConfig) {
  if (config.redirectUris.includes(value)) {
    return true;
  }

  let redirect: URL;
  try {
    redirect = new URL(value);
  } catch {
    return false;
  }

  if (
    redirect.search ||
    redirect.hash ||
    redirect.username ||
    redirect.password
  ) {
    return false;
  }

  if (
    redirect.protocol === "http:" &&
    LOOPBACK_REDIRECT_HOSTS.has(redirect.hostname) &&
    /^\/callback\/[A-Za-z0-9_-]+$/.test(redirect.pathname)
  ) {
    return true;
  }

  if (redirect.origin !== CHATGPT_REDIRECT_ORIGIN) {
    return false;
  }

  return (
    redirect.pathname === "/connector_platform_oauth_redirect" ||
    /^\/connector\/oauth\/[A-Za-z0-9_-]+$/.test(redirect.pathname)
  );
}

function assertClientId(value: string) {
  try {
    const clientId = new URL(value);
    if (
      clientId.protocol !== "https:" ||
      clientId.username ||
      clientId.password ||
      clientId.search ||
      clientId.hash
    ) {
      throw new Error();
    }
  } catch {
    throw new OAuthRequestError("invalid_client", "The client ID must be an HTTPS URL");
  }
}

function requiredParam(params: URLSearchParams, name: string) {
  const value = params.get(name)?.trim();
  if (!value) {
    throw new OAuthRequestError("invalid_request", `Missing ${name}`);
  }
  return value;
}

function validateCredentials(credentials: BentoCredentials): BentoCredentials {
  return {
    publishableKey: validateCredential("publishable key", credentials.publishableKey),
    secretKey: validateCredential("secret key", credentials.secretKey),
    siteUuid: validateCredential("site UUID", credentials.siteUuid),
  };
}

function validateCredential(label: string, value: unknown) {
  if (typeof value !== "string") {
    throw new OAuthRequestError("invalid_request", `Missing Bento ${label}`);
  }

  const normalized = value.trim();
  if (normalized.length < 8 || normalized.length > 512 || /[\r\n]/.test(normalized)) {
    throw new OAuthRequestError("invalid_request", `Bento ${label} is invalid`);
  }
  return normalized;
}

function normalizePublicBaseUrl(value: string) {
  const parsed = new URL(value);
  if (
    (parsed.protocol !== "https:" && parsed.hostname !== "localhost" && parsed.hostname !== "127.0.0.1") ||
    parsed.username ||
    parsed.password ||
    parsed.pathname !== "/" ||
    parsed.search ||
    parsed.hash
  ) {
    throw new Error("PUBLIC_BASE_URL must be an HTTPS origin");
  }
  return parsed.origin;
}

function normalizeMcpUrl(value: string) {
  const parsed = new URL(value);
  if (
    parsed.protocol !== "https:" ||
    parsed.username ||
    parsed.password ||
    parsed.search ||
    parsed.hash ||
    !parsed.pathname.endsWith("/mcp")
  ) {
    throw new Error("BENTO_MCP_URL must be an HTTPS /mcp endpoint");
  }
  return parsed.toString();
}

function isSafeConfiguredRedirectUri(value: string) {
  try {
    const redirect = new URL(value);
    return (
      (redirect.protocol === "https:" ||
        (redirect.protocol === "http:" &&
          ["localhost", "127.0.0.1"].includes(redirect.hostname))) &&
      !redirect.username &&
      !redirect.password &&
      !redirect.search &&
      !redirect.hash
    );
  } catch {
    return false;
  }
}

async function encryptPayload(payload: object, secret: string) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      await getKey(secret),
      new TextEncoder().encode(JSON.stringify(payload)),
    ),
  );
  const combined = new Uint8Array(iv.length + encrypted.length);
  combined.set(iv);
  combined.set(encrypted, iv.length);
  return encodeBase64Url(combined);
}

async function decryptPayload<T>(token: string, secret: string) {
  try {
    const combined = decodeBase64Url(token);
    if (combined.length <= 12) {
      throw new Error();
    }
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: combined.slice(0, 12) },
      await getKey(secret),
      combined.slice(12),
    );
    const payload = JSON.parse(new TextDecoder().decode(plaintext)) as T;
    if (!payload || typeof payload !== "object") {
      throw new Error();
    }
    return payload;
  } catch {
    throw new OAuthRequestError("invalid_grant", "The authorization token is invalid or expired");
  }
}

async function getKey(secret: string) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(secret));
  return crypto.subtle.importKey("raw", digest, { name: "AES-GCM" }, false, [
    "encrypt",
    "decrypt",
  ]);
}

function encodeBase64Url(bytes: Uint8Array) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function decodeBase64Url(value: string) {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error();
  }
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "===";
  const binary = atob(padded.slice(0, padded.length - (padded.length % 4)));
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function randomId() {
  return encodeBase64Url(crypto.getRandomValues(new Uint8Array(16)));
}

function now() {
  return Math.floor(Date.now() / 1000);
}

interface AuthorizationCodePayload extends AuthorizationRequest {
  credentials: BentoCredentials;
  exp: number;
  kind: "authorization_code";
}

interface AccessTokenPayload {
  credentials: BentoCredentials;
  exp: number;
  kind: "access_token";
  resource: string;
  scope: string;
  tokenId: string;
}
