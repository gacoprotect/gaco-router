import { NextResponse } from "next/server";
import {
  getProviderConnectionById,
  getProviderConnections,
  createProviderConnection,
  updateProviderConnection,
  getProxyPools,
  getProxyPoolById,
  validateApiKey,
} from "@/models";

export const dynamic = "force-dynamic";

const ALLOWED = new Set([
  "name",
  "priority",
  "globalPriority",
  "defaultModel",
  "isActive",
  "apiKey",
  "accessToken",
  "refreshToken",
  "expiresAt",
  "expiresIn",
  "tokenType",
  "scope",
  "projectId",
  "email",
  "displayName",
  "testStatus",
  "lastError",
  "lastErrorAt",
  "providerSpecificData",
  "authType",
  "idToken",
  "lastRefreshAt",
]);

// Token fields that can invalidate a live OAuth session if an older export overwrites them
const TOKEN_FIELDS = [
  "accessToken",
  "refreshToken",
  "idToken",
  "expiresAt",
  "expiresIn",
  "tokenType",
  "scope",
  "lastRefreshAt",
];

const TYPE_TO_PROVIDER = {
  xai: "grok-cli",
  "grok-cli": "grok-cli",
  gcli: "grok-cli",
  "grok-build": "grok-cli",
  gb: "grok-cli",
  "xai-api": "xai",
  xai_oauth: "xai",
};

/**
 * Explicit allow-list — webhook only mutates providers with known CPA/export mapping.
 * Expand when a new export shape is implemented + tested.
 */
const WEBHOOK_SUPPORTED_PROVIDERS = new Set([
  "grok-cli",
  // explicit api.x.ai OAuth export (type xai-api / xai_oauth) — same token fields as grok-cli map
  "xai",
]);

const OPS = new Set(["insert", "update", "upsert"]);

function isWebhookSupportedProvider(providerId) {
  return !!providerId && WEBHOOK_SUPPORTED_PROVIDERS.has(providerId);
}

function unsupportedProviderResult(providerId) {
  return {
    ok: false,
    status: 400,
    error: "Provider not supported by webhook",
    code: "unsupported_provider",
    provider: providerId || null,
    supported: [...WEBHOOK_SUPPORTED_PROVIDERS],
  };
}

function unauthorized() {
  return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
}

function getWebhookSecret() {
  return process.env.WEBHOOK_SECRET || process.env.API_KEY_SECRET || "";
}

function extractPresentedKey(request) {
  const auth = request.headers.get("authorization") || "";
  if (auth.startsWith("Bearer ")) return auth.slice(7).trim();
  return (
    request.headers.get("x-webhook-secret") ||
    request.headers.get("x-api-key") ||
    ""
  ).trim();
}

async function checkAuth(request) {
  const presented = extractPresentedKey(request);
  if (!presented) return false;
  const secret = getWebhookSecret();
  if (secret && presented === secret) return true;
  try {
    return await validateApiKey(presented);
  } catch {
    return false;
  }
}

function decodeJwtPayload(token) {
  if (!token || typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length < 2) return null;
  try {
    const b64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const pad = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
    return JSON.parse(Buffer.from(pad, "base64").toString("utf8"));
  } catch {
    return null;
  }
}

function firstDefined(...vals) {
  for (const v of vals) {
    if (v !== undefined && v !== null && v !== "") return v;
  }
  return undefined;
}

/**
 * Resolve proxy pool for insert (or explicit update).
 * Priority:
 *  1) payload proxyPoolId / proxy_pool_id / providerSpecificData.proxyPoolId
 *  2) payload proxyPoolName / proxy_pool_name (active pool name match)
 *  3) env WEBHOOK_DEFAULT_PROXY_POOL_ID
 *  4) auto least-used active pool if autoProxyPool / WEBHOOK_AUTO_PROXY_POOL
 *  5) none
 */
async function resolveProxyPoolBinding(item, { forCreate }) {
  const rawId = firstDefined(
    item.proxyPoolId,
    item.proxy_pool_id,
    item.providerSpecificData?.proxyPoolId,
  );
  const rawName = firstDefined(item.proxyPoolName, item.proxy_pool_name);
  const clear =
    rawId === null ||
    rawId === "__none__" ||
    item.proxyPoolId === null ||
    item.proxy_pool_id === null;

  if (clear && !forCreate) {
    return { clear: true };
  }

  if (rawId && rawId !== "__none__") {
    const pool = await getProxyPoolById(String(rawId).trim());
    if (!pool) {
      return { error: { ok: false, status: 400, error: "Proxy pool not found", code: "proxy_pool_not_found", proxyPoolId: String(rawId) } };
    }
    if (pool.isActive === false) {
      return { error: { ok: false, status: 400, error: "Proxy pool is inactive", code: "proxy_pool_inactive", proxyPoolId: pool.id } };
    }
    return { proxyPoolId: pool.id, pool };
  }

  if (rawName) {
    const pools = await getProxyPools({ isActive: true });
    const name = String(rawName).trim().toLowerCase();
    const pool = pools.find((p) => String(p.name || "").trim().toLowerCase() === name);
    if (!pool) {
      return { error: { ok: false, status: 400, error: "Proxy pool name not found", code: "proxy_pool_not_found", proxyPoolName: rawName } };
    }
    return { proxyPoolId: pool.id, pool };
  }

  // Explicit false on item disables auto for this row
  if (item.autoProxyPool === false || item.auto_proxy_pool === false) {
    return { proxyPoolId: null };
  }

  const envDefault = (process.env.WEBHOOK_DEFAULT_PROXY_POOL_ID || "").trim();
  if (envDefault) {
    const pool = await getProxyPoolById(envDefault);
    if (!pool) {
      return { error: { ok: false, status: 400, error: "WEBHOOK_DEFAULT_PROXY_POOL_ID not found", code: "proxy_pool_not_found", proxyPoolId: envDefault } };
    }
    if (pool.isActive === false) {
      return { error: { ok: false, status: 400, error: "Default proxy pool is inactive", code: "proxy_pool_inactive", proxyPoolId: pool.id } };
    }
    return { proxyPoolId: pool.id, pool, source: "env_default" };
  }

  const autoEnv = String(process.env.WEBHOOK_AUTO_PROXY_POOL || "").toLowerCase();
  const auto =
    item.autoProxyPool === true ||
    item.auto_proxy_pool === true ||
    autoEnv === "1" ||
    autoEnv === "true" ||
    autoEnv === "yes";

  if (!auto || !forCreate) {
    return { proxyPoolId: null };
  }

  const pools = await getProxyPools({ isActive: true });
  if (!pools.length) {
    return { proxyPoolId: null, source: "auto_none" };
  }

  // least-used among active pools (count connections that reference pool id)
  const allConns = await getProviderConnections();
  const counts = new Map(pools.map((p) => [p.id, 0]));
  for (const c of allConns) {
    const pid = c.providerSpecificData?.proxyPoolId;
    if (pid && counts.has(pid)) counts.set(pid, (counts.get(pid) || 0) + 1);
  }
  pools.sort((a, b) => {
    const d = (counts.get(a.id) || 0) - (counts.get(b.id) || 0);
    if (d !== 0) return d;
    return String(a.name || a.id).localeCompare(String(b.name || b.id));
  });
  const pick = pools[0];
  return { proxyPoolId: pick.id, pool: pick, source: "auto_least_used" };
}

function applyProxyPoolToUpdates(updates, binding) {
  if (!binding || binding.error) return updates;
  const psd = { ...(updates.providerSpecificData || {}) };
  if (binding.clear) {
    delete psd.proxyPoolId;
    return { ...updates, providerSpecificData: psd };
  }
  if (binding.proxyPoolId) {
    psd.proxyPoolId = binding.proxyPoolId;
    return { ...updates, providerSpecificData: psd };
  }
  return updates;
}

function parseTime(v) {
  if (!v) return null;
  const t = new Date(v).getTime();
  return Number.isFinite(t) ? t : null;
}

function resolveOp(raw, defaultOp) {
  const v = String(raw?.op || raw?.action || raw?.mode || defaultOp || "insert").toLowerCase();
  return OPS.has(v) ? v : null;
}

/**
 * Accept CPA / auth-export payload (snake_case) or internal connection shape.
 */
function normalizeItem(raw) {
  if (!raw || typeof raw !== "object") return null;
  const item = { ...raw };

  const typeKey = String(item.type || item.provider || "").toLowerCase();
  if (!item.provider && typeKey) {
    item.provider = TYPE_TO_PROVIDER[typeKey] || typeKey;
  }
  if (item.provider === "xai") {
    const base = String(item.base_url || item.baseUrl || "");
    if (base.includes("cli-chat-proxy.grok.com") || !base.includes("api.x.ai")) {
      item.provider = "grok-cli";
    }
  }

  item.accessToken = firstDefined(item.accessToken, item.access_token);
  item.refreshToken = firstDefined(item.refreshToken, item.refresh_token);
  item.idToken = firstDefined(item.idToken, item.id_token);
  item.tokenType = firstDefined(item.tokenType, item.token_type);
  item.expiresIn = firstDefined(item.expiresIn, item.expires_in);
  item.expiresAt = firstDefined(item.expiresAt, item.expired, item.expires_at);
  item.lastRefreshAt = firstDefined(item.lastRefreshAt, item.last_refresh, item.lastRefresh);
  item.authType = firstDefined(
    item.authType,
    item.auth_kind,
    item.authKind,
    item.apiKey || item.api_key ? "apikey" : "oauth",
  );
  item.apiKey = firstDefined(item.apiKey, item.api_key);
  item.forceTokens = item.forceTokens === true || item.force_tokens === true;

  const idPayload = decodeJwtPayload(item.idToken);
  const accessPayload = decodeJwtPayload(item.accessToken);
  item.email = firstDefined(item.email, idPayload?.email, accessPayload?.email);
  const sub = firstDefined(
    item.sub,
    item.userId,
    idPayload?.sub,
    accessPayload?.sub,
    accessPayload?.principal_id,
  );
  const displayName = firstDefined(
    item.displayName,
    item.display_name,
    [idPayload?.given_name, idPayload?.family_name].filter(Boolean).join(" ").trim() || undefined,
  );
  if (displayName) item.displayName = displayName;

  if (!item.expiresAt && item.expiresIn) {
    const n = Number(item.expiresIn);
    if (Number.isFinite(n) && n > 0) {
      item.expiresAt = new Date(Date.now() + n * 1000).toISOString();
    }
  }

  if (!item.name && item.display_name) item.name = item.display_name;

  const psd = { ...(item.providerSpecificData || {}) };
  if (item.idToken !== undefined) psd.idToken = item.idToken;
  if (item.email) psd.email = item.email;
  if (sub) psd.userId = sub;
  if (item.headers && typeof item.headers === "object") psd.headers = item.headers;
  if (item.base_url || item.baseUrl) psd.baseUrl = item.base_url || item.baseUrl;
  if (item.redirect_uri || item.redirectUri) psd.redirectUri = item.redirect_uri || item.redirectUri;
  if (item.token_endpoint || item.tokenEndpoint) psd.tokenEndpoint = item.token_endpoint || item.tokenEndpoint;
  if (item.provider === "grok-cli" && !psd.authMethod) {
    psd.authMethod = item.auth_kind || item.authType || "oauth";
  }
  if (Object.keys(psd).length) item.providerSpecificData = psd;

  return item;
}

function pickUpdates(body) {
  const out = {};
  for (const k of ALLOWED) {
    if (body[k] !== undefined) out[k] = body[k];
  }
  return out;
}

/**
 * Drop token fields when incoming export looks older than what 9Router already holds.
 * Prevents stale CPA re-upload from invalidating a rotated refresh_token.
 */
function applyTokenSafety(updates, existing, item) {
  const hasTokenWrite = TOKEN_FIELDS.some((f) => updates[f] !== undefined);
  if (!hasTokenWrite) return { updates, tokensApplied: false, tokensSkipped: false };

  if (item.forceTokens) {
    return { updates, tokensApplied: true, tokensSkipped: false };
  }

  const existingTs =
    parseTime(existing.lastRefreshAt) ||
    parseTime(existing.updatedAt) ||
    parseTime(existing.expiresAt);
  const incomingTs =
    parseTime(item.lastRefreshAt) ||
    parseTime(item.expiresAt);

  // Existing session was refreshed and caller sent no freshness marker, or older marker
  if (existingTs != null) {
    if (incomingTs == null || incomingTs < existingTs) {
      const next = { ...updates };
      for (const f of TOKEN_FIELDS) delete next[f];
      // also avoid clobbering idToken nested in psd if we stripped tokens
      if (next.providerSpecificData && existing.providerSpecificData) {
        next.providerSpecificData = {
          ...next.providerSpecificData,
          idToken: existing.providerSpecificData.idToken,
        };
      }
      return { updates: next, tokensApplied: false, tokensSkipped: true };
    }
  }

  return { updates, tokensApplied: true, tokensSkipped: false };
}

function sanitize(conn) {
  if (!conn) return null;
  const r = { ...conn };
  delete r.apiKey;
  delete r.accessToken;
  delete r.refreshToken;
  delete r.idToken;
  if (r.providerSpecificData?.idToken) {
    r.providerSpecificData = { ...r.providerSpecificData };
    delete r.providerSpecificData.idToken;
  }
  return r;
}

async function findExisting(item) {
  if (item.id) {
    const byId = await getProviderConnectionById(item.id);
    if (!byId) return { error: { ok: false, status: 404, error: "Connection not found", id: item.id } };
    return { existing: byId };
  }

  if (!item.provider) return { existing: null };

  const list = await getProviderConnections({ provider: item.provider });

  if (item.email) {
    const byEmail = list.find((c) => c.email === item.email);
    if (byEmail) return { existing: byEmail };
  }
  const sub = item.providerSpecificData?.userId;
  if (sub) {
    const bySub = list.find((c) => c.providerSpecificData?.userId === sub);
    if (bySub) return { existing: bySub };
  }
  if (item.name) {
    const byName = list.find((c) => c.name === item.name);
    if (byName) return { existing: byName };
  }
  return { existing: null };
}

async function processOne(raw, defaultOp) {
  const item = normalizeItem(raw);
  if (!item) return { ok: false, status: 400, error: "Invalid item" };

  const op = resolveOp(item, defaultOp);
  if (!op) {
    return { ok: false, status: 400, error: "op must be insert | update | upsert" };
  }

  // Resolve identity first so update-by-id can validate existing.provider
  const found = await findExisting(item);
  if (found.error) return found.error;
  const { existing } = found;

  const providerId = existing?.provider || item.provider;
  if (!isWebhookSupportedProvider(providerId)) {
    return unsupportedProviderResult(providerId);
  }
  // Reject attempts to retarget a row to another unsupported/mismatched provider id
  if (item.provider && !isWebhookSupportedProvider(item.provider)) {
    return unsupportedProviderResult(item.provider);
  }
  if (existing && item.provider && item.provider !== existing.provider) {
    return {
      ok: false,
      status: 400,
      error: "Provider mismatch for existing connection",
      code: "provider_mismatch",
      existingProvider: existing.provider,
      requestedProvider: item.provider,
    };
  }

  // Force canonical provider id from allow-list resolution
  if (!item.provider) item.provider = providerId;

  const updates = pickUpdates(item);
  // Never allow provider field rewrite via ALLOWED — not in ALLOWED already

  if (op === "insert") {
    if (existing) {
      return {
        ok: false,
        status: 409,
        error: "Connection already exists",
        code: "already_exists",
        id: existing.id,
        provider: existing.provider,
        email: existing.email || null,
        name: existing.name || null,
      };
    }
    return createOne(item, updates);
  }

  if (op === "update") {
    if (!existing) {
      return {
        ok: false,
        status: 404,
        error: "Connection not found",
        code: "not_found",
      };
    }
    return updateOne(existing, item, updates);
  }

  // upsert
  if (existing) return updateOne(existing, item, updates);
  return createOne(item, updates);
}

async function createOne(item, updates) {
  if (!item.provider) {
    return { ok: false, status: 400, error: "provider/type required for create (or pass id)" };
  }
  if (!isWebhookSupportedProvider(item.provider)) {
    return unsupportedProviderResult(item.provider);
  }
  if (!item.name && !item.email && !item.displayName) {
    return { ok: false, status: 400, error: "email or name required for create" };
  }
  if (!item.accessToken && !item.apiKey && !item.refreshToken) {
    return { ok: false, status: 400, error: "access_token / apiKey / refresh_token required for create" };
  }

  const binding = await resolveProxyPoolBinding(item, { forCreate: true });
  if (binding.error) return binding.error;
  const withPool = applyProxyPoolToUpdates(updates, binding);

  const created = await createProviderConnection({
    provider: item.provider,
    authType: item.authType || (item.apiKey ? "apikey" : "oauth"),
    name: item.name || item.displayName || item.email,
    email: item.email,
    ...withPool,
    isActive: item.isActive !== undefined ? item.isActive : true,
  });
  return {
    ok: true,
    action: "created",
    proxyPoolId: binding.proxyPoolId || null,
    proxyPoolSource: binding.source || (binding.proxyPoolId ? "payload" : null),
    connection: sanitize(created),
  };
}

async function updateOne(existing, item, updates) {
  let next = { ...updates };
  if (next.providerSpecificData) {
    next.providerSpecificData = {
      ...(existing.providerSpecificData || {}),
      ...next.providerSpecificData,
    };
  }

  // Only touch proxy pool when caller explicitly sent pool fields / auto flag
  const wantsPool =
    item.proxyPoolId !== undefined ||
    item.proxy_pool_id !== undefined ||
    item.proxyPoolName !== undefined ||
    item.proxy_pool_name !== undefined ||
    item.autoProxyPool !== undefined ||
    item.auto_proxy_pool !== undefined ||
    item.providerSpecificData?.proxyPoolId !== undefined;

  let binding = null;
  if (wantsPool) {
    binding = await resolveProxyPoolBinding(item, { forCreate: false });
    if (binding.error) return binding.error;
    next = applyProxyPoolToUpdates(next, binding);
  }

  const safe = applyTokenSafety(next, existing, item);
  next = safe.updates;

  // nothing left to write
  if (Object.keys(next).length === 0) {
    return {
      ok: true,
      action: "noop",
      tokensSkipped: safe.tokensSkipped,
      connection: sanitize(existing),
    };
  }

  const updated = await updateProviderConnection(existing.id, next);
  return {
    ok: true,
    action: "updated",
    tokensSkipped: safe.tokensSkipped,
    tokensApplied: safe.tokensApplied,
    proxyPoolId:
      binding?.proxyPoolId ??
      updated?.providerSpecificData?.proxyPoolId ??
      existing.providerSpecificData?.proxyPoolId ??
      null,
    proxyPoolSource: binding?.source || (binding?.proxyPoolId ? "payload" : undefined),
    connection: sanitize(updated),
  };
}

function extractItemsAndDefaultOp(body, url) {
  const qOp = url?.searchParams?.get("op") || url?.searchParams?.get("action");
  let defaultOp = resolveOp({ op: qOp }, null) || resolveOp(body, null) || "insert";

  // body.op applies to whole batch; strip so it is not treated as a connection row
  if (body && typeof body === "object" && !Array.isArray(body) && Array.isArray(body.connections)) {
    return { items: body.connections, defaultOp: resolveOp(body, defaultOp) || defaultOp };
  }
  if (Array.isArray(body)) {
    return { items: body, defaultOp };
  }
  if (body && typeof body === "object") {
    // single connection object may carry its own op
    return { items: [body], defaultOp };
  }
  return { items: [], defaultOp };
}

// POST /api/webhooks/providers?op=insert|update|upsert
// Auth: env secret OR dashboard API key
// Default op = insert (409 if already exists — never silent token overwrite)
export async function POST(request) {
  try {
    if (!(await checkAuth(request))) return unauthorized();

    const body = await request.json();
    const { items, defaultOp } = extractItemsAndDefaultOp(body, request.nextUrl);

    if (!items.length) {
      return NextResponse.json({ error: "Empty payload" }, { status: 400 });
    }

    const results = [];
    for (const item of items) {
      results.push(await processOne(item, defaultOp));
    }

    const failed = results.filter((r) => !r.ok);
    const status =
      failed.length === 0
        ? 200
        : failed.length === results.length
          ? failed[0].status || 400
          : 207;
    return NextResponse.json({ op: defaultOp, results }, { status });
  } catch (error) {
    console.log("webhook providers error:", error);
    return NextResponse.json({ error: "Failed to process webhook" }, { status: 500 });
  }
}
