import { describe, expect, it, vi, beforeEach } from "vitest";
import { isAuthError } from "../../open-sse/services/accountFallback.js";

const mocks = vi.hoisted(() => ({
  updateProviderConnection: vi.fn(),
  getProviderConnections: vi.fn(),
  getSettings: vi.fn(),
  getProxyPools: vi.fn(),
}));

vi.mock("@/lib/localDb", () => ({
  updateProviderConnection: mocks.updateProviderConnection,
  getProviderConnections: mocks.getProviderConnections,
  getSettings: mocks.getSettings,
  getProxyPools: mocks.getProxyPools,
  validateApiKey: vi.fn(),
}));

describe("isAuthError — credential/auth error classification", () => {
  it("flags HTTP 401 as auth error", () => {
    expect(isAuthError(401, "Unauthorized")).toBe(true);
    expect(isAuthError(401, JSON.stringify({ error: { message: "Invalid token" } }))).toBe(true);
    expect(isAuthError(401, null)).toBe(true);
  });

  it("flags HTTP 403 as auth error unless it is rate limit or quota wording", () => {
    expect(isAuthError(403, "Forbidden - User not allowed")).toBe(true);
    expect(isAuthError(403, "quota exceeded for project")).toBe(false);
    expect(isAuthError(403, "rate limit reached")).toBe(false);
    expect(isAuthError(403, "too many requests")).toBe(false);
  });

  it("flags auth keywords even on non-401 status", () => {
    expect(isAuthError(400, "Invalid API key provided")).toBe(true);
    expect(isAuthError(200, "token expired")).toBe(true);
    expect(isAuthError(500, "upstream_auth_error: credentials revoked")).toBe(true);
    expect(isAuthError(null, "no credentials found")).toBe(true);
  });

  it("does not flag transient errors, server errors, or rate limits as auth errors", () => {
    expect(isAuthError(429, "Too Many Requests")).toBe(false);
    expect(isAuthError(429, "RESOURCE_EXHAUSTED")).toBe(false);
    expect(isAuthError(500, "Internal Server Error")).toBe(false);
    expect(isAuthError(502, "Bad Gateway")).toBe(false);
    expect(isAuthError(503, "Service Unavailable")).toBe(false);
    expect(isAuthError(400, "maximum context length exceeded")).toBe(false);
  });
});

describe("markAccountUnavailable — auto-disable behavior", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.getProviderConnections.mockResolvedValue([
      { id: "conn-1", name: "Account 1", provider: "openai", backoffLevel: 0 }
    ]);
    mocks.updateProviderConnection.mockResolvedValue({ id: "conn-1" });
  });

  it("auto-disables connection (isActive: false, testStatus: 'error') on 401 auth error", async () => {
    const { markAccountUnavailable } = await import("../../src/sse/services/auth.js");
    const res = await markAccountUnavailable("conn-1", 401, "Invalid API key provided", "openai", "gpt-4o");

    expect(res.shouldFallback).toBe(true);
    expect(mocks.updateProviderConnection).toHaveBeenCalledWith(
      "conn-1",
      expect.objectContaining({
        isActive: false,
        testStatus: "error",
        errorCode: 401,
      })
    );
  });

  it("does NOT set isActive: false on 429 rate limit errors", async () => {
    const { markAccountUnavailable } = await import("../../src/sse/services/auth.js");
    const res = await markAccountUnavailable("conn-1", 429, "Rate limit reached", "openai", "gpt-4o");

    expect(res.shouldFallback).toBe(true);
    expect(mocks.updateProviderConnection).toHaveBeenCalledWith(
      "conn-1",
      expect.objectContaining({
        testStatus: "unavailable",
        errorCode: 429,
      })
    );
    const updateCall = mocks.updateProviderConnection.mock.calls[0][1];
    expect(updateCall.isActive).toBeUndefined();
  });
});
