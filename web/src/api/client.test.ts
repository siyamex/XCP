import { describe, expect, it, vi } from "vitest";
import { ApiError, makeClient, setCsrfToken, unwrap } from "./client";

function fakeFetch(status: number, body: unknown, contentType = "application/json") {
  return vi.fn(async (input: Request) => {
    void input;
    return new Response(status === 204 ? null : JSON.stringify(body), {
      status,
      headers: { "Content-Type": contentType },
    });
  });
}

// Node needs absolute URLs; the browser build uses the relative "/api/v1".
const baseUrl = "http://panel.test/api/v1";

describe("api client", () => {
  it("sends the CSRF token on state-changing requests only", async () => {
    setCsrfToken("tok123");
    const f = fakeFetch(200, { status: "ok" });
    const client = makeClient({ fetch: f as unknown as typeof fetch, baseUrl });
    await client.GET("/health");
    await client.POST("/auth/logout");
    const [getReq, postReq] = f.mock.calls.map((c) => c[0]);
    expect(getReq!.headers.get("X-CSRF-Token")).toBeNull();
    expect(postReq!.headers.get("X-CSRF-Token")).toBe("tok123");
  });

  it("turns problem+json into ApiError with the stable code", async () => {
    const problem = { type: "about:blank", title: "Unauthorized", status: 401, code: "invalid_credentials", detail: "nope" };
    const client = makeClient({ fetch: fakeFetch(401, problem, "application/problem+json") as unknown as typeof fetch, baseUrl });
    const err = await unwrap(client.POST("/auth/login", { body: { username: "a", password: "b" } })).catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(401);
    expect(err.code).toBe("invalid_credentials");
    expect(err.message).toBe("nope");
  });
});
