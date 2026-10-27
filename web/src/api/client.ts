import createClient, { type Middleware } from "openapi-fetch";
import type { components, paths } from "./schema";

export type Problem = components["schemas"]["Problem"];
export type Me = components["schemas"]["Me"];
export type Session = components["schemas"]["Session"];

/** An API error with the stable machine-readable code from problem+json. */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly problem?: Problem;

  constructor(status: number, problem?: Problem) {
    super(problem?.detail ?? problem?.title ?? `HTTP ${status}`);
    this.status = status;
    this.code = problem?.code ?? "unknown";
    this.problem = problem;
  }
}

// The CSRF token comes from the login response and from GET /me. It is kept
// in memory only (never in storage), and sent on every state-changing request.
let csrfToken = "";
export function setCsrfToken(token: string) {
  csrfToken = token;
}

const csrfMiddleware: Middleware = {
  onRequest({ request }) {
    if (request.method !== "GET" && request.method !== "HEAD" && csrfToken) {
      request.headers.set("X-CSRF-Token", csrfToken);
    }
    return request;
  },
};

export function makeClient(opts: { fetch?: typeof fetch; baseUrl?: string } = {}) {
  const client = createClient<paths>({
    baseUrl: opts.baseUrl ?? "/api/v1",
    credentials: "same-origin",
    ...(opts.fetch ? { fetch: opts.fetch } : {}),
  });
  client.use(csrfMiddleware);
  return client;
}

export const api = makeClient();

/** Returns data or throws ApiError, so React Query sees failures as errors. */
export async function unwrap<T>(
  call: Promise<{ data?: T; error?: unknown; response: Response }>,
): Promise<T> {
  const { data, error, response } = await call;
  if (!response.ok) {
    throw new ApiError(response.status, error as Problem | undefined);
  }
  return data as T;
}
