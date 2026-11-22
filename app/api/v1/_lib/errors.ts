export type ErrorCode =
  | "BAD_REQUEST"
  | "BAD_ID"
  | "BAD_CURSOR"
  | "BAD_LIMIT"
  | "BAD_QUERY"
  | "BAD_FILTER"
  | "BAD_DATE_RANGE"
  | "CVE_NOT_FOUND"
  | "LIST_NOT_FOUND"
  | "CHECKPOINT_UNAVAILABLE"
  | "REPLAY_UNAVAILABLE"
  | "RATE_LIMITED"
  | "INTERNAL"
  // Assistant codes. They live in the same taxonomy so the one route outside
  // `/api/v1` reuses `errorResponse` instead of hand-building a second error
  // shape; no v1 route can emit them.
  | "AI_DISABLED"
  | "AI_BUDGET_EXHAUSTED"
  | "AI_TIMEOUT"
  | "AI_UPSTREAM_ERROR"
  | "AI_TRUNCATED"
  | "AI_REFUSED"
  | "BAD_IMAGE";

export class ApiError extends Error {
  readonly code: ErrorCode;
  readonly status: number;
  readonly details?: Record<string, unknown>;

  constructor(code: ErrorCode, status: number, message: string, details?: Record<string, unknown>) {
    super(message);
    this.name = "ApiError";
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

export function errorStatus(code: ErrorCode): number {
  switch (code) {
    case "CVE_NOT_FOUND":
    case "LIST_NOT_FOUND":
    case "CHECKPOINT_UNAVAILABLE":
    case "REPLAY_UNAVAILABLE":
      return 404;
    case "RATE_LIMITED":
    case "AI_BUDGET_EXHAUSTED":
      return 429;
    case "AI_TIMEOUT":
      return 504;
    case "AI_DISABLED":
      return 503;
    case "AI_UPSTREAM_ERROR":
    case "AI_TRUNCATED":
      return 502;
    case "AI_REFUSED":
      return 422;
    case "INTERNAL":
      return 500;
    default:
      return 400;
  }
}
