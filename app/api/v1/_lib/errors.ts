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
  | "BAD_IMAGE"
  /**
   * The envelope, not the schema: a body over the read cap. Its own code
   * because `400` under-reports it — nothing about the request was malformed,
   * it was simply larger than the route accepts.
   */
  | "PAYLOAD_TOO_LARGE";

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
    // `422` is semantic refusal: the request was well-formed and understood,
    // and what it carried is what cannot be accepted — a refused question, or
    // an image that is a second one, too large, or not one of the three types.
    case "AI_REFUSED":
    case "BAD_IMAGE":
      return 422;
    case "PAYLOAD_TOO_LARGE":
      return 413;
    case "INTERNAL":
      return 500;
    default:
      return 400;
  }
}
