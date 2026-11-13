export type ErrorCode =
  | "BAD_REQUEST"
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
  | "INTERNAL";

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
      return 429;
    case "INTERNAL":
      return 500;
    default:
      return 400;
  }
}
