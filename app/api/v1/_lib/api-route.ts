// One request lifecycle for the v1 read routes. Every handler used to repeat
// the same guard sequence by hand — database handle, rate reservation,
// concurrency slot, request bounds, error mapping, slot release — so a new
// route could silently skip a guard, reorder two, or release the slot before
// the handler settled. The order below is the contract; a route supplies only
// its own work, and the route file stays a thin export of `GET`/`OPTIONS`.
//
// Named `api-route.ts`, not `route.ts`: tests/api-hardening.test.ts counts every
// file named `route.ts` under app/api/v1 (recursing into `_lib`) and asserts the
// exact route count, so a helper holding that name would read as a route.
import type { CveDatabase } from "../../../../src/lib/db";
import { getDb } from "./db-handle";
import { ApiError } from "./errors";
import {
  acquireConcurrencySlot,
  assertRequestBounds,
  preflightResponse,
  releaseConcurrencySlot,
  type RateReservation,
} from "./guardrails";
import { errorResponse, reserveRateLimit } from "./responses";

/** What a handler receives once the shared guards have passed. */
export interface ApiRouteContext {
  request: Request;
  /** The rebound writable handle from `getDb`, never null inside a handler. */
  db: CveDatabase;
  /** This request's rate reservation, to thread through every response. */
  rate: RateReservation;
}

/**
 * Wrap a v1 handler in the shared guard sequence.
 *
 * Order is the behaviour: a database failure answers `INTERNAL` before any
 * budget is spent; an exhausted rate budget returns its own 429 before a
 * concurrency slot exists; a busy server answers `RATE_LIMITED` and never
 * releases a slot it did not take. A handler's `ApiError` keeps its code,
 * message and details, any other throw becomes the same `INTERNAL` body, and
 * the slot is released after the handler's promise settles — not when the
 * promise is returned.
 *
 * Extra arguments are forwarded untouched, so a dynamic route still receives
 * its `context` with the awaited `params`.
 */
export function withApiRoute<RouteArgs extends unknown[] = []>(
  handler: (ctx: ApiRouteContext, ...routeArgs: RouteArgs) => Promise<Response>,
): (request: Request, ...routeArgs: RouteArgs) => Promise<Response> {
  return async (request, ...routeArgs) => {
    let db: CveDatabase | null = null;
    try {
      db = getDb();
    } catch {
      return errorResponse(request, "INTERNAL", "Unexpected failure handling the request.", null);
    }
    const rate = reserveRateLimit(request, db);
    if (rate instanceof Response) return rate;
    if (!acquireConcurrencySlot()) {
      return errorResponse(
        request,
        "RATE_LIMITED",
        "Server is busy. Retry after 60 seconds.",
        db,
        undefined,
        rate,
      );
    }
    try {
      assertRequestBounds(request);
      return await handler({ request, db, rate }, ...routeArgs);
    } catch (error) {
      if (error instanceof ApiError) {
        return errorResponse(request, error.code, error.message, db, error.details, rate);
      }
      return errorResponse(
        request,
        "INTERNAL",
        "Unexpected failure handling the request.",
        db,
        undefined,
        rate,
      );
    } finally {
      releaseConcurrencySlot();
    }
  };
}

/**
 * The 204 preflight every v1 route answers for `OPTIONS`.
 *
 * It spends one hit from the same per-IP budget a GET spends, so an `OPTIONS`
 * loop is throttled instead of being a free request amplifier. It takes no
 * concurrency slot: that cap bounds in-flight database work and a preflight
 * reads nothing.
 */
export function apiPreflight(request: Request): Response {
  const rate = reserveRateLimit(request, null);
  if (rate instanceof Response) return rate;
  return preflightResponse(request, rate);
}
