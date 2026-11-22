// The transport seam.
//
// `client.ts` already takes an `AiTransport`, but the route builds its client
// per request, so the suite needs one place to substitute the socket for a
// canned response. That place is here — a module-level override for in-process
// tests, plus `AI_FAKE_TRANSPORT=1` for the browser suite, resolved at call
// time. Both refuse to activate under `APP_ENV=production`, so a misconfigured
// deployment cannot be talked into pointing the assistant at a fake provider.
//
// `AI_FAKE_TRANSPORT` is test-only and documented as such: it exists so
// `tests/e2e/assistant.spec.ts` can stream a turn offline, and it is not a
// configuration knob a deployment should ever set.
//
// Production never sets either: `resolveAssistantTransport()` returns the real
// `fetchTransport`, which sends the bearer key and refuses redirects.

import { fetchTransport, type AiTransport } from "../../../../src/lib/ai/client";
import { createFakeAssistantTransport, fakeAssistantTransportEnabled } from "./fake-transport";

let override: AiTransport | null = null;

/**
 * Installs a fake transport for the test suite. Throws in production: a test
 * hook that works in production is a bypass, not a hook.
 */
export function setAssistantTransport(transport: AiTransport | null): void {
  if (process.env.APP_ENV === "production") {
    throw new Error("The assistant transport seam is unavailable in production.");
  }
  override = transport;
}

/** The transport this process should use. */
export function resolveAssistantTransport(): AiTransport {
  if (override !== null) return override;
  if (fakeAssistantTransportEnabled()) return createFakeAssistantTransport();
  return fetchTransport;
}
