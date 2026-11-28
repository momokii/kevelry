// The one shape check every untrusted JSON boundary shares.
//
// Bodies, gateway frames, usage blocks and error envelopes all arrive as
// `unknown` and all need the same question answered before a field is read:
// is this a JSON object? Arrays and `null` are not — an array would answer
// `typeof === "object"` and then read `[0]` as a named field, which is how a
// shape check becomes a silent misread.

/** `value` as a plain JSON object, or `null` when it is anything else. */
export function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}
