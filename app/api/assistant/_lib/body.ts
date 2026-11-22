// The assistant's request body: strict, bounded, and rejected rather than
// coerced.
//
// This is the only POST body the application accepts, so it is also the only
// place untrusted bytes enter a code path with a budget attached. Three rules:
//
//  1. **Bounded read.** The body is consumed from the request stream with a
//     hard byte cap; a body over the cap is refused *while reading*, not after
//     it has been buffered. A screenshot is at most 1.5 MB decoded, so a 3 MB
//     envelope is generous and still finite.
//  2. **No unknown keys.** `messages`, `image`, `cveContext` and nothing else.
//     An unknown key is a client bug, and silently ignoring it hides the bug
//     until it matters.
//  3. **The image is checked, not trusted.** Declared MIME type, decoded size
//     and magic bytes must agree; a `data:image/gif` URL or a PNG header on a
//     WebP declaration is refused with `BAD_IMAGE` before the model sees it.
//
// Nothing here interprets the text: screening for weaponisation is
// `preScreen`'s job, in the route, so a body can be valid and still refused.

import type { ErrorCode } from "../../v1/_lib/errors";

/** Body envelope: 1.5 MB of image base64 plus room for 12 000 chars of text. */
export const ASSISTANT_MAX_BODY_BYTES = 3 * 1024 * 1024;

/** History bounds, matching the plan's `history ≤ 12 turns / 12 000 chars`. */
export const ASSISTANT_MAX_MESSAGES = 12;
export const ASSISTANT_MAX_MESSAGE_CHARS = 2000;
export const ASSISTANT_MAX_TOTAL_CHARS = 12_000;

/** One image, ≤ 1.5 MB decoded, and only these three formats. */
export const ASSISTANT_MAX_IMAGES = 1;
export const ASSISTANT_MAX_IMAGE_BYTES = 1_572_864;
export const ASSISTANT_IMAGE_MIME_TYPES = ["image/png", "image/jpeg", "image/webp"] as const;

/** `CVE-YYYY-NNNN` — the same shape the tools validate. */
export const ASSISTANT_CVE_CONTEXT_PATTERN = /^CVE-[0-9]{4}-[0-9]{4,}$/;

/** Data URL with a base64 payload and no whitespace or parameters. */
const DATA_URL_PATTERN = /^data:(image\/(?:png|jpeg|webp));base64,([A-Za-z0-9+/]+={0,2})$/;

const MESSAGE_ROLES = ["user", "assistant"] as const;
const BODY_KEYS = ["messages", "image", "cveContext"] as const;
const MESSAGE_KEYS = ["role", "content"] as const;
const IMAGE_KEYS = ["dataUrl"] as const;

export interface AssistantMessageInput {
  role: "user" | "assistant";
  content: string;
}

export interface AssistantTurnBody {
  messages: AssistantMessageInput[];
  image?: { dataUrl: string };
  cveContext?: string;
}

export interface BodyFailure {
  ok: false;
  code: ErrorCode;
  message: string;
  details?: Record<string, unknown>;
}

export type BodyResult = { ok: true; body: AssistantTurnBody } | BodyFailure;

export type ReadBodyResult =
  | { ok: true; value: unknown }
  | { ok: false; code: ErrorCode; message: string; details?: Record<string, unknown> };

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

/**
 * Reads the request body with a hard cap. Returns a typed failure instead of
 * throwing, so the route's guard sequence has one shape to branch on.
 */
export async function readAssistantBody(
  request: Request,
  maxBytes: number = ASSISTANT_MAX_BODY_BYTES,
): Promise<ReadBodyResult> {
  const contentType = request.headers.get("content-type");
  if (contentType === null || !contentType.toLowerCase().startsWith("application/json")) {
    return {
      ok: false,
      code: "BAD_REQUEST",
      message: "Content-Type must be application/json.",
    };
  }
  const declared = request.headers.get("content-length");
  if (declared !== null && Number(declared) > maxBytes) {
    return {
      ok: false,
      code: "BAD_REQUEST",
      message: "The request body is too large.",
      details: { maxBytes },
    };
  }
  const body = request.body;
  if (body === null) {
    return { ok: false, code: "BAD_REQUEST", message: "The request body is required." };
  }
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        return {
          ok: false,
          code: "BAD_REQUEST",
          message: "The request body is too large.",
          details: { maxBytes },
        };
      }
      chunks.push(value);
    }
  } catch {
    return { ok: false, code: "BAD_REQUEST", message: "The request body could not be read." };
  } finally {
    reader.releaseLock();
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  let decoded: string;
  try {
    decoded = new TextDecoder("utf-8", { fatal: true }).decode(merged);
  } catch {
    return { ok: false, code: "BAD_REQUEST", message: "The request body is not valid UTF-8." };
  }
  try {
    return { ok: true, value: JSON.parse(decoded) as unknown };
  } catch {
    return { ok: false, code: "BAD_REQUEST", message: "The request body is not valid JSON." };
  }
}

/** Decoded byte length of a base64 payload, without decoding it. */
export function base64ByteLength(payload: string): number {
  const padding = payload.endsWith("==") ? 2 : payload.endsWith("=") ? 1 : 0;
  return Math.floor((payload.length * 3) / 4) - padding;
}

function sniffMime(bytes: Uint8Array): string | null {
  if (bytes.length >= 8) {
    const png = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
    if (png.every((byte, index) => bytes[index] === byte)) return "image/png";
  }
  if (bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) {
    return "image/jpeg";
  }
  if (bytes.length >= 12) {
    const riff = String.fromCharCode(...bytes.subarray(0, 4));
    const webp = String.fromCharCode(...bytes.subarray(8, 12));
    if (riff === "RIFF" && webp === "WEBP") return "image/webp";
  }
  return null;
}

function imageFailure(
  message: string,
  details: Record<string, unknown> = {},
): BodyFailure & { ok: false } {
  return { ok: false, code: "BAD_IMAGE", message, details };
}

/** Validates `image` strictly: one object, one `dataUrl`, matching magic bytes. */
function validateImage(
  raw: unknown,
): { ok: true; image?: { dataUrl: string } } | (BodyFailure & { ok: false }) {
  if (raw === undefined) return { ok: true };
  if (Array.isArray(raw)) {
    return imageFailure(`At most ${String(ASSISTANT_MAX_IMAGES)} image per request.`, {
      max: ASSISTANT_MAX_IMAGES,
    });
  }
  const image = asRecord(raw);
  if (image === null) return imageFailure("`image` must be an object with a `dataUrl`.");
  for (const key of Object.keys(image)) {
    if (!(IMAGE_KEYS as readonly string[]).includes(key)) {
      return imageFailure(`Unknown image field "${key}".`, { key });
    }
  }
  const dataUrl = image["dataUrl"];
  if (typeof dataUrl !== "string") {
    return imageFailure("`image.dataUrl` must be a base64 data URL.");
  }
  const match = DATA_URL_PATTERN.exec(dataUrl);
  if (match === null) {
    return imageFailure(
      `The image must be a base64 data URL of type ${ASSISTANT_IMAGE_MIME_TYPES.join(", ")}.`,
      { allowed: [...ASSISTANT_IMAGE_MIME_TYPES] },
    );
  }
  const declared = match[1] as string;
  const payload = match[2] as string;
  const bytes = base64ByteLength(payload);
  if (bytes > ASSISTANT_MAX_IMAGE_BYTES) {
    return imageFailure("The image is larger than the 1.5 MB limit.", {
      maxBytes: ASSISTANT_MAX_IMAGE_BYTES,
    });
  }
  if (bytes === 0) return imageFailure("The image is empty.");
  // Sniff the header only: the payload itself is never decoded here, and a
  // declaration that disagrees with the bytes is refused rather than forwarded.
  const sniffed = sniffMime(Buffer.from(payload.slice(0, 32), "base64"));
  if (sniffed === null || sniffed !== declared) {
    return imageFailure("The image bytes do not match their declared type.", {
      declared,
      sniffed,
    });
  }
  return { ok: true, image: { dataUrl } };
}

/**
 * Validates the parsed body. Order is deliberate: keys, then messages, then the
 * image — a request with an oversized message should not pay for an image scan.
 */
export function validateAssistantBody(raw: unknown): BodyResult {
  const root = asRecord(raw);
  if (root === null) {
    return { ok: false, code: "BAD_REQUEST", message: "The body must be a JSON object." };
  }
  for (const key of Object.keys(root)) {
    if (!(BODY_KEYS as readonly string[]).includes(key)) {
      return {
        ok: false,
        code: "BAD_REQUEST",
        message: `Unknown field "${key}".`,
        details: { key, allowed: [...BODY_KEYS] },
      };
    }
  }

  const rawMessages = root["messages"];
  if (!Array.isArray(rawMessages)) {
    return { ok: false, code: "BAD_REQUEST", message: "`messages` must be an array." };
  }
  if (rawMessages.length === 0) {
    return { ok: false, code: "BAD_REQUEST", message: "`messages` must not be empty." };
  }
  if (rawMessages.length > ASSISTANT_MAX_MESSAGES) {
    return {
      ok: false,
      code: "BAD_REQUEST",
      message: `At most ${String(ASSISTANT_MAX_MESSAGES)} messages per turn.`,
      details: { max: ASSISTANT_MAX_MESSAGES, received: rawMessages.length },
    };
  }

  const messages: AssistantMessageInput[] = [];
  let totalChars = 0;
  for (const [index, entry] of rawMessages.entries()) {
    const message = asRecord(entry);
    if (message === null) {
      return {
        ok: false,
        code: "BAD_REQUEST",
        message: `messages[${String(index)}] is not an object.`,
      };
    }
    for (const key of Object.keys(message)) {
      if (!(MESSAGE_KEYS as readonly string[]).includes(key)) {
        return {
          ok: false,
          code: "BAD_REQUEST",
          message: `Unknown field "${key}" in messages[${String(index)}].`,
          details: { key, index },
        };
      }
    }
    const role = message["role"];
    if (typeof role !== "string" || !(MESSAGE_ROLES as readonly string[]).includes(role)) {
      return {
        ok: false,
        code: "BAD_REQUEST",
        message: `messages[${String(index)}].role must be "user" or "assistant".`,
        details: { index },
      };
    }
    const content = message["content"];
    if (typeof content !== "string") {
      return {
        ok: false,
        code: "BAD_REQUEST",
        message: `messages[${String(index)}].content must be a string.`,
        details: { index },
      };
    }
    if (content.length > ASSISTANT_MAX_MESSAGE_CHARS) {
      return {
        ok: false,
        code: "BAD_REQUEST",
        message: `Each message is limited to ${String(ASSISTANT_MAX_MESSAGE_CHARS)} characters.`,
        details: { index, max: ASSISTANT_MAX_MESSAGE_CHARS, received: content.length },
      };
    }
    totalChars += content.length;
    messages.push({ role: role as AssistantMessageInput["role"], content });
  }
  if (totalChars > ASSISTANT_MAX_TOTAL_CHARS) {
    return {
      ok: false,
      code: "BAD_REQUEST",
      message: `The conversation is limited to ${String(ASSISTANT_MAX_TOTAL_CHARS)} characters.`,
      details: { max: ASSISTANT_MAX_TOTAL_CHARS, received: totalChars },
    };
  }
  const last = messages[messages.length - 1] as AssistantMessageInput;
  if (last.role !== "user") {
    // The turn answers a question; a trailing assistant message would let a
    // client put words in the answer slot before the model has said anything.
    return {
      ok: false,
      code: "BAD_REQUEST",
      message: "The last message must be a user message.",
    };
  }

  const imageResult = validateImage(root["image"]);
  if (!imageResult.ok) return imageResult;

  let cveContext: string | undefined;
  const rawContext = root["cveContext"];
  if (rawContext !== undefined) {
    if (typeof rawContext !== "string" || !ASSISTANT_CVE_CONTEXT_PATTERN.test(rawContext)) {
      return {
        ok: false,
        code: "BAD_ID",
        message: "`cveContext` must be a CVE id in the form CVE-YYYY-NNNN.",
      };
    }
    cveContext = rawContext;
  }

  const body: AssistantTurnBody = { messages };
  if (imageResult.image !== undefined) body.image = imageResult.image;
  if (cveContext !== undefined) body.cveContext = cveContext;
  return { ok: true, body };
}

/**
 * Rough session size in tokens. There is no server session — the client holds
 * the transcript — so the only honest session measure is the history it sent.
 * Four characters per token is the conservative direction for English text.
 */
export function estimateSessionTokens(messages: readonly AssistantMessageInput[]): number {
  let chars = 0;
  for (const message of messages) chars += message.content.length;
  return Math.ceil(chars / 4);
}
