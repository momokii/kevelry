// Screenshot intake, validated twice.
//
// The server re-checks everything in `app/api/assistant/_lib/body.ts` — MIME,
// decoded size, and magic bytes — because a client check is a courtesy, not a
// control. This module exists so the reader learns what is wrong before a
// 1.5 MB upload is attempted, and so the message is written once instead of
// living in three `catch` blocks.
//
// The rule the copy has to keep: an image is only ever used to find CVE ids.
// Nothing the image says becomes a fact; every id it yields is resolved against
// the dataset, and an unresolved id is reported as not in the dataset.

/** 1.5 MB, the same decoded limit the route enforces. */
export const ASSISTANT_IMAGE_MAX_BYTES = 1_572_864;

/** The limit as the copy states it. One string, so copy and validator agree. */
export const ASSISTANT_IMAGE_MAX_LABEL = "1.5 MB";

/** Exactly three formats, matching the route's allow-list and magic sniffer. */
export const ASSISTANT_IMAGE_MIME_TYPES = ["image/png", "image/jpeg", "image/webp"] as const;

export type AssistantImageMime = (typeof ASSISTANT_IMAGE_MIME_TYPES)[number];

export interface AssistantImageMetadata {
  name: string;
  /** The browser's declared type; empty when the OS did not supply one. */
  type: string;
  size: number;
}

/** The one image a turn may carry, as the client holds it. */
export interface AssistantImage {
  dataUrl: string;
  name: string;
  size: number;
  mime: AssistantImageMime;
}

/**
 * An image the desk is holding for the next turn.
 *
 * `id` is monotonic per session, and the turn's record carries the same one, so
 * a turn can say whether *its* screenshot is still the one being sent — after a
 * removal, or after a second attach, it is not, and the record says so instead
 * of implying the image is still in play.
 */
export interface AssistantAttachment extends AssistantImage {
  id: number;
  /** A downscaled copy (≤480px wide) for the turn's record, never the payload. */
  thumb: string;
}

/** The width cap for the record's copy: recognisable, not re-sendable. */
export const ASSISTANT_THUMBNAIL_WIDTH = 480;

/**
 * A downscaled copy of an attached image, for the turn's record.
 *
 * The turn keeps this and not the payload: ten turns × 2.1 MB of base64 is 21 MB
 * of retained string for a record that needs to be recognisable. Decoding is
 * `createImageBitmap`, which is absent under jsdom and in any environment without
 * a decoder — there the source is returned unchanged, so the record still shows
 * the picture and nothing has to branch on capability.
 */
export async function toThumbnail(dataUrl: string): Promise<string> {
  if (typeof createImageBitmap !== "function" || typeof document === "undefined") {
    return dataUrl;
  }
  try {
    const response = await fetch(dataUrl);
    const bitmap = await createImageBitmap(await response.blob());
    const scale = Math.min(1, ASSISTANT_THUMBNAIL_WIDTH / bitmap.width);
    const canvas = document.createElement("canvas");
    canvas.width = Math.max(1, Math.round(bitmap.width * scale));
    canvas.height = Math.max(1, Math.round(bitmap.height * scale));
    const context = canvas.getContext("2d");
    if (context === null) return dataUrl;
    context.drawImage(bitmap, 0, 0, canvas.width, canvas.height);
    bitmap.close();
    const thumb = canvas.toDataURL("image/webp", 0.75);
    return thumb.startsWith("data:image/") ? thumb : dataUrl;
  } catch {
    return dataUrl;
  }
}

export const IMAGE_EMPTY_MESSAGE = "That file is empty, so there is nothing to read.";
export const IMAGE_MAGIC_MISMATCH_MESSAGE =
  "That file's bytes are not a PNG, JPEG or WebP image. Save the screenshot again instead of renaming the file.";
export const IMAGE_UNREADABLE_MESSAGE =
  "That file could not be read as an image. Try saving the screenshot again.";

export function imageTooLargeMessage(size: number): string {
  return `That image is ${formatImageSize(size)}. The limit is ${ASSISTANT_IMAGE_MAX_LABEL} — crop it or downscale it before attaching.`;
}

export function imageWrongTypeMessage(type: string): string {
  const declared = type.trim() === "" ? "no file type at all" : type;
  return `Only PNG, JPEG and WebP screenshots are accepted. That file declares ${declared}.`;
}

/** `620 KB`, `1.4 MB` — coarse, because a screenshot's byte count is not a fact. */
export function formatImageSize(bytes: number): string {
  if (bytes < 1024) return `${String(Math.max(0, Math.round(bytes)))} B`;
  const kb = bytes / 1024;
  if (kb < 1024) return `${String(Math.round(kb))} KB`;
  const mb = kb / 1024;
  return `${mb < 10 ? mb.toFixed(1) : String(Math.round(mb))} MB`;
}

export function isAssistantImageMime(type: string): type is AssistantImageMime {
  return (ASSISTANT_IMAGE_MIME_TYPES as readonly string[]).includes(type);
}

export type ImageMetadataValidation =
  { ok: true; mime: AssistantImageMime | null } | { ok: false; message: string };

export type ImageByteValidation =
  { ok: true; mime: AssistantImageMime } | { ok: false; message: string };

/**
 * Type and size, before a byte is read. An empty declared type is allowed: some
 * platforms do not supply one, and the sniffer below is the authority.
 */
export function validateImageMetadata(metadata: AssistantImageMetadata): ImageMetadataValidation {
  if (metadata.type.trim() !== "" && !isAssistantImageMime(metadata.type)) {
    return { ok: false, message: imageWrongTypeMessage(metadata.type) };
  }
  if (metadata.size === 0) return { ok: false, message: IMAGE_EMPTY_MESSAGE };
  if (metadata.size > ASSISTANT_IMAGE_MAX_BYTES) {
    return { ok: false, message: imageTooLargeMessage(metadata.size) };
  }
  return { ok: true, mime: isAssistantImageMime(metadata.type) ? metadata.type : null };
}

const PNG_SIGNATURE = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] as const;

/** Magic bytes only: the extension and declared type are never trusted. */
export function sniffImageMime(bytes: Uint8Array): AssistantImageMime | null {
  if (bytes.length >= 8 && PNG_SIGNATURE.every((byte, index) => bytes[index] === byte)) {
    return "image/png";
  }
  if (bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) {
    return "image/jpeg";
  }
  if (
    bytes.length >= 12 &&
    bytes[0] === 0x52 &&
    bytes[1] === 0x49 &&
    bytes[2] === 0x46 &&
    bytes[3] === 0x46 &&
    bytes[8] === 0x57 &&
    bytes[9] === 0x45 &&
    bytes[10] === 0x42 &&
    bytes[11] === 0x50
  ) {
    return "image/webp";
  }
  return null;
}

/**
 * The bytes, against the declared type. A mismatch is refused rather than
 * relabelled: a renamed file is a reader about to be surprised by the server's
 * own refusal, and saying so now is kinder.
 */
export function validateImageBytes(
  declared: AssistantImageMime | null,
  bytes: Uint8Array,
): ImageByteValidation {
  if (bytes.length === 0) return { ok: false, message: IMAGE_EMPTY_MESSAGE };
  const sniffed = sniffImageMime(bytes);
  if (sniffed === null) return { ok: false, message: IMAGE_MAGIC_MISMATCH_MESSAGE };
  if (declared !== null && sniffed !== declared) {
    return { ok: false, message: IMAGE_MAGIC_MISMATCH_MESSAGE };
  }
  return { ok: true, mime: sniffed };
}

function toBase64(bytes: Uint8Array): string {
  // Chunked: spreading 1.5 MB into one call overflows the argument limit.
  let binary = "";
  const chunk = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunk) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunk));
  }
  return btoa(binary);
}

export type ImageReadResult = { ok: true; image: AssistantImage } | { ok: false; message: string };

/**
 * Reads one file into the data URL the route expects, refusing before the read
 * when metadata is wrong and after it when the bytes disagree with the label.
 */
export async function readImageFile(file: File): Promise<ImageReadResult> {
  const metadata = validateImageMetadata({ name: file.name, type: file.type, size: file.size });
  if (!metadata.ok) return metadata;

  let bytes: Uint8Array;
  try {
    bytes = new Uint8Array(await file.arrayBuffer());
  } catch {
    return { ok: false, message: IMAGE_UNREADABLE_MESSAGE };
  }

  const validation = validateImageBytes(metadata.mime, bytes);
  if (!validation.ok) return validation;

  return {
    ok: true,
    image: {
      dataUrl: `data:${validation.mime};base64,${toBase64(bytes)}`,
      name: file.name,
      size: bytes.byteLength,
      mime: validation.mime,
    },
  };
}
