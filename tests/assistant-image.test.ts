// Image intake: the two validators and the copy they refuse with.
//
// The server re-checks all of this, so these tests are about the reader's
// experience rather than about security: a wrong file is named in one sentence,
// before a 1.5 MB upload is attempted, and a renamed file is caught by its
// bytes rather than believed because of its extension.

import { describe, expect, it } from "vitest";

import {
  ASSISTANT_IMAGE_MAX_BYTES,
  IMAGE_EMPTY_MESSAGE,
  IMAGE_MAGIC_MISMATCH_MESSAGE,
  ASSISTANT_IMAGE_MAX_LABEL,
  formatImageSize,
  imageTooLargeMessage,
  imageWrongTypeMessage,
  sniffImageMime,
  validateImageBytes,
  validateImageMetadata,
} from "../src/components/assistant/assistant-image";

const PNG = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00]);
const JPEG = new Uint8Array([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10]);
const WEBP = new Uint8Array([
  0x52, 0x49, 0x46, 0x46, 0x24, 0x00, 0x00, 0x00, 0x57, 0x45, 0x42, 0x50, 0x56, 0x50, 0x38,
]);
const GIF = new Uint8Array([0x47, 0x49, 0x46, 0x38, 0x39, 0x61]);

describe("image metadata validation", () => {
  it("[CODE] accepts the three allowed types and reports which one it read", () => {
    for (const [type, expected] of [
      ["image/png", "image/png"],
      ["image/jpeg", "image/jpeg"],
      ["image/webp", "image/webp"],
    ] as const) {
      const result = validateImageMetadata({ name: "shot", type, size: 1024 });
      expect(result).toEqual({ ok: true, mime: expected });
    }
  });

  it("[CODE] refuses a type outside the allow-list and names what the file declares", () => {
    const result = validateImageMetadata({ name: "scan.pdf", type: "application/pdf", size: 200 });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.message).toBe(imageWrongTypeMessage("application/pdf"));
    expect(result.message).toContain("Only PNG, JPEG and WebP");
    expect(result.message).toContain("application/pdf");
  });

  it("[CODE] refuses a file over 1.5 MB and states its actual size and the limit", () => {
    const size = ASSISTANT_IMAGE_MAX_BYTES + 1;
    const result = validateImageMetadata({ name: "huge.png", type: "image/png", size });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.message).toContain(formatImageSize(size));
    expect(result.message).toContain(ASSISTANT_IMAGE_MAX_LABEL);
    expect(result.message).toContain("crop it or downscale it");
  });

  it("[CODE] refuses an empty file rather than reading zero bytes", () => {
    const result = validateImageMetadata({ name: "empty.png", type: "image/png", size: 0 });
    expect(result).toEqual({ ok: false, message: IMAGE_EMPTY_MESSAGE });
  });

  it("[CODE] allows an empty declared type, because the sniffer is the authority", () => {
    const result = validateImageMetadata({ name: "paste", type: "", size: 2048 });
    expect(result).toEqual({ ok: true, mime: null });
  });
});

describe("image magic bytes", () => {
  it("[CODE] sniffs PNG, JPEG and WebP from their bytes", () => {
    expect(sniffImageMime(PNG)).toBe("image/png");
    expect(sniffImageMime(JPEG)).toBe("image/jpeg");
    expect(sniffImageMime(WEBP)).toBe("image/webp");
  });

  it("[CODE] returns null for a file that is not one of the three formats", () => {
    expect(sniffImageMime(GIF)).toBeNull();
    expect(sniffImageMime(new Uint8Array([]))).toBeNull();
  });

  it("[CODE] refuses a renamed file whose bytes disagree with its declared type", () => {
    const result = validateImageBytes("image/png", JPEG);
    expect(result).toEqual({ ok: false, message: IMAGE_MAGIC_MISMATCH_MESSAGE });
  });

  it("[CODE] refuses bytes it cannot identify at all", () => {
    expect(validateImageBytes(null, GIF)).toEqual({
      ok: false,
      message: IMAGE_MAGIC_MISMATCH_MESSAGE,
    });
  });

  it("[CODE] accepts matching bytes and returns the sniffed type", () => {
    expect(validateImageBytes("image/png", PNG)).toEqual({ ok: true, mime: "image/png" });
    expect(validateImageBytes(null, WEBP)).toEqual({ ok: true, mime: "image/webp" });
  });
});

describe("image size copy", () => {
  it("[CODE] prints a size a reader can act on", () => {
    expect(formatImageSize(512)).toBe("512 B");
    expect(formatImageSize(62 * 1024)).toBe("62 KB");
    expect(formatImageSize(ASSISTANT_IMAGE_MAX_BYTES)).toBe("1.5 MB");
  });
});
