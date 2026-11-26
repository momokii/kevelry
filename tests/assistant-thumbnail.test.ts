// The turn's record of an attached screenshot: one downscale, made locally.
//
// The bug this file pins down is a policy one, not a pixel one. The page ships
// `connect-src 'self'`, so the old `fetch(dataUrl)` was refused by the browser,
// the catch swallowed it, and every attach logged two CSP errors while the record
// silently kept the full payload. The assertion that matters is therefore the
// negative one: the decode path never calls `fetch`.
//
// @vitest-environment jsdom

import { afterEach, describe, expect, it, vi } from "vitest";

import {
  ASSISTANT_THUMBNAIL_WIDTH,
  toThumbnail,
} from "../src/components/assistant/assistant-image";

/** A real PNG signature plus padding: enough bytes to decode, not a valid image. */
const SOURCE = `data:image/png;base64,${btoa("\x89PNG\r\n\x1a\n" + "x".repeat(24))}`;

interface Bitmap {
  width: number;
  height: number;
  close: () => void;
}

/** `createImageBitmap` and the 2d canvas, stubbed: jsdom has neither. */
function stubDecoder(bitmap: Bitmap, painted: number[][]): () => void {
  const createBitmap = vi.fn(async () => bitmap);
  vi.stubGlobal("createImageBitmap", createBitmap);
  const getContext = vi
    .spyOn(HTMLCanvasElement.prototype, "getContext")
    .mockImplementation(function (this: HTMLCanvasElement) {
      painted.push([this.width, this.height]);
      return { drawImage: () => undefined } as unknown as CanvasRenderingContext2D;
    } as never);
  const toDataURL = vi
    .spyOn(HTMLCanvasElement.prototype, "toDataURL")
    .mockReturnValue("data:image/webp;base64,dGh1bWI=");
  return () => {
    getContext.mockRestore();
    toDataURL.mockRestore();
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("the turn's thumbnail", () => {
  it("downscales the picture without fetching its data URL", async () => {
    const fetchSpy = vi.fn(() => Promise.reject(new Error("the page cannot connect to data:")));
    vi.stubGlobal("fetch", fetchSpy);
    const bitmap: Bitmap = { width: 960, height: 480, close: vi.fn() };
    const painted: number[][] = [];
    const restore = stubDecoder(bitmap, painted);

    const thumb = await toThumbnail(SOURCE);

    expect(thumb).toBe("data:image/webp;base64,dGh1bWI=");
    // The whole fix, in one assertion: nothing goes over the network, so the
    // document's `connect-src 'self'` has nothing to refuse.
    expect(fetchSpy).not.toHaveBeenCalled();
    // Half the width, same aspect: 960 → 480, and the 480 cap is the constant.
    expect(painted).toEqual([[ASSISTANT_THUMBNAIL_WIDTH, ASSISTANT_THUMBNAIL_WIDTH / 2]]);
    expect(bitmap.close).toHaveBeenCalledTimes(1);
    restore();
  });

  it("leaves a picture under the cap at its own size", async () => {
    const bitmap: Bitmap = { width: 320, height: 200, close: vi.fn() };
    const painted: number[][] = [];
    const restore = stubDecoder(bitmap, painted);

    await toThumbnail(SOURCE);

    expect(painted).toEqual([[320, 200]]);
    restore();
  });

  it("keeps the source rather than guessing when the URL cannot be decoded", async () => {
    vi.stubGlobal("createImageBitmap", vi.fn());
    const percentEncoded = "data:image/svg+xml,%3Csvg%20width%3D%22480%22/%3E";
    expect(await toThumbnail(percentEncoded)).toBe(percentEncoded);
    const corrupted = "data:image/png;base64,not_base64_at_all!!";
    expect(await toThumbnail(corrupted)).toBe(corrupted);
    // Not a data URL at all: nothing to downscale, so nothing is invented.
    expect(await toThumbnail("https://example.test/shot.png")).toBe(
      "https://example.test/shot.png",
    );
  });
});
