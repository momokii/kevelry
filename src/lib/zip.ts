// Dependency-free single-entry ZIP reader for MITRE taxonomy packs (v3 E3 step 2a).
//
// The project rule is no new production dependency, and the upstream shape is
// narrow: MITRE publishes each CWE view as `CSV.zip` containing exactly one
// CSV. So this module implements only that subset of APPNOTE.TXT: locate the
// End of Central Directory record, read the single central-directory entry to
// learn the authoritative sizes, then read the one local file header and its
// data. Stored (method 0) and deflate (method 8) are supported; deflate is
// inflated with `node:zlib`'s `inflateRawSync`.
//
// Every rejection is a `ZipExtractError` with a stable `code`, never a raw
// Node error: not a zip, zero or several entries, encrypted flag, unsupported
// method, multi-disk or ZIP64 framing, a declared uncompressed size above the
// caller's cap, or inflated output above that cap (zip-bomb guard — the cap is
// also handed to zlib as `maxOutputLength`, so a hostile stream is stopped
// before it allocates past the cap). The local header is not trusted for
// sizes: a streaming writer leaves zeros there, and a lying local size must
// not defeat the cap, so sizes always come from the central directory.
//
// CRC-32 is not verified: the caller's CSV parser rejects malformed content,
// and a checksum failure is not a reason to reject an otherwise readable pack.

import { inflateRawSync } from "node:zlib";

export type ZipErrorCode =
  | "invalid-input"
  | "invalid-cap"
  | "not-zip"
  | "entry-count"
  | "multi-disk"
  | "zip64"
  | "encrypted"
  | "unsupported-method"
  | "declared-size"
  | "inflated-size"
  | "corrupt";

export class ZipExtractError extends Error {
  readonly name = "ZipExtractError";
  readonly code: ZipErrorCode;

  constructor(code: ZipErrorCode, message: string) {
    super(message);
    this.code = code;
  }
}

export interface ZipExtractOptions {
  /** Hard cap on the entry's uncompressed bytes, enforced twice (declared + actual). */
  maxUncompressedBytes: number;
}

export interface ZipExtractResult {
  name: string;
  data: Buffer;
}

const SIG_EOCD = 0x06054b50;
const SIG_CENTRAL = 0x02014b50;
const SIG_LOCAL = 0x04034b50;

const EOCD_MIN_BYTES = 22;
// 22-byte record plus the maximum 0xffff-byte trailing comment.
const EOCD_MAX_BYTES = EOCD_MIN_BYTES + 0xffff;
const CENTRAL_MIN_BYTES = 46;
const LOCAL_MIN_BYTES = 30;

const METHOD_STORED = 0;
const METHOD_DEFLATE = 8;
const FLAG_ENCRYPTED = 1 << 0;

function fail(code: ZipErrorCode, message: string): never {
  throw new ZipExtractError(code, message);
}

function need(buffer: Buffer, offset: number, length: number, what: string): void {
  if (offset < 0 || length < 0 || offset + length > buffer.length) {
    fail(
      "not-zip",
      `truncated zip: ${what} needs ${length} byte(s) at offset ${offset}, but the archive is ${buffer.length} byte(s)`,
    );
  }
}

function u16(buffer: Buffer, offset: number, what: string): number {
  need(buffer, offset, 2, what);
  return buffer.readUInt16LE(offset);
}

function u32(buffer: Buffer, offset: number, what: string): number {
  need(buffer, offset, 4, what);
  return buffer.readUInt32LE(offset);
}

/**
 * Locate the End of Central Directory record. The record sits at the end of
 * the archive minus its trailing comment, and its signature can occur inside
 * compressed data, so a candidate only counts when its declared comment
 * length lands exactly on the end of the buffer.
 */
function findEocd(buffer: Buffer): number {
  if (buffer.length < EOCD_MIN_BYTES) {
    fail(
      "not-zip",
      `not a zip archive: ${buffer.length} byte(s) is shorter than the ${EOCD_MIN_BYTES}-byte end of central directory record`,
    );
  }
  const searchStart = Math.max(0, buffer.length - EOCD_MAX_BYTES);
  for (let offset = buffer.length - EOCD_MIN_BYTES; offset >= searchStart; offset -= 1) {
    if (buffer.readUInt32LE(offset) !== SIG_EOCD) continue;
    const commentLength = buffer.readUInt16LE(offset + 20);
    if (offset + EOCD_MIN_BYTES + commentLength === buffer.length) return offset;
  }
  fail("not-zip", "not a zip archive: no end of central directory record found");
}

/**
 * Extract the only entry of a single-entry zip archive.
 *
 * The options cap is required rather than defaulted: the caller owns the
 * acquisition budget, and a missing or non-positive cap is a programming
 * error, not a silently unbounded read.
 */
export function extractSingleEntryZip(
  buffer: Buffer,
  options: ZipExtractOptions,
): ZipExtractResult {
  if (!Buffer.isBuffer(buffer)) {
    fail("invalid-input", "zip input must be a Buffer");
  }
  const cap = options?.maxUncompressedBytes;
  if (typeof cap !== "number" || !Number.isSafeInteger(cap) || cap <= 0) {
    fail("invalid-cap", `maxUncompressedBytes must be a positive safe integer, got ${String(cap)}`);
  }

  const eocd = findEocd(buffer);
  const diskNumber = u16(buffer, eocd + 4, "end of central directory disk number");
  const centralDisk = u16(buffer, eocd + 6, "end of central directory central-directory disk");
  const entriesThisDisk = u16(buffer, eocd + 8, "end of central directory entry count");
  const totalEntries = u16(buffer, eocd + 10, "end of central directory total entries");
  const centralSize = u32(buffer, eocd + 12, "end of central directory size");
  const centralOffset = u32(buffer, eocd + 16, "end of central directory offset");

  if (diskNumber !== 0 || centralDisk !== 0 || entriesThisDisk !== totalEntries) {
    fail(
      "multi-disk",
      `multi-disk zip archives are not supported (disk ${diskNumber}, central directory disk ${centralDisk})`,
    );
  }
  if (totalEntries === 0xffff && centralOffset === 0xffffffff) {
    fail("zip64", "ZIP64 archives are not supported: the central directory uses ZIP64 framing");
  }
  if (totalEntries === 0) {
    fail("entry-count", "zip archive contains no entries; exactly one entry is required");
  }
  if (totalEntries > 1) {
    fail(
      "entry-count",
      `zip archive contains ${totalEntries} entries; exactly one entry is required`,
    );
  }
  if (centralOffset + centralSize > buffer.length) {
    fail(
      "not-zip",
      `central directory declares ${centralSize} byte(s) at offset ${centralOffset}, past the end of the ${buffer.length}-byte archive`,
    );
  }

  const signature = u32(buffer, centralOffset, "central directory signature");
  if (signature !== SIG_CENTRAL) {
    fail(
      "not-zip",
      `not a zip archive: expected a central directory record at offset ${centralOffset}, found signature 0x${signature.toString(16)}`,
    );
  }

  const flags = u16(buffer, centralOffset + 8, "central directory flags");
  const method = u16(buffer, centralOffset + 10, "central directory compression method");
  const compressedSize = u32(buffer, centralOffset + 20, "central directory compressed size");
  const uncompressedSize = u32(buffer, centralOffset + 24, "central directory uncompressed size");
  const nameLength = u16(buffer, centralOffset + 28, "central directory name length");
  const extraLength = u16(buffer, centralOffset + 30, "central directory extra length");
  const commentLength = u16(buffer, centralOffset + 32, "central directory comment length");
  const localOffset = u32(buffer, centralOffset + 42, "central directory local header offset");
  if (CENTRAL_MIN_BYTES + nameLength + extraLength + commentLength > centralSize) {
    fail(
      "corrupt",
      `central directory record declares ${nameLength}+${extraLength}+${commentLength} name/extra/comment bytes, more than the ${centralSize}-byte directory`,
    );
  }

  if ((flags & FLAG_ENCRYPTED) !== 0) {
    fail(
      "encrypted",
      "zip entry is encrypted (general purpose flag bit 0); decryption is not supported",
    );
  }
  if (method !== METHOD_STORED && method !== METHOD_DEFLATE) {
    fail(
      "unsupported-method",
      `unsupported compression method ${method}; only stored (0) and deflate (8) are supported`,
    );
  }
  if (uncompressedSize > cap) {
    fail(
      "declared-size",
      `declared uncompressed size ${uncompressedSize} byte(s) exceeds the ${cap}-byte cap`,
    );
  }

  const name = buffer.toString(
    "utf8",
    centralOffset + CENTRAL_MIN_BYTES,
    centralOffset + CENTRAL_MIN_BYTES + nameLength,
  );
  if (name.trim() === "") {
    fail("corrupt", "zip entry has an empty name");
  }

  const localSignature = u32(buffer, localOffset, "local file header signature");
  if (localSignature !== SIG_LOCAL) {
    fail(
      "not-zip",
      `not a zip archive: expected a local file header at offset ${localOffset}, found signature 0x${localSignature.toString(16)}`,
    );
  }
  const localFlags = u16(buffer, localOffset + 6, "local file header flags");
  const localMethod = u16(buffer, localOffset + 8, "local file header compression method");
  const localNameLength = u16(buffer, localOffset + 26, "local file header name length");
  const localExtraLength = u16(buffer, localOffset + 28, "local file header extra length");
  if ((localFlags & FLAG_ENCRYPTED) !== 0) {
    fail("encrypted", "zip entry is encrypted (local header general purpose flag bit 0)");
  }
  if (localMethod !== method) {
    fail(
      "corrupt",
      `compression method mismatch: central directory says ${method}, local header says ${localMethod}`,
    );
  }

  const dataStart = localOffset + LOCAL_MIN_BYTES + localNameLength + localExtraLength;
  if (dataStart + compressedSize > buffer.length) {
    fail(
      "not-zip",
      `truncated zip: entry data needs ${compressedSize} byte(s) at offset ${dataStart}, but the archive is ${buffer.length} byte(s)`,
    );
  }
  const compressed = buffer.subarray(dataStart, dataStart + compressedSize);

  if (method === METHOD_STORED) {
    if (compressedSize !== uncompressedSize) {
      fail(
        "corrupt",
        `stored entry declares ${uncompressedSize} uncompressed byte(s) but carries ${compressedSize}`,
      );
    }
    if (compressed.length > cap) {
      fail(
        "inflated-size",
        `stored entry data is ${compressed.length} byte(s), exceeding the ${cap}-byte cap`,
      );
    }
    return { name, data: compressed };
  }

  let data: Buffer;
  try {
    // `maxOutputLength` makes zlib abort as soon as the stream would pass the
    // cap, so a small deflate stream that expands to gigabytes never allocates.
    data = inflateRawSync(compressed, { maxOutputLength: cap });
  } catch (error) {
    const nodeCode = (error as { code?: unknown }).code;
    if (nodeCode === "ERR_BUFFER_TOO_LARGE") {
      fail("inflated-size", `inflated output exceeds the ${cap}-byte cap`);
    }
    const detail = error instanceof Error ? error.message : String(error);
    fail("corrupt", `deflate stream could not be inflated: ${detail}`);
  }
  if (data.length > cap) {
    fail(
      "inflated-size",
      `inflated output is ${data.length} byte(s), exceeding the ${cap}-byte cap`,
    );
  }
  return { name, data };
}
