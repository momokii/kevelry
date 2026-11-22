// The answer renderer: the model's text in, React nodes out.
//
// This is the only place where model output becomes structure, and it is built
// around one rule: **nothing the model wrote is ever parsed as markup**. There is
// no `dangerouslySetInnerHTML` in this app, and this file never assembles an HTML
// string to inject — every character of the answer ends up as a React text child,
// which React escapes at the boundary, and the only attribute taken from model
// text is an `href` that `safeHref()` has already vetted.
//
// The subset is deliberately small, and ordered, so the same input always yields
// the same reading:
//
//   1. fenced code blocks (```), verbatim, never inline-parsed;
//   2. pipe tables (header row + dash separator row + body rows);
//   3. unordered and ordered lists;
//   4. `**bold**`, `*italic*`, `` `inline code` ``;
//   5. links — markdown `[label](target)` and bare `https://` URLs;
//   6. bare record ids in prose (`CVE-YYYY-NNNN`) as `/explore?q=` links, but
//      only ids the server cited this turn (see `AnswerRenderOptions`).
//
// Anything else is text, which is the safe default: an unsupported construct
// renders as the characters the model wrote, not as something decoded.
//
// Streaming is a first-class case. The renderer runs on partial text on every
// delta, so a table whose separator row has not arrived yet is *not* a table: it
// renders as its own lines until the `| --- |` row lands, at which point it
// becomes a table in one step. A partial row is padded to the header width so
// the table does not jump sideways as cells arrive.

import type { ReactNode } from "react";

/** The path a bare record id points at; the citation chips use the same one. */
export const CVE_SEARCH_PATH = "/explore?q=";

export interface AnswerRenderOptions {
  /**
   * The record ids the server's `citations` event named for this turn.
   *
   * Only these become links. The desk's whole claim is that the prose is grounded
   * in records the tools returned, so an id the tools did not return must never
   * gain an anchor that implies the dataset holds it — it stays a string, and the
   * unverified caution above the citations is what names it. Omitted or empty:
   * every id in prose stays text.
   */
  verifiedIds?: readonly string[];
}

/** A scheme-relative path is resolved against this origin and must stay on it. */
const INTERNAL_ORIGIN = "https://answer.invalid";

const CVE_ID = /^CVE-\d{4}-\d{4,7}(?![0-9A-Za-z_])/;
const CVE_CELL = /^CVE-\d{4}-\d{4,7}$/;
const FENCE_OPEN = /^ {0,3}(`{3,})[ \t]*([^`]*)$/;
const FENCE_CLOSE = /^ {0,3}`{3,}[ \t]*$/;
const BULLET = /^\s*[-*+]\s+(.*)$/;
const ORDERED = /^\s*(\d{1,9})[.)]\s+(.*)$/;
const CONTINUATION = /^\s{2,}\S/;
const INLINE_CODE = /^(`+)([\s\S]*?)\1(?!`)/;
const STRONG = /^\*\*([\s\S]+?)\*\*/;
const EMPHASIS = /^\*([^*\n]+?)\*/;
const BARE_URL = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^\s<>"'`]+/;
const SEPARATOR_CELL = /^:?-{1,}:?$/;

/** Deepest inline nesting `**_`x`_**`-style input can reach before it is text. */
const MAX_DEPTH = 6;

/**
 * The link policy, in one function.
 *
 * Allowed: `https:` URLs, and internal paths that start with `/` and stay on this
 * site. Everything else — `javascript:`, `data:`, `vbscript:`, plain `http:`,
 * other schemes, protocol-relative `//host`, scheme-less relative paths, and any
 * target carrying whitespace, a control character or a backslash (browsers read
 * `/\host` as `//host`) — returns `null`, and the caller renders the model's
 * characters as text instead of an anchor.
 */
export function safeHref(raw: string): string | null {
  const value = raw.trim();
  if (value === "") return null;
  // Whitespace, controls and backslashes have no place in a target we vouch for.
  if (/[\s\u0000-\u001f\u007f\\]/.test(value)) return null;
  // No scheme: only an absolute path on this site is acceptable.
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(value)) {
    if (!value.startsWith("/")) return null;
    if (value.startsWith("//")) return null;
    let resolved: URL;
    try {
      resolved = new URL(value, INTERNAL_ORIGIN);
    } catch {
      return null;
    }
    // `//host`, `/\host` and dot-segment tricks all leave this origin.
    if (resolved.origin !== INTERNAL_ORIGIN) return null;
    return `${resolved.pathname}${resolved.search}${resolved.hash}`;
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  if (url.protocol !== "https:") return null;
  if (url.hostname === "") return null;
  // A URL that carries credentials is never something the model should hand a
  // reader a clickable form of.
  if (url.username !== "" || url.password !== "") return null;
  return url.href;
}

interface InlineContext {
  /** `null` for an id the server never cited: it is text, not a link. */
  readonly cveHref: (id: string) => string | null;
  /** Off inside a link's own label, so an id is never a link inside a link. */
  readonly linkIds: boolean;
  readonly linkUrls: boolean;
}

/** Reads `[label](target)` at `start`, tolerating parentheses in the target. */
function readLink(text: string, start: number): { label: string; target: string } | null {
  let index = start + 1;
  let label = "";
  while (index < text.length && text[index] !== "]" && text[index] !== "\n") {
    label += text[index] ?? "";
    index += 1;
  }
  if (text[index] !== "]" || text[index + 1] !== "(") return null;
  index += 2;
  let target = "";
  let depth = 1;
  while (index < text.length && text[index] !== "\n") {
    const char = text[index] ?? "";
    if (char === "(") depth += 1;
    if (char === ")") {
      depth -= 1;
      if (depth === 0) {
        index += 1;
        break;
      }
    }
    target += char;
    index += 1;
  }
  // An unterminated link (the common mid-delta case) is not a link yet.
  if (depth !== 0) return null;
  return { label, target };
}

/** A bare URL never owns the sentence punctuation that follows it. */
function trimUrlTail(value: string): string {
  let trimmed = value.replace(/[.,;:!?'"]+$/, "");
  for (;;) {
    const opens = trimmed.split("(").length - 1;
    const closes = trimmed.split(")").length - 1;
    if (!trimmed.endsWith(")") || closes <= opens) break;
    trimmed = trimmed.slice(0, -1).replace(/[.,;:!?'"]+$/, "");
  }
  return trimmed;
}

/** An emphasis delimiter with whitespace inside it is arithmetic, not emphasis. */
function isTight(value: string): boolean {
  return value.trim() !== "" && !/^\s/.test(value) && !/\s$/.test(value);
}

function suppressLinks(context: InlineContext): InlineContext {
  return { ...context, linkIds: false, linkUrls: false };
}

/** One line of text, inline constructs only. Every leaf is a React text child. */
function renderInline(
  text: string,
  context: InlineContext,
  keyPrefix: string,
  depth = 0,
): ReactNode[] {
  const nodes: ReactNode[] = [];
  let buffer = "";
  let index = 0;
  let part = 0;

  const flush = (): void => {
    if (buffer === "") return;
    nodes.push(buffer);
    buffer = "";
  };
  const nextKey = (kind: string): string => {
    part += 1;
    return `${keyPrefix}-${kind}-${String(part)}`;
  };

  while (index < text.length) {
    const rest = text.slice(index);
    const char = text[index] ?? "";

    // 1. Inline code: verbatim, and nothing inside it is a construct.
    if (char === "`") {
      const code = INLINE_CODE.exec(rest);
      if (code !== null) {
        flush();
        nodes.push(<code key={nextKey("code")}>{code[2] ?? ""}</code>);
        index += code[0].length;
        continue;
      }
      buffer += char;
      index += 1;
      continue;
    }

    // 2. Markdown links. A rejected target keeps the model's own characters.
    if (char === "[") {
      const link = readLink(text, index);
      if (link !== null) {
        flush();
        const key = nextKey("link");
        const href = link.label.trim() === "" ? null : safeHref(link.target);
        if (href === null) {
          // Rejected target: the model's own characters, as text. No anchor is
          // created, so no browser can act on the scheme it proposed.
          nodes.push(text.slice(index, index + link.label.length + link.target.length + 4));
        } else {
          const external = !href.startsWith("/");
          nodes.push(
            <a
              key={key}
              href={href}
              rel={external ? "noopener noreferrer" : undefined}
              target={external ? "_blank" : undefined}
            >
              {renderInline(link.label, suppressLinks(context), key, depth + 1)}
            </a>,
          );
        }
        // `[label](target)` is 4 delimiter characters around the two halves.
        index += link.label.length + link.target.length + 4;
        continue;
      }
      buffer += char;
      index += 1;
      continue;
    }

    // 3. Strong, then emphasis. Both refuse to span a line break.
    if (char === "*" && depth < MAX_DEPTH) {
      const strong = text[index + 1] === "*" ? STRONG.exec(rest) : null;
      if (strong !== null && isTight(strong[1] ?? "")) {
        flush();
        nodes.push(
          <strong key={nextKey("strong")}>
            {renderInline(strong[1] ?? "", context, nextKey("strong-body"), depth + 1)}
          </strong>,
        );
        index += strong[0].length;
        continue;
      }
      const emphasis = EMPHASIS.exec(rest);
      if (emphasis !== null && isTight(emphasis[1] ?? "")) {
        flush();
        nodes.push(
          <em key={nextKey("em")}>
            {renderInline(emphasis[1] ?? "", context, nextKey("em-body"), depth + 1)}
          </em>,
        );
        index += emphasis[0].length;
        continue;
      }
    }

    // 4. A bare URL, linked only when the policy accepts it.
    if (char !== "<" && context.linkUrls) {
      const url = BARE_URL.exec(rest);
      if (url !== null) {
        flush();
        const raw = trimUrlTail(url[0]);
        const tail = url[0].slice(raw.length);
        const href = raw === "" ? null : safeHref(raw);
        if (href === null) {
          nodes.push(url[0]);
        } else {
          nodes.push(
            <a
              key={nextKey("url")}
              href={href}
              rel="noopener noreferrer"
              target="_blank"
              data-external="true"
            >
              {raw}
            </a>,
          );
          buffer = tail;
        }
        index += url[0].length;
        continue;
      }
    }

    // 5. A record id in prose becomes the same link the citation chips use —
    //    but only when the server cited that record this turn.
    if (char === "C" && context.linkIds) {
      const id = CVE_ID.exec(rest);
      const before = index === 0 ? "" : (text[index - 1] ?? "");
      if (id !== null && !/[A-Za-z0-9_]/.test(before)) {
        const href = context.cveHref(id[0]);
        if (href !== null) {
          flush();
          nodes.push(
            <a key={nextKey("cve")} href={href}>
              {id[0]}
            </a>,
          );
          index += id[0].length;
          continue;
        }
      }
    }

    buffer += char;
    index += 1;
  }

  flush();
  return nodes;
}

/** Splits a pipe row into cells; `\|` is a literal pipe, not a boundary. */
function splitRow(line: string): string[] {
  const cells: string[] = [];
  let current = "";
  for (let index = 0; index < line.length; index += 1) {
    const char = line[index] ?? "";
    if (char === "\\" && line[index + 1] === "|") {
      current += "|";
      index += 1;
      continue;
    }
    if (char === "|") {
      cells.push(current);
      current = "";
      continue;
    }
    current += char;
  }
  cells.push(current);
  if (cells.length > 1 && (cells[0] ?? "").trim() === "") cells.shift();
  if (cells.length > 1 && (cells[cells.length - 1] ?? "").trim() === "") cells.pop();
  return cells.map((cell) => cell.trim());
}

function isSeparatorRow(line: string): boolean {
  const cells = splitRow(line);
  return cells.length > 0 && cells.every((cell) => SEPARATOR_CELL.test(cell));
}

function isTableStart(lines: readonly string[], index: number): boolean {
  const head = lines[index] ?? "";
  const separator = lines[index + 1] ?? "";
  return head.includes("|") && separator.includes("|") && isSeparatorRow(separator);
}

function isListItem(line: string, ordered: boolean): string | null {
  const match = ordered ? ORDERED.exec(line) : BULLET.exec(line);
  if (match === null) return null;
  return (ordered ? match[2] : match[1]) ?? "";
}

function startsBlock(lines: readonly string[], index: number): boolean {
  const line = lines[index] ?? "";
  if (FENCE_OPEN.test(line)) return true;
  if (isListItem(line, false) !== null || isListItem(line, true) !== null) return true;
  return isTableStart(lines, index);
}

function renderLines(
  lines: readonly string[],
  context: InlineContext,
  keyPrefix: string,
): ReactNode[] {
  const nodes: ReactNode[] = [];
  lines.forEach((line, position) => {
    if (position > 0) nodes.push(<br key={`${keyPrefix}-br-${String(position)}`} />);
    nodes.push(...renderInline(line, context, `${keyPrefix}-${String(position)}`));
  });
  return nodes;
}

function AnswerTable({
  head,
  rows,
  context,
  keyPrefix,
}: {
  head: readonly string[];
  rows: readonly (readonly string[])[];
  context: InlineContext;
  keyPrefix: string;
}): ReactNode {
  const width = head.length;
  return (
    // `table-wrap` is the app's existing horizontal-scroll container, and the
    // scroll region is focusable so it can be read with a keyboard.
    <div
      className="table-wrap"
      role="region"
      aria-label="Answer table"
      tabIndex={0}
      data-testid="assistant-table"
    >
      <table className="data-table assistant-table">
        <thead>
          <tr>
            {head.map((cell, column) => (
              <th key={`${keyPrefix}-h${String(column)}`} scope="col">
                {renderInline(cell, context, `${keyPrefix}-h${String(column)}`)}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, rowIndex) => {
            const cells =
              row.length < width ? [...row, ...Array<string>(width - row.length).fill("")] : row;
            return (
              <tr key={`${keyPrefix}-r${String(rowIndex)}`}>
                {cells.map((cell, column) => (
                  <td
                    key={`${keyPrefix}-r${String(rowIndex)}c${String(column)}`}
                    className={CVE_CELL.test(cell.trim()) ? "cell-id" : undefined}
                  >
                    {renderInline(
                      cell,
                      context,
                      `${keyPrefix}-r${String(rowIndex)}c${String(column)}`,
                    )}
                  </td>
                ))}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function renderTable(
  lines: readonly string[],
  start: number,
  context: InlineContext,
  key: string,
): { node: ReactNode; next: number } {
  const head = splitRow(lines[start] ?? "");
  let index = start + 2;
  const rows: string[][] = [];
  while (index < lines.length) {
    const row = lines[index] ?? "";
    if (row.trim() === "" || !row.includes("|") || isSeparatorRow(row)) break;
    rows.push(splitRow(row));
    index += 1;
  }
  return {
    node: <AnswerTable head={head} rows={rows} context={context} key={key} keyPrefix={key} />,
    next: index,
  };
}

function renderList(
  lines: readonly string[],
  start: number,
  context: InlineContext,
  ordered: boolean,
  key: string,
): { node: ReactNode; next: number } {
  const items: string[] = [];
  let index = start;
  while (index < lines.length) {
    const line = lines[index] ?? "";
    const item = isListItem(line, ordered);
    if (item !== null) {
      items.push(item);
      index += 1;
      continue;
    }
    // A continuation line belongs to the item above it while it is indented and
    // does not open a block of its own.
    if (items.length > 0 && CONTINUATION.test(line) && !startsBlock(lines, index)) {
      items[items.length - 1] = `${items[items.length - 1] ?? ""} ${line.trim()}`;
      index += 1;
      continue;
    }
    break;
  }
  const rendered = items.map((item, position) => (
    <li key={`${key}-i${String(position)}`}>
      {renderInline(item, context, `${key}-i${String(position)}`)}
    </li>
  ));
  if (ordered) {
    const first = Number(ORDERED.exec(lines[start] ?? "")?.[1] ?? "1");
    const startAt = Number.isFinite(first) && first > 1 ? first : undefined;
    return {
      node: (
        <ol key={key} start={startAt}>
          {rendered}
        </ol>
      ),
      next: index,
    };
  }
  return { node: <ul key={key}>{rendered}</ul>, next: index };
}

function renderBlocks(text: string, context: InlineContext): ReactNode[] {
  const lines = text.replace(/\r\n?/g, "\n").split("\n");
  const blocks: ReactNode[] = [];
  let index = 0;
  let block = 0;
  const nextKey = (kind: string): string => {
    block += 1;
    return `${kind}-${String(block)}`;
  };

  while (index < lines.length) {
    const line = lines[index] ?? "";
    if (line.trim() === "") {
      index += 1;
      continue;
    }

    // Fenced code: verbatim, and an unterminated fence is still code (the model
    // is mid-block, and showing the block is truer than showing the backticks).
    if (FENCE_OPEN.test(line)) {
      index += 1;
      const code: string[] = [];
      while (index < lines.length && !FENCE_CLOSE.test(lines[index] ?? "")) {
        code.push(lines[index] ?? "");
        index += 1;
      }
      if (index < lines.length) index += 1;
      blocks.push(
        <pre className="assistant-code" key={nextKey("code")}>
          <code>{code.join("\n")}</code>
        </pre>,
      );
      continue;
    }

    // A table needs its separator row. Header-only text stays text, so a delta
    // that has not finished the table cannot flash a broken grid.
    if (isTableStart(lines, index)) {
      const table = renderTable(lines, index, context, nextKey("table"));
      blocks.push(table.node);
      index = table.next;
      continue;
    }

    if (isListItem(line, false) !== null || isListItem(line, true) !== null) {
      const list = renderList(
        lines,
        index,
        context,
        isListItem(line, true) !== null,
        nextKey("list"),
      );
      blocks.push(list.node);
      index = list.next;
      continue;
    }

    const paragraph: string[] = [];
    while (index < lines.length) {
      const row = lines[index] ?? "";
      if (row.trim() === "") break;
      if (paragraph.length > 0 && startsBlock(lines, index)) break;
      paragraph.push(row);
      index += 1;
    }
    const key = nextKey("p");
    blocks.push(<p key={key}>{renderLines(paragraph, context, key)}</p>);
  }

  return blocks;
}

/**
 * Renders one model answer. Pure: the same text always yields the same nodes, and
 * no output depends on the document, the network or the clock.
 */
export function renderAnswer(text: string, options: AnswerRenderOptions = {}): ReactNode {
  const verified = new Set(options.verifiedIds ?? []);
  const context: InlineContext = {
    cveHref: (id: string) =>
      verified.has(id) ? `${CVE_SEARCH_PATH}${encodeURIComponent(id)}` : null,
    linkIds: true,
    linkUrls: true,
  };
  return <>{renderBlocks(text, context)}</>;
}

/** The inline pass alone, exported for the tests that pin the link policy. */
export function renderAnswerInline(text: string, verifiedIds: readonly string[] = []): ReactNode {
  const verified = new Set(verifiedIds);
  return (
    <>
      {renderInline(
        text,
        {
          cveHref: (id: string) =>
            verified.has(id) ? `${CVE_SEARCH_PATH}${encodeURIComponent(id)}` : null,
          linkIds: true,
          linkUrls: true,
        },
        "inline",
      )}
    </>
  );
}
