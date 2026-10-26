// Browsable API docs data layer (task 45). Reads openapi/v1.yaml at build
// time with a small line-based parser — no YAML dependency — so the rendered
// endpoint list cannot drift from the spec. Values quoted below for rate
// limits, errors, and deprecation are copied from docs/api/README.md; the
// unit test pins the key phrases against that file.

export interface ApiParam {
  name: string;
  location: string;
  required: boolean;
  description: string;
  type: string;
}

export interface ApiResponse {
  status: string;
  description: string;
  schema: string;
}

export interface ApiEndpoint {
  method: string;
  path: string;
  operationId: string;
  summary: string;
  description: string;
  params: ApiParam[];
  responses: ApiResponse[];
}

export interface ApiSpecMeta {
  title: string;
  version: string;
  description: string;
  serverUrl: string;
}

function indentOf(line: string): number {
  const match = line.match(/^ */);
  return match === null ? 0 : match[0].length;
}

/** Collect a `description: |` block scalar starting at lines[i]. */
function readBlockScalar(lines: string[], i: number): { text: string; next: number } {
  const base = indentOf(lines[i] ?? "");
  const collected: string[] = [];
  let j = i + 1;
  while (j < lines.length) {
    const line = lines[j] as string;
    if (line.trim() === "") {
      collected.push("");
      j += 1;
      continue;
    }
    if (indentOf(line) <= base) break;
    collected.push(line.slice(base + 2));
    j += 1;
  }
  while (collected.length > 0 && collected[collected.length - 1] === "") collected.pop();
  return { text: collected.join("\n").replace(/\n+/g, " ").trim(), next: j };
}

/** Parse one parameter block (shared params or inline `- name:` items). */
function parseParamBlock(lines: string[]): Omit<ApiParam, "name"> & { name: string } {
  let name = "";
  let location = "query";
  let required = false;
  let description = "";
  let type = "";
  let format = "";
  let enumValues: string[] = [];
  let schemaRef = "";
  const first = (lines[0] ?? "").trim().replace(/^-\s*/, "");
  const nameMatch = first.match(/^name:\s*(.+)$/);
  if (nameMatch?.[1]) name = nameMatch[1].trim();
  for (let i = 0; i < lines.length; i += 1) {
    const line = (lines[i] ?? "").trim();
    const nameLine = line.match(/^-\s*name:\s*(.+)$/) ?? line.match(/^name:\s*(.+)$/);
    if (nameLine?.[1] && name === "") name = nameLine[1].trim();
    const inMatch = line.match(/^in:\s*(.+)$/);
    if (inMatch?.[1]) location = inMatch[1].trim();
    const reqMatch = line.match(/^required:\s*(.+)$/);
    if (reqMatch?.[1]) required = reqMatch[1].trim() === "true";
    const descMatch = line.match(/^description:\s*(.*)$/);
    if (descMatch && indentOf(lines[i] ?? "") <= 12) {
      if ((descMatch[1] ?? "").trim() === "|" || (descMatch[1] ?? "").trim() === "|-") {
        description = readBlockScalar(lines, i).text;
      } else if ((descMatch[1] ?? "").trim() !== "") {
        description = (descMatch[1] ?? "").trim();
      }
    }
    const typeMatch = line.match(/^type:\s*(.+)$/);
    if (typeMatch?.[1] && type === "") type = typeMatch[1].trim();
    const formatMatch = line.match(/^format:\s*(.+)$/);
    if (formatMatch?.[1]) format = formatMatch[1].trim();
    if (/^enum:\s*$/.test(line)) {
      enumValues = [];
      for (let j = i + 1; j < lines.length; j += 1) {
        const enumLine = (lines[j] ?? "").trim();
        if (!enumLine.startsWith("- ")) break;
        enumValues.push(enumLine.slice(2).trim());
      }
    }
    const refMatch = line.match(/^\$ref:\s*'#\/components\/schemas\/(\w+)'\s*$/);
    if (refMatch?.[1] && /^schema:\s*$/.test((lines[i - 1] ?? "").trim())) {
      schemaRef = refMatch[1];
    }
  }
  void schemaRef;
  return { name, location, required, description, type, format, enumValues } as unknown as Omit<
    ApiParam,
    "name"
  > & { name: string };
}

interface RawParam {
  name: string;
  location: string;
  required: boolean;
  description: string;
  type: string;
}

/** Split an indented mapping into per-key line groups. */
function splitMapping(lines: string[], keyIndent: number): { key: string; block: string[] }[] {
  const groups: { key: string; block: string[] }[] = [];
  let current: { key: string; block: string[] } | null = null;
  for (const line of lines) {
    if (line.trim() === "") {
      current?.block.push(line);
      continue;
    }
    if (indentOf(line) === keyIndent) {
      const keyMatch = line.trim().match(/^-?\s*['"]?([^'":]+)['"]?:\s*(.*)$/);
      if (current !== null) groups.push(current);
      current = { key: keyMatch?.[1]?.trim() ?? line.trim(), block: [line] };
    } else if (current !== null) {
      current.block.push(line);
    }
  }
  if (current !== null) groups.push(current);
  return groups;
}

function finishParam(
  raw: ReturnType<typeof parseParamBlock>,
  schemaEnums: Map<string, string[]>,
): ApiParam {
  const parsed = raw as unknown as {
    name: string;
    location: string;
    required: boolean;
    description: string;
    type: string;
    format: string;
    enumValues: string[];
    schemaRefName?: string;
  };
  let type = parsed.type;
  if (parsed.enumValues.length > 0) {
    type =
      type === "" ? parsed.enumValues.join(" | ") : `${type}: ${parsed.enumValues.join(" | ")}`;
  }
  if (parsed.format !== "" && !type.includes(parsed.format)) {
    type = type === "" ? parsed.format : `${type} (${parsed.format})`;
  }
  return {
    name: parsed.name,
    location: parsed.location,
    required: parsed.required,
    description: parsed.description,
    type: type === "" ? "—" : type,
  };
}

/** Pull the schema $ref name referenced inside a schema block, if any. */
function findSchemaRef(block: string[]): string {
  for (let i = 0; i < block.length; i += 1) {
    const line = (block[i] ?? "").trim();
    if (/^schema:\s*$/.test(line)) {
      for (let j = i + 1; j < Math.min(block.length, i + 4); j += 1) {
        const refMatch = (block[j] ?? "").trim().match(/^\$ref:\s*'#\/components\/schemas\/(\w+)'/);
        if (refMatch?.[1]) return refMatch[1];
      }
    }
  }
  return "";
}

/** Parse the operations under `paths:` plus shared params and schema enums. */
export function parseSpec(text: string): { meta: ApiSpecMeta; endpoints: ApiEndpoint[] } {
  const lines = text.split("\n");
  let title = "Public API";
  let version = "v1";
  let infoDescription = "";
  let serverUrl = "";
  for (let i = 0; i < lines.length; i += 1) {
    const line = (lines[i] ?? "").trim();
    if (serverUrl === "") {
      const serverMatch = line.match(/^- url:\s*(\S+)/);
      if (serverMatch?.[1]) serverUrl = serverMatch[1];
    }
    if (line.startsWith("title:") && title === "Public API") {
      title = line.slice("title:".length).trim();
    }
    if (/^version:\s*/.test(line)) version = line.replace(/^version:\s*/, "").trim();
    if (/^description:\s*\|/.test(line) && infoDescription === "") {
      infoDescription = readBlockScalar(lines, i).text;
    }
    if (/^paths:\s*$/.test(line)) break;
  }

  // Slice the top-level sections.
  const pathsStart = lines.findIndex((line) => /^paths:\s*$/.test(line));
  const componentsStart = lines.findIndex((line) => /^components:\s*$/.test(line));
  const pathLines =
    pathsStart === -1
      ? []
      : lines.slice(pathsStart + 1, componentsStart === -1 ? undefined : componentsStart);
  const componentLines = componentsStart === -1 ? [] : lines.slice(componentsStart + 1);

  // Shared parameters: `  parameters:` ... up to `  headers:`.
  const sharedParams = new Map<
    string,
    RawParam & { enumValues: string[]; schemaRefName: string }
  >();
  const paramsIdx = componentLines.findIndex((line) => /^  parameters:\s*$/.test(line));
  const headersIdx = componentLines.findIndex((line) => /^  headers:\s*$/.test(line));
  if (paramsIdx !== -1) {
    const block = componentLines.slice(paramsIdx + 1, headersIdx === -1 ? undefined : headersIdx);
    for (const group of splitMapping(block, 4)) {
      const parsed = parseParamBlock(
        group.block.map((line) => line.replace(/^    /, "")),
      ) as unknown as RawParam & {
        enumValues: string[];
        schemaRefName?: string;
      };
      sharedParams.set(group.key, {
        name: parsed.name,
        location: parsed.location,
        required: parsed.required,
        description: parsed.description,
        type: (parsed as unknown as { type: string }).type,
        enumValues: parsed.enumValues,
        schemaRefName: findSchemaRef(group.block),
      });
    }
  }

  // Schema enums for $ref'd param schemas (PriorityListName, RadarKind).
  const schemaEnums = new Map<string, string[]>();
  const schemasIdx = componentLines.findIndex((line) => /^  schemas:\s*$/.test(line));
  if (schemasIdx !== -1) {
    const block = componentLines.slice(schemasIdx + 1);
    const endIdx = block.findIndex(
      (line) =>
        /^  [a-z]+:\s*$/.test(line) &&
        !/^  schemas:/.test(line) &&
        indentOf(line) === 2 &&
        !line.startsWith("   "),
    );
    const schemaBlock = endIdx === -1 ? block : block.slice(0, endIdx);
    for (const group of splitMapping(schemaBlock, 4)) {
      const enumValues: string[] = [];
      for (let i = 0; i < group.block.length; i += 1) {
        if ((group.block[i] ?? "").trim() === "enum:") {
          for (let j = i + 1; j < group.block.length; j += 1) {
            const enumLine = (group.block[j] ?? "").trim();
            if (!enumLine.startsWith("- ")) break;
            enumValues.push(enumLine.slice(2).trim());
          }
        }
      }
      if (enumValues.length > 0) schemaEnums.set(group.key, enumValues);
    }
  }

  const resolveParam = (
    raw: RawParam & { enumValues?: string[]; schemaRefName?: string },
  ): ApiParam => {
    let type = raw.type;
    const enumValues = raw.enumValues ?? [];
    if (enumValues.length > 0) {
      type = type === "" ? enumValues.join(" | ") : `${type}: ${enumValues.join(" | ")}`;
    } else if (raw.schemaRefName) {
      const resolved = schemaEnums.get(raw.schemaRefName);
      if (resolved) type = resolved.join(" | ");
      else if (type === "") type = raw.schemaRefName;
    }
    return {
      name: raw.name,
      location: raw.location,
      required: raw.required,
      description: raw.description,
      type: type === "" ? "—" : type,
    };
  };

  // Operations: `  /path:` groups, `    method:` subgroups.
  const endpoints: ApiEndpoint[] = [];
  for (const pathGroup of splitMapping(pathLines, 2)) {
    const path = pathGroup.key;
    for (const methodGroup of splitMapping(pathGroup.block.slice(1), 4)) {
      const method = methodGroup.key.toUpperCase();
      if (!["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE"].includes(method))
        continue;
      const opLines = methodGroup.block;
      let operationId = "";
      let summary = "";
      let description = "";
      for (let i = 0; i < opLines.length; i += 1) {
        const line = (opLines[i] ?? "").trim();
        const opMatch = line.match(/^operationId:\s*(.+)$/);
        if (opMatch?.[1] && indentOf(opLines[i] ?? "") === 6) operationId = opMatch[1].trim();
        const sumMatch = line.match(/^summary:\s*(.+)$/);
        if (sumMatch?.[1] && indentOf(opLines[i] ?? "") === 6) summary = sumMatch[1].trim();
        if (/^description:\s*\|/.test(line) && indentOf(opLines[i] ?? "") === 6) {
          description = readBlockScalar(opLines, i).text;
        }
      }
      // Parameters: `      parameters:` list items at indent 8.
      const params: ApiParam[] = [];
      const paramsIdx = opLines.findIndex((line) => /^      parameters:\s*$/.test(line));
      if (paramsIdx !== -1) {
        const paramRegion: string[] = [];
        for (let i = paramsIdx + 1; i < opLines.length; i += 1) {
          const line = opLines[i] as string;
          if (line.trim() !== "" && indentOf(line) <= 6) break;
          paramRegion.push(line);
        }
        for (const item of splitMapping(
          paramRegion.filter((line) => line.trim() !== ""),
          8,
        )) {
          const refMatch = item.block
            .map((line) => line.trim())
            .join(" ")
            .match(/#\/components\/parameters\/(\w+)/);
          if (refMatch?.[1]) {
            const shared = sharedParams.get(refMatch[1]);
            if (shared) params.push(resolveParam(shared));
          } else {
            const parsed = parseParamBlock(item.block) as unknown as RawParam & {
              enumValues: string[];
            };
            params.push(
              resolveParam({
                ...parsed,
                schemaRefName: findSchemaRef(item.block),
              }),
            );
          }
        }
      }
      // Responses: `      responses:` entries at indent 8.
      const responses: ApiResponse[] = [];
      const respIdx = opLines.findIndex((line) => /^      responses:\s*$/.test(line));
      if (respIdx !== -1) {
        const respRegion: string[] = [];
        for (let i = respIdx + 1; i < opLines.length; i += 1) {
          const line = opLines[i] as string;
          if (line.trim() !== "" && indentOf(line) <= 6) break;
          respRegion.push(line);
        }
        for (const item of splitMapping(
          respRegion.filter((line) => line.trim() !== ""),
          8,
        )) {
          const status = item.key.replace(/['"]/g, "");
          let respDescription = "";
          for (const line of item.block) {
            const descMatch = line.trim().match(/^description:\s*(.+)$/);
            if (descMatch?.[1] && indentOf(line) === 10) {
              respDescription = descMatch[1].trim();
              break;
            }
          }
          const refMatch = item.block
            .map((line) => line.trim())
            .join(" ")
            .match(/#\/components\/(responses|schemas)\/(\w+)/);
          responses.push({
            status,
            description: respDescription,
            schema: refMatch?.[2] ?? "",
          });
        }
      }
      endpoints.push({ method, path, operationId, summary, description, params, responses });
    }
  }

  void finishParam;
  return { meta: { title, version, description: infoDescription, serverUrl }, endpoints };
}

/** Sample path params taken from the spec's own examples. */
export const SAMPLE_PATH_PARAMS: Record<string, string> = {
  cveId: "CVE-2026-109618",
  listName: "known-exploited",
};

/** Sample queries per operation so every endpoint gets a copy-paste example. */
export const SAMPLE_QUERIES: Record<string, string> = {
  listCves: "?limit=2",
  getCveById: "",
  searchCves: "?q=openssl&limit=2",
  getPriorityList: "?limit=2",
  listRadarEvents: "?limit=2",
  replayCheckpoint: "?date=2026-10-17&view=known-exploited",
  listReplayCheckpoints: "?limit=2",
  getOverview: "?bucket=month&months=2",
  getStatus: "",
  getHealth: "",
};

export function endpointSlug(endpoint: ApiEndpoint): string {
  return `${endpoint.method.toLowerCase()}-${endpoint.path
    .replace(/[{}/]/g, "-")
    .replace(/[^a-zA-Z0-9-]+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "")
    .toLowerCase()}`;
}

export function buildCurl(baseUrl: string, endpoint: ApiEndpoint): string {
  const path = endpoint.path.replace(
    /\{(\w+)\}/g,
    (_, key: string) => SAMPLE_PATH_PARAMS[key] ?? key,
  );
  return `curl "${baseUrl}${path}${SAMPLE_QUERIES[endpoint.operationId] ?? "?limit=2"}"`;
}

// Prose below is copied from docs/api/README.md (the human-docs source of
// truth); the unit test pins the key phrases against that file.

export const RATE_LIMIT_TEXT = [
  "600 requests per minute per IP; bursts over the budget get 429 RATE_LIMITED.",
  "`limit` parameter capped at 200; `q` capped at 200 characters.",
  "Every 200 and 429 carries X-RateLimit-Limit, X-RateLimit-Remaining, and X-RateLimit-Reset; 429 adds Retry-After.",
];

export const PAGINATION_TEXT = [
  "Cursor-based. limit defaults to 50 and caps at 200; oversized values are rejected with BAD_LIMIT, not clamped.",
  "Responses carry pagination: {limit, hasMore, nextCursor}; pass nextCursor back as cursor.",
  "Cursors are opaque — never constructed by hand.",
];

export const FRESHNESS_TEXT = [
  "Reads never call upstream; they serve accepted local snapshots.",
  "CVE / KEV stale when the last successful check is more than 3 hours old.",
  "EPSS stale when the accepted score date is older than 2 UTC calendar days.",
  "A stale source keeps its dated values with `stale: true` and the last error named.",
];

export const ERROR_CATALOG: { code: string; http: string; meaning: string }[] = [
  { code: "BAD_REQUEST", http: "400", meaning: "Generic rejected input" },
  { code: "BAD_CURSOR", http: "400", meaning: "Malformed or foreign cursor" },
  { code: "BAD_LIMIT", http: "400", meaning: "limit outside 1–200" },
  { code: "BAD_QUERY", http: "400", meaning: "q too short, too long, or unsafe" },
  { code: "BAD_FILTER", http: "400", meaning: "Unknown enum value or bad combination" },
  { code: "BAD_DATE_RANGE", http: "400", meaning: "Unparseable dates or start >= end" },
  { code: "CVE_NOT_FOUND", http: "404", meaning: "No current PUBLISHED record for the ID" },
  { code: "LIST_NOT_FOUND", http: "404", meaning: "Unknown priority list name" },
  { code: "CHECKPOINT_UNAVAILABLE", http: "404", meaning: "No manifest for the date" },
  {
    code: "REPLAY_UNAVAILABLE",
    http: "404",
    meaning: "Expired, missing, or model-changed; details.reason names it",
  },
  {
    code: "RATE_LIMITED",
    http: "429",
    meaning: "Per-IP budget spent; Retry-After tells when to return",
  },
  { code: "INTERNAL", http: "500", meaning: "Sanitized failure; report requestId" },
];

export const DEPRECATION_TEXT = [
  "The path major (/api/v1) is stable. Breaking changes ship as /api/v2, never as silent v1 changes. Additive fields are not breaking.",
  "A deprecated v1 route or field is announced in release notes and in the notices array of the status response, with a removal date at least 90 days out. Deprecated elements keep working until that date.",
  "A field that is absent because its source is unknown renders as explicit `null` with a status label, not as a missing key; every documented field exists in openapi/v1.yaml.",
];

/** Human guides under docs/api, each anchored to its endpoint section below. */
export const HUMAN_GUIDES: { file: string; title: string; anchor: string; blurb: string }[] = [
  {
    file: "cves.md",
    title: "Current records and one-record lookup",
    anchor: "listCves",
    blurb: "Paginated PUBLISHED records and one CVE by ID.",
  },
  {
    file: "search.md",
    title: "ID and description search",
    anchor: "searchCves",
    blurb: "Local index search behind the explore view.",
  },
  {
    file: "priority-lists.md",
    title: "The four named explainable orderings",
    anchor: "getPriorityList",
    blurb: "known-exploited, highest-forecast, new-critical, rising-forecast.",
  },
  {
    file: "radar.md",
    title: "Observed change feed",
    anchor: "listRadarEvents",
    blurb: "Before/after evidence with the reason shown.",
  },
  {
    file: "replay.md",
    title: "Retained-checkpoint replay",
    anchor: "replayCheckpoint",
    blurb: "Replay a retained checkpoint plus policy version.",
  },
  {
    file: "overview.md",
    title: "Publication-volume aggregates",
    anchor: "getOverview",
    blurb: "UTC calendar buckets behind the overview charts.",
  },
  {
    file: "status.md",
    title: "Freshness, cohorts, notices, liveness",
    anchor: "getStatus",
    blurb: "Per-source health, cohorts, notices, plus the liveness probe.",
  },
];
