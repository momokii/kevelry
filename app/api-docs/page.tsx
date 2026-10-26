// Browsable v1 API documentation (task 45). Server component that reads
// openapi/v1.yaml at build time and renders every documented path+method with
// summary, parameters, response highlights, and one copy-paste curl per
// endpoint built from the live base URL. No invented endpoints: the unit test
// asserts this list equals the parsed spec paths/methods.

import { PageHeader } from "@/components/shell/PageHeader";
import { readFileSync } from "node:fs";
import { headers } from "next/headers";
import path from "node:path";

import { SpecDownload } from "./SpecDownload";
import {
  buildCurl,
  DEPRECATION_TEXT,
  endpointSlug,
  ERROR_CATALOG,
  FRESHNESS_TEXT,
  HUMAN_GUIDES,
  PAGINATION_TEXT,
  parseSpec,
  RATE_LIMIT_TEXT,
} from "./spec";

export const dynamic = "force-dynamic";

export const metadata = {
  title: "Public API v1 documentation - CVE Change Radar",
  description:
    "Browsable reference for the versioned read-only v1 API: endpoints, parameters, curl examples, rate limits, freshness, errors, and deprecation policy.",
};

function readSpecText(): string {
  return readFileSync(path.join(process.cwd(), "openapi", "v1.yaml"), "utf8");
}

function exampleResponse(endpoint: { path: string }): string {
  const provenance = {
    rankingPolicyVersion: "ranking-v1",
    generatedAt: "2026-10-26T00:00:00.000Z",
    sources: {
      cve: { revision: "509084ac", lastAcceptedAt: "2026-10-25T15:27:00.000Z", stale: false },
      kev: {
        catalogVersion: "2026-10-24",
        lastAcceptedAt: "2026-10-25T14:39:00.000Z",
        stale: false,
      },
      epss: { scoreDate: "2026-10-24", modelVersion: "v2026.06.15", stale: false },
    },
  };
  if (endpoint.path.includes("/health")) {
    return JSON.stringify({ status: "ok", version: "v1", provenance }, null, 2);
  }
  if (endpoint.path.includes("/status")) {
    return JSON.stringify(
      {
        state: "ok",
        sources: provenance.sources,
        cohort: { published: 395286, kev: 1756, epssScored: 395249, unscored: 215998 },
        notices: [],
      },
      null,
      2,
    );
  }
  if (endpoint.path.includes("/overview")) {
    return JSON.stringify(
      {
        bucket: "month",
        dateBasis: "publishedAt-utc",
        buckets: [{ bucketStart: "2026-09", count: 14934 }],
        coverage: { eligibleCohort: 395286, returned: 24 },
        provenance,
      },
      null,
      2,
    );
  }
  if (endpoint.path.includes("/priority/")) {
    return JSON.stringify(
      {
        view: "known-exploited",
        items: [
          {
            cveId: "CVE-2026-110447",
            kevMember: true,
            dateAdded: "2026-10-23T00:00:00.000Z",
            epss: {
              status: "known",
              value: 0.02285,
              percentile: 0.91,
              scoreDate: "2026-10-24",
              modelVersion: "v2026.06.15",
            },
            cvss: { status: "known", source: "cna", version: "4.0", baseScore: 9.2 },
          },
        ],
        coverage: { eligibleCohort: 1756, returned: 1 },
        provenance,
      },
      null,
      2,
    );
  }
  if (endpoint.path.includes("/radar")) {
    return JSON.stringify(
      {
        events: [
          { kind: "kev-added", cveId: "CVE-2026-110447", before: null, after: { kevMember: true } },
        ],
        snapshot: { before: "2026-10-23", after: "2026-10-24" },
        provenance,
      },
      null,
      2,
    );
  }
  if (endpoint.path.includes("/replay/checkpoints")) {
    return JSON.stringify(
      {
        checkpoints: [
          { checkpointDate: "2026-10-24", policyVersion: "ranking-v1", expired: false },
        ],
        provenance,
      },
      null,
      2,
    );
  }
  if (endpoint.path.includes("/replay")) {
    return JSON.stringify(
      {
        status: "available",
        manifest: {
          checkpointDate: "2026-10-24",
          policyVersion: "ranking-v1",
          cohortCount: 395286,
        },
        provenance,
      },
      null,
      2,
    );
  }
  if (endpoint.path.includes("/search")) {
    return JSON.stringify(
      {
        items: [
          {
            cveId: "CVE-2026-110447",
            title: "Edge gateway overflow",
            severityBand: "critical",
            kevMember: true,
            epssKnown: true,
          },
        ],
        total: 1,
        coverage: { unknownDate: 0, kevMembers: 1, epssKnown: 1 },
        nextCursor: null,
        provenance,
      },
      null,
      2,
    );
  }
  if (endpoint.path.includes("{cveId}")) {
    return JSON.stringify(
      {
        data: {
          cveId: "CVE-2026-110447",
          title: "Edge gateway overflow",
          state: "PUBLISHED",
          kev: { status: "known" },
          epss: { status: "known", value: 0.02285 },
          cvss: { status: "known", source: "cna", version: "4.0", baseScore: 9.2 },
        },
        provenance,
      },
      null,
      2,
    );
  }
  return JSON.stringify(
    {
      data: [{ cveId: "CVE-2026-110447", title: "Edge gateway overflow", state: "PUBLISHED" }],
      nextCursor: null,
      provenance,
    },
    null,
    2,
  );
}

export default async function ApiDocsPage() {
  const specText = readSpecText();
  const { meta, endpoints } = parseSpec(specText);
  const headerList = await headers();
  const host = headerList.get("x-forwarded-host") ?? headerList.get("host") ?? "localhost:3000";
  const protocol = headerList.get("x-forwarded-proto") ?? "http";
  const baseUrl = `${protocol}://${host}`;

  return (
    <main className="page" data-testid="api-docs-root" id="main-content">
      <PageHeader
        eyebrow={
          <>
            <span>API</span>
            <span className="dot" aria-hidden="true" />
            <span>{meta.version}</span>
            <span className="dot" aria-hidden="true" />
            <span>rendered from the spec</span>
          </>
        }
        title="Public API v1"
        lede={
          <span data-testid="api-docs-lede">
            {meta.title} {meta.version}: the same accepted local snapshots the site reads, served as
            versioned read-only GET routes. The table below is rendered from openapi/v1.yaml, so it
            cannot drift from the spec.
          </span>
        }
        actions={
          <a className="btn btn-sm" href="/methodology">
            Data semantics
          </a>
        }
      />

      <nav className="page-toc" aria-label="On this page" data-testid="api-docs-toc">
        <span className="eyebrow">On this page</span>
        <div className="page-toc-links">
          <a href="#api-docs-overview-heading">Overview</a>
          <a href="#api-docs-auth-heading">Authentication</a>
          <a href="#api-docs-limits-heading">Rate limits</a>
          <a href="#api-docs-pagination-heading">Pagination</a>
          <a href="#api-docs-freshness-heading">Freshness</a>
          <a href="#api-docs-errors-heading">Errors</a>
          <a href="#api-docs-deprecation-heading">Deprecation</a>
          <a href="#api-docs-endpoints-heading">Endpoints</a>
          <a href="#api-docs-spec-heading">Machine contract</a>
          <a href="#api-docs-guides-heading">Human guides</a>
        </div>
        <div className="page-toc-links page-toc-endpoints">
          {endpoints.map((endpoint) => (
            <a key={endpoint.operationId} href={`#endpoint-${endpoint.operationId}`}>
              <code>{endpoint.path}</code>
            </a>
          ))}
        </div>
      </nav>

      <section className="ledger-section" aria-labelledby="api-docs-overview-heading">
        <h2 id="api-docs-overview-heading">Overview</h2>
        <div data-testid="api-docs-overview">
          <p>
            Base path: <code data-testid="api-docs-base-url">/api/v1</code> on{" "}
            <code>{baseUrl}</code>. Self-hosted copies serve the API from their own origin; the
            example origin in the spec is illustrative.
          </p>
          <p>
            Versioned and read-only: every route is GET under the <code>/api/v1</code> path major.
            Breaking changes ship as <code>/api/v2</code>, never as silent v1 changes. Public writes
            are out of scope.
          </p>
          <p>
            Anonymous by design: no authentication, no tokens, no accounts, no per-user state. Every
            response carries provenance (ranking policy version plus per-source revision, dates,
            stale flags, and errors) so any score or ordering can be verified.
          </p>
        </div>
      </section>

      <section className="ledger-section" aria-labelledby="api-docs-auth-heading">
        <h2 id="api-docs-auth-heading">Authentication</h2>
        <div data-testid="api-docs-auth">
          <p>
            None. Public reads are anonymous; there is deliberately no write endpoint to
            authenticate against. Clients that need private use run their own self-hosted copy and
            put their own access control in front of it.
          </p>
        </div>
      </section>

      <section className="ledger-section" aria-labelledby="api-docs-limits-heading">
        <h2 id="api-docs-limits-heading">Rate limits</h2>
        <div data-testid="api-docs-rate-limits">
          <ul>
            {RATE_LIMIT_TEXT.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
          <p className="ledger-meta">
            Defaults, enforced per client IP and visible on every response. Tune the numbers per
            deployment; the header names and the 429 shape are stable.
          </p>
        </div>
      </section>

      <section className="ledger-section" aria-labelledby="api-docs-pagination-heading">
        <h2 id="api-docs-pagination-heading">Pagination and cursors</h2>
        <div data-testid="api-docs-pagination">
          <ul>
            {PAGINATION_TEXT.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        </div>
      </section>

      <section className="ledger-section" aria-labelledby="api-docs-freshness-heading">
        <h2 id="api-docs-freshness-heading">Freshness semantics</h2>
        <div data-testid="api-docs-freshness">
          <ul>
            {FRESHNESS_TEXT.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
          <p>
            A missing EPSS row renders as explicit unknown with nulls, never zero; a real zero
            remains known. Missing publication dates go to an explicit unknown bucket.
          </p>
        </div>
      </section>

      <section className="ledger-section" aria-labelledby="api-docs-errors-heading">
        <h2 id="api-docs-errors-heading">Error catalog</h2>
        <div data-testid="api-docs-errors">
          <p>
            All errors share <code>{"{code, message, details?, requestId?, provenance}"}</code>.{" "}
            <code>code</code> is stable for clients; <code>message</code> is sanitized; no stack
            traces, paths, or secrets.
          </p>
          <div className="ledger-api-table-wrap">
            <table className="ledger-api-table" data-testid="api-docs-errors-table">
              <thead>
                <tr>
                  <th scope="col">Code</th>
                  <th scope="col">HTTP</th>
                  <th scope="col">Meaning</th>
                </tr>
              </thead>
              <tbody>
                {ERROR_CATALOG.map((row) => (
                  <tr key={row.code} data-testid={`api-docs-error-${row.code}`}>
                    <td>
                      <code>{row.code}</code>
                    </td>
                    <td>{row.http}</td>
                    <td>{row.meaning}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <section className="ledger-section" aria-labelledby="api-docs-deprecation-heading">
        <h2 id="api-docs-deprecation-heading">Deprecation policy</h2>
        <div data-testid="api-docs-deprecation">
          <ul>
            {DEPRECATION_TEXT.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        </div>
      </section>

      <section className="ledger-section" aria-labelledby="api-docs-endpoints-heading">
        <h2 id="api-docs-endpoints-heading">Endpoints</h2>
        <p className="ledger-meta">
          {endpoints.length} documented routes, every path+method from openapi/v1.yaml. Each example
          below is built from this deployment&apos;s base URL.
        </p>
        <div className="ledger-api-table-wrap">
          <table className="ledger-api-table" data-testid="api-docs-endpoints">
            <thead>
              <tr>
                <th scope="col">Method</th>
                <th scope="col">Path</th>
                <th scope="col">Summary</th>
              </tr>
            </thead>
            <tbody>
              {endpoints.map((endpoint) => (
                <tr
                  key={`${endpoint.method} ${endpoint.path}`}
                  data-testid={`api-docs-row-${endpointSlug(endpoint)}`}
                >
                  <td>
                    <code className="ledger-api-method">{endpoint.method}</code>
                  </td>
                  <td>
                    <a href={`#endpoint-${endpoint.operationId}`}>
                      <code>{endpoint.path}</code>
                    </a>
                  </td>
                  <td>{endpoint.summary}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {endpoints.map((endpoint) => (
          <article
            key={`${endpoint.method} ${endpoint.path}`}
            id={`endpoint-${endpoint.operationId}`}
            className="ledger-api-endpoint"
            data-testid={`api-docs-endpoint-${endpointSlug(endpoint)}`}
          >
            <h3>
              <code className="ledger-api-method">{endpoint.method}</code>{" "}
              <code>{endpoint.path}</code>
            </h3>
            <p>{endpoint.summary}</p>
            {endpoint.description !== "" ? (
              <p className="ledger-meta">{endpoint.description}</p>
            ) : null}
            {endpoint.params.length > 0 ? (
              <div className="ledger-api-table-wrap">
                <table
                  className="ledger-api-table"
                  data-testid={`api-docs-params-${endpointSlug(endpoint)}`}
                >
                  <caption>Parameters</caption>
                  <thead>
                    <tr>
                      <th scope="col">Name</th>
                      <th scope="col">In</th>
                      <th scope="col">Type</th>
                      <th scope="col">Required</th>
                      <th scope="col">Description</th>
                    </tr>
                  </thead>
                  <tbody>
                    {endpoint.params.map((param) => (
                      <tr key={`${param.location}:${param.name}`}>
                        <td>
                          <code>{param.name}</code>
                        </td>
                        <td>{param.location}</td>
                        <td>
                          <code>{param.type}</code>
                        </td>
                        <td>{param.required ? "yes" : "no"}</td>
                        <td>{param.description}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <p className="ledger-meta" data-testid={`api-docs-params-${endpointSlug(endpoint)}`}>
                No parameters.
              </p>
            )}
            <ul className="ledger-meta">
              {endpoint.responses.map((response) => (
                <li key={response.status}>
                  <code>{response.status}</code>
                  {response.schema !== "" ? (
                    <>
                      {" "}
                      · schema <code>{response.schema}</code>
                    </>
                  ) : null}{" "}
                  — {response.description}
                </li>
              ))}
            </ul>
            <pre
              className="ledger-api-curl"
              data-testid={`api-docs-example-${endpointSlug(endpoint)}`}
            >
              {buildCurl(baseUrl, endpoint)}
            </pre>
            <details className="api-response-example">
              <summary>Example response · illustrative shape</summary>
              <pre data-testid={`api-docs-response-${endpointSlug(endpoint)}`}>
                {exampleResponse(endpoint)}
              </pre>
              <p className="chart-note">
                Illustrative values only. The OpenAPI schema and the live route are authoritative.
              </p>
            </details>
          </article>
        ))}
      </section>

      <section className="ledger-section" aria-labelledby="api-docs-spec-heading">
        <h2 id="api-docs-spec-heading">Machine contract</h2>
        <div data-testid="api-docs-spec">
          <p>
            The full contract lives in <code>openapi/v1.yaml</code> in the repo. This page renders
            that file at build time; download the exact text below (served from this page as a file
            download, so no extra route is needed).
          </p>
          <SpecDownload specText={specText} />
          <details>
            <summary className="ledger-more-link">View openapi/v1.yaml inline</summary>
            <pre className="ledger-api-curl" data-testid="api-docs-spec-text">
              {specText}
            </pre>
          </details>
        </div>
      </section>

      <section className="ledger-section" aria-labelledby="api-docs-guides-heading">
        <h2 id="api-docs-guides-heading">Human guides</h2>
        <div data-testid="api-docs-guides">
          <p className="ledger-meta">
            Prose companions under docs/api in the repo, one per view. Each links to its endpoint
            section above.
          </p>
          <ul>
            {HUMAN_GUIDES.map((guide) => (
              <li key={guide.file}>
                <a href={`#endpoint-${guide.anchor}`}>{guide.title}</a>{" "}
                <span className="ledger-meta">
                  (docs/api/{guide.file}) — {guide.blurb}
                </span>
              </li>
            ))}
          </ul>
        </div>
      </section>
    </main>
  );
}
