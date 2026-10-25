// Browsable v1 API documentation (task 45). Server component that reads
// openapi/v1.yaml at build time and renders every documented path+method with
// summary, parameters, response highlights, and one copy-paste curl per
// endpoint built from the live base URL. No invented endpoints: the unit test
// asserts this list equals the parsed spec paths/methods.

import { readFileSync } from "node:fs";
import { headers } from "next/headers";
import path from "node:path";

import { Masthead } from "@/components/ledger/Masthead";

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

export default async function ApiDocsPage() {
  const specText = readSpecText();
  const { meta, endpoints } = parseSpec(specText);
  const headerList = await headers();
  const host = headerList.get("x-forwarded-host") ?? headerList.get("host") ?? "localhost:3000";
  const protocol = headerList.get("x-forwarded-proto") ?? "http";
  const baseUrl = `${protocol}://${host}`;

  return (
    <main className="ledger-page" data-testid="api-docs-root" id="main-content">
      <Masthead current="API" testId="api-docs-masthead" />
      <h1>Public API v1 documentation</h1>
      <p className="ledger-meta" data-testid="api-docs-lede">
        {meta.title} {meta.version}: the same accepted local snapshots the site reads, served as
        versioned read-only GET routes. The machine contract is openapi/v1.yaml; this page renders
        that file, so the table below cannot drift from the spec.
      </p>

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
