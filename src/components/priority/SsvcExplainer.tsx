import Link from "next/link";

import { HelpTip } from "@/components/ledger/HelpTip";

/**
 * Plain-language explainer for the SSVC view. The point of surfacing CISA's
 * decision points is explainability, so the page has to say what SSVC is, how
 * to read the three points, and what the site does (and refuses to do) with
 * them — in the product, not only in the docs.
 */
export function SsvcExplainer({ sinceDays }: { sinceDays: number | null }) {
  const windows = [
    { days: 30, label: "Last 30 days" },
    { days: 90, label: "Last 90 days" },
    { days: 365, label: "Last year" },
    { days: null, label: "All time" },
  ] as const;

  return (
    <section className="ssvc-explainer" data-testid="ssvc-explainer" aria-labelledby="ssvc-heading">
      <div className="ssvc-explainer-head">
        <div>
          <h2 id="ssvc-heading">What SSVC means here</h2>
          <p className="chart-note">
            CISA publishes three decision points per CVE in its Vulnrichment repository (CC0).
            This site stores them verbatim and shows them beside KEV, EPSS, and CVSS. It never
            blends them into a score of its own.
          </p>
        </div>
      </div>

      <dl className="ssvc-points">
        <div>
          <dt>
            Exploitation{" "}
            <HelpTip term="SSVC exploitation" testId="ssvc-help-exploitation">
              Whether exploitation is none, proof-of-concept only (poc), or active. This view only
              lists records where CISA states active.
            </HelpTip>
          </dt>
          <dd>
            <code>none</code> · <code>poc</code> · <code>active</code> — <strong>active</strong>{" "}
            means CISA sees exploitation in the wild, not a lab demonstration.
          </dd>
        </div>
        <div>
          <dt>
            Technical impact{" "}
            <HelpTip term="SSVC technical impact" testId="ssvc-help-impact">
              partial or total. Total means the exploit can take over the vulnerable component;
              partial means limited control or access.
            </HelpTip>
          </dt>
          <dd>
            <code>partial</code> · <code>total</code> — total exploits the whole component, so it
            sorts ahead of partial in this view.
          </dd>
        </div>
        <div>
          <dt>
            Automatable{" "}
            <HelpTip term="SSVC automatable" testId="ssvc-help-automatable">
              Whether the exploit can be delivered reliably at scale without a human in the loop.
            </HelpTip>
          </dt>
          <dd>
            <code>yes</code> · <code>no</code> — yes means a worm-like or scripted attack is
            plausible.
          </dd>
        </div>
      </dl>

      <div className="ssvc-order">
        <div>
          <span className="eyebrow">Order of this list</span>
          <p className="chart-note">
            Technical impact total first, then automatable yes, then the{" "}
            <strong>KEV catalog date descending</strong> — newest exploitation confirmation first —
            then raw EPSS probability, then CVE ID. Recency is a published date, not an estimate.
          </p>
        </div>
        <nav className="ssvc-windows" aria-label="Recency window" data-testid="ssvc-windows">
          {windows.map((window) => {
            const active = (window.days ?? null) === sinceDays;
            const href = window.days === null ? "/priority?view=ssvc-active" : `/priority?view=ssvc-active&since=${window.days}`;
            return active ? (
              <span key={window.label} className="ledger-filter-chip" aria-current="page">
                {window.label}
              </span>
            ) : (
              <Link key={window.label} className="ledger-filter-chip" href={href}>
                {window.label}
              </Link>
            );
          })}
        </nav>
      </div>

      <p className="chart-note" data-testid="ssvc-coverage-note">
        Coverage is partial: CISA has not published an SSVC block for every CVE. A record without
        one is <strong>ineligible</strong> here and says so in its detail panel — it is never
        assumed safe. Source: CISA Vulnrichment, refreshed daily; see{" "}
        <a
          href="https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc"
          target="_blank"
          rel="noreferrer noopener"
        >
          CISA&apos;s SSVC documentation
        </a>
        .
      </p>
    </section>
  );
}
