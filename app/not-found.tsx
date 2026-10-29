import Link from "next/link";

export const metadata = {
  title: "Page not found — Kevelry",
  description: "The requested page does not exist on this CVE intelligence console.",
};

export default function NotFound() {
  return (
    <main className="page" data-testid="not-found-root" id="main-content">
      <p className="eyebrow">404 · no such page</p>
      <h1>Nothing retained here</h1>
      <p className="takeaway">
        This address matches no page and no CVE record. If you followed a link here, the target may
        have moved; CVE records themselves live under official upstream links, not here.
      </p>
      <p className="pill-row">
        <Link className="btn btn-primary btn-sm" href="/">
          Back to overview
        </Link>
        <Link className="btn btn-sm" href="/explore">
          Search records
        </Link>
        <Link className="btn btn-sm" href="/api-docs">
          API reference
        </Link>
      </p>
    </main>
  );
}
