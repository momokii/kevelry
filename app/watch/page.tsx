import { PageHeader } from "@/components/shell/PageHeader";
import { WatchView } from "@/components/watch/WatchView";

export const revalidate = 60;

export const metadata = {
  title: "Watch — Kevelry",
  description:
    "CVE IDs starred in this browser, hydrated from the retained snapshot. No account, no server record.",
};

export default function WatchPage() {
  return (
    <main className="page" data-testid="watch-root" id="main-content">
      <PageHeader
        eyebrow={
          <>
            <span>Watch</span>
            <span className="dot" aria-hidden="true" />
            <span>this browser only</span>
            <span className="dot" aria-hidden="true" />
            <span>no account</span>
          </>
        }
        title="Watched CVEs"
        lede="Starred rows, hydrated from the retained snapshot on each visit. The list never leaves this browser: no account, no server record, clearing storage unwatches everything."
      />
      <WatchView />
    </main>
  );
}
