export default function PriorityLoading() {
  return (
    <main className="page" aria-busy="true" aria-label="Loading priority lists">
      <div className="page-head">
        <div>
          <div className="skeleton skeleton-line" style={{ width: 180 }} />
          <div className="skeleton skeleton-title" />
        </div>
      </div>
      <div className="priority-layout">
        <div>
          <div className="skeleton skeleton-panel" style={{ height: 120, marginBottom: 16 }} />
          <div className="skeleton skeleton-panel" style={{ height: 520 }} />
        </div>
        <div className="skeleton skeleton-panel" style={{ height: 420 }} />
      </div>
    </main>
  );
}
