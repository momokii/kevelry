export default function ExploreLoading() {
  return (
    <main className="page" aria-busy="true" aria-label="Loading search results">
      <div className="page-head">
        <div>
          <div className="skeleton skeleton-line" style={{ width: 160 }} />
          <div className="skeleton skeleton-title" />
        </div>
      </div>
      <div className="explore-layout">
        <div className="skeleton skeleton-panel" style={{ height: 520 }} />
        <div>
          <div className="skeleton skeleton-panel" style={{ height: 240, marginBottom: 16 }} />
          <div className="skeleton skeleton-panel" style={{ height: 480 }} />
        </div>
      </div>
    </main>
  );
}
