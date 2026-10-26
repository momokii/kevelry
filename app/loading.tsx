export default function Loading() {
  return (
    <main className="page" aria-busy="true" aria-label="Loading retained snapshot">
      <div className="page-head">
        <div>
          <div className="skeleton skeleton-line" style={{ width: 180 }} />
          <div className="skeleton skeleton-title" />
          <div className="skeleton skeleton-line" style={{ width: "min(560px, 90%)" }} />
        </div>
      </div>
      <div className="skeleton skeleton-hero" />
      <div className="grid">
        <div className="skeleton skeleton-panel span-8" />
        <div className="skeleton skeleton-panel span-4" />
      </div>
    </main>
  );
}
