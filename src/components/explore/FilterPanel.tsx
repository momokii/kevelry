import { ExploreFilters } from "./ExploreFilters";
import type { ExploreInitial } from "./filter-meta";

export function FilterPanel({ initial }: { initial: ExploreInitial }) {
  const active =
    (initial.q !== "" ? 1 : 0) +
    (initial.dateStart !== "" || initial.dateEnd !== "" ? 1 : 0) +
    (initial.severity.length > 0 ? 1 : 0) +
    (initial.kev !== "all" ? 1 : 0) +
    (initial.epss !== "all" ? 1 : 0) +
    (initial.vendor !== "" ? 1 : 0);

  return (
    <details className="explore-filter-details" open>
      <summary>
        <span className="filter-summary-title">
          <span className="filter-chevron" aria-hidden="true" />
          <span>Filters</span>
        </span>
        <span className={`filter-count${active > 0 ? " is-active" : ""}`}>
          {active === 0 ? "none active" : `${active} active`}
        </span>
      </summary>
      <div className="explore-filter-body">
        <ExploreFilters initial={initial} />
      </div>
    </details>
  );
}
