"use client";

import { useEffect, useState } from "react";

import { ExploreFilters } from "./ExploreFilters";
import type { ExploreInitial } from "./filter-meta";

export function FilterPanel({ initial }: { initial: ExploreInitial }) {
  const [open, setOpen] = useState(true);

  useEffect(() => {
    if (window.matchMedia("(max-width: 1080px)").matches) setOpen(false);
  }, []);

  const active =
    (initial.q !== "" ? 1 : 0) +
    (initial.dateStart !== "" || initial.dateEnd !== "" ? 1 : 0) +
    (initial.severity.length > 0 ? 1 : 0) +
    (initial.kev !== "all" ? 1 : 0) +
    (initial.epss !== "all" ? 1 : 0);

  return (
    <details
      className="explore-filter-details"
      open={open}
      onToggle={(event) => setOpen(event.currentTarget.open)}
    >
      <summary>
        <span>Filters</span>
        <span className="pill">{active === 0 ? "none active" : `${active} active`}</span>
      </summary>
      <div className="explore-filter-body">
        <ExploreFilters initial={initial} />
      </div>
    </details>
  );
}
