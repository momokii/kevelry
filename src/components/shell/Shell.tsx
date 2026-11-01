"use client";

import { useEffect, useRef, useState } from "react";
import { usePathname } from "next/navigation";
import Link from "next/link";

import { ThemeToggle } from "@/components/ledger/ThemeToggle";
import { TimeZoneSelect } from "@/components/ledger/TimeZoneSelect";

import {
  ActivityIcon,
  ApiIcon,
  CloseIcon,
  CollapseIcon,
  ExpandIcon,
  MenuIcon,
  MethodIcon,
  OverviewIcon,
  PriorityIcon,
  RadarIcon,
  GraphIcon,
  ReplayIcon,
  SearchIcon,
  StarIcon,
} from "./icons";

const NAV = [
  { href: "/", label: "Overview", icon: OverviewIcon },
  { href: "/explore", label: "Search", icon: SearchIcon },
  { href: "/priority", label: "Priority", icon: PriorityIcon, count: "5 views" },
  { href: "/radar", label: "Radar", icon: RadarIcon },
  { href: "/replay", label: "Replay", icon: ReplayIcon },
  { href: "/graph", label: "Graph", icon: GraphIcon },
  { href: "/methodology", label: "Method", icon: MethodIcon },
  { href: "/api-docs", label: "API", icon: ApiIcon },
  { href: "/watch", label: "Watch", icon: StarIcon },
] as const;

const MASTHEAD_IDS: Record<string, string> = {
  "/": "overview-masthead",
  "/explore": "explore-masthead",
  "/priority": "priority-masthead",
  "/radar": "radar-masthead",
  "/replay": "replay-masthead",
  "/graph": "graph-masthead",
  "/methodology": "methodology-masthead",
  "/api-docs": "api-docs-masthead",
  "/showcase": "showcase-masthead",
  "/watch": "watch-masthead",
};

function currentLabel(pathname: string): string {
  const match = NAV.find((item) => item.href === pathname);
  return match?.label ?? "Overview";
}

export function Shell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname() ?? "/";
  const [open, setOpen] = useState(false);
  const [collapsed, setCollapsed] = useState(false);
  const searchRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    setCollapsed(window.localStorage.getItem("ui-rail-collapsed") === "true");
  }, []);

  const toggleRail = (): void => {
    setCollapsed((current) => {
      const next = !current;
      window.localStorage.setItem("ui-rail-collapsed", String(next));
      return next;
    });
  };

  useEffect(() => {
    setOpen(false);
  }, [pathname]);

  useEffect(() => {
    const onKey = (event: KeyboardEvent): void => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        searchRef.current?.focus();
      }
      if (event.key === "Escape") setOpen(false);
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, []);

  const mastheadId = MASTHEAD_IDS[pathname] ?? "shell-masthead";

  return (
    <div className={`app-shell ${collapsed ? "rail-collapsed" : ""}`}>
      <button
        type="button"
        className={`app-scrim ${open ? "is-open" : ""}`}
        aria-label="Close navigation"
        tabIndex={open ? 0 : -1}
        onClick={() => setOpen(false)}
      />
      <aside
        className={`app-rail ${open ? "is-open" : ""}`}
        data-testid={mastheadId}
        aria-label="Application navigation"
      >
        <div className="app-brand-row">
          <Link className="app-brand" href="/">
            <span className="app-brand-mark" aria-hidden="true">
              CV
            </span>
            <span>
              <span className="app-brand-name">Kevelry</span>
              <span className="app-brand-sub">research console</span>
            </span>
          </Link>
          <button
            type="button"
            className="btn btn-ghost btn-icon mobile-menu-button"
            aria-label="Close menu"
            onClick={() => setOpen(false)}
          >
            <CloseIcon />
          </button>
          <button
            type="button"
            className="btn btn-ghost btn-icon rail-collapse-button"
            aria-label={collapsed ? "Expand navigation" : "Collapse navigation"}
            aria-expanded={!collapsed}
            onClick={toggleRail}
          >
            {collapsed ? <ExpandIcon /> : <CollapseIcon />}
          </button>
        </div>

        <nav className="app-nav" aria-label="Primary">
          {NAV.map((item) => {
            const Icon = item.icon;
            const active = item.href === pathname;
            return (
              <Link
                key={item.href}
                href={item.href}
                className="app-nav-link"
                aria-current={active ? "page" : undefined}
                aria-label={item.label}
                title={collapsed ? item.label : undefined}
              >
                <Icon className="app-nav-icon" />
                <span className="app-nav-text">
                  {item.label}
                  {active ? (
                    <span className="sr-only" aria-current="page">
                      {" "}
                      (current)
                    </span>
                  ) : null}
                </span>
                {"count" in item && item.count ? (
                  <span className="app-nav-count">{item.count}</span>
                ) : null}
              </Link>
            );
          })}
        </nav>

        <div className="app-rail-spacer" />

        <div className="app-rail-section">
          <div className="app-rail-label">Data status</div>
          <Link className="app-rail-status" href="/methodology#methodology-section-status">
            <ActivityIcon className="app-nav-icon" />
            <span className="app-nav-text">Source freshness</span>
            <span className="app-nav-count">status</span>
          </Link>
          <Link className="app-rail-status" href="/api-docs">
            <ApiIcon className="app-nav-icon" />
            <span className="app-nav-text">Reference</span>
            <span className="app-nav-count">v1</span>
          </Link>
        </div>

        <div className="app-rail-section">
          <div className="app-rail-label">Display</div>
          <TimeZoneSelect testId="global-timezone" />
          <ThemeToggle testId="global-theme" />
        </div>
      </aside>

      <div className="app-main">
        <header className="app-topbar">
          <button
            type="button"
            className="btn btn-ghost btn-icon mobile-menu-button"
            aria-label="Open navigation"
            aria-expanded={open}
            onClick={() => setOpen(true)}
          >
            <MenuIcon />
          </button>
          <div className="app-topbar-context">
            <strong>{currentLabel(pathname)}</strong>
            <span aria-hidden="true">/</span>
            <span>all sources</span>
          </div>
          <form className="app-search" action="/explore" method="get" role="search">
            <SearchIcon />
            <input
              ref={searchRef}
              type="search"
              name="q"
              data-testid="global-search"
              placeholder="Search CVE, vendor, product, description…"
              aria-label="Search CVE records"
              maxLength={200}
            />
            <span className="app-kbd" aria-hidden="true">
              ⌘K
            </span>
          </form>
          <div className="app-topbar-actions">
            <Link className="pill timezone-compact" href="/methodology#methodology-section-status">
              <span>Data status</span>
            </Link>
            <Link className="btn btn-sm" href="/explore">
              Explore
            </Link>
          </div>
        </header>
        <div className="app-content">{children}</div>
      </div>
    </div>
  );
}
