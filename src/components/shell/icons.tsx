type IconProps = { className?: string };

const base = {
  width: 18,
  height: 18,
  viewBox: "0 0 24 24",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.7,
  strokeLinecap: "round" as const,
  strokeLinejoin: "round" as const,
  "aria-hidden": true,
};

export function OverviewIcon({ className }: IconProps) {
  return (
    <svg {...base} className={className}>
      <rect x="3" y="3" width="7" height="7" rx="1" />
      <rect x="14" y="3" width="7" height="7" rx="1" />
      <rect x="3" y="14" width="7" height="7" rx="1" />
      <rect x="14" y="14" width="7" height="7" rx="1" />
    </svg>
  );
}

export function SearchIcon({ className }: IconProps) {
  return (
    <svg {...base} className={className}>
      <circle cx="11" cy="11" r="7" />
      <path d="m20 20-3.2-3.2" />
    </svg>
  );
}

export function PriorityIcon({ className }: IconProps) {
  return (
    <svg {...base} className={className}>
      <path d="M4 6h10M4 12h16M4 18h7" />
      <path d="m16 5 2 2 3-3" />
    </svg>
  );
}

export function RadarIcon({ className }: IconProps) {
  return (
    <svg {...base} className={className}>
      <circle cx="12" cy="12" r="8.5" />
      <circle cx="12" cy="12" r="4" />
      <path d="M12 12 18 6" />
    </svg>
  );
}

export function ReplayIcon({ className }: IconProps) {
  return (
    <svg {...base} className={className}>
      <path d="M3 12a9 9 0 1 0 3-6.7" />
      <path d="M3 4v5h5" />
      <path d="M12 8v5l3 2" />
    </svg>
  );
}

export function MethodIcon({ className }: IconProps) {
  return (
    <svg {...base} className={className}>
      <path d="M5 4v16M19 4v16" />
      <path d="M5 8h14M5 16h14" />
      <circle cx="12" cy="12" r="2.5" />
    </svg>
  );
}

export function ApiIcon({ className }: IconProps) {
  return (
    <svg {...base} className={className}>
      <path d="m8 8-4 4 4 4M16 8l4 4-4 4" />
      <path d="m13.5 5-3 14" />
    </svg>
  );
}

export function ActivityIcon({ className }: IconProps) {
  return (
    <svg {...base} className={className}>
      <path d="M3 12h4l2.5-6 4 12 2.5-6H21" />
    </svg>
  );
}

export function StarIcon({ className }: IconProps) {
  return (
    <svg {...base} className={className}>
      <path d="M12 3.5l2.6 5.3 5.9.9-4.2 4.1 1 5.8-5.3-2.8-5.3 2.8 1-5.8L3.5 9.7l5.9-.9L12 3.5z" />
    </svg>
  );
}

export function MenuIcon({ className }: IconProps) {
  return (
    <svg {...base} className={className}>
      <path d="M4 7h16M4 12h16M4 17h16" />
    </svg>
  );
}

export function CloseIcon({ className }: IconProps) {
  return (
    <svg {...base} className={className}>
      <path d="m6 6 12 12M18 6 6 18" />
    </svg>
  );
}

export function ArrowIcon({ className }: IconProps) {
  return (
    <svg {...base} className={className}>
      <path d="M5 12h14M13 6l6 6-6 6" />
    </svg>
  );
}

export function InfoIcon({ className }: IconProps) {
  return (
    <svg {...base} className={className}>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 11v5M12 8h.01" />
    </svg>
  );
}

export function CollapseIcon({ className }: IconProps) {
  return (
    <svg {...base} className={className}>
      <path d="m14 6-6 6 6 6" />
      <path d="M20 4v16" />
    </svg>
  );
}

export function ExpandIcon({ className }: IconProps) {
  return (
    <svg {...base} className={className}>
      <path d="m10 6 6 6-6 6" />
      <path d="M4 4v16" />
    </svg>
  );
}
