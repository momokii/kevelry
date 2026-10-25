// Pure data behind the methodology diagrams. No JSX, no policy text of its
// own: every label below summarizes prose already stated on the methodology
// page. Tested by tests/methodology-diagrams.test.ts.

export interface PipelineStage {
  step: number;
  title: string;
  detail: string;
  connectorLabel: string | null;
}

export const PIPELINE_STAGES: PipelineStage[] = [
  {
    step: 1,
    title: "Free upstream feeds",
    detail: "CVE List V5, CISA KEV, FIRST EPSS. Only the ingestion worker fetches upstream.",
    connectorLabel: "worker fetches",
  },
  {
    step: 2,
    title: "Pin revisions",
    detail:
      "Exact source revisions and dates, observation times, ranking policy version, eligible cohort.",
    connectorLabel: "pins",
  },
  {
    step: 3,
    title: "Validate and stage",
    detail:
      "A complete snapshot is staged. A successful unchanged check updates health, not record dates.",
    connectorLabel: "stages",
  },
  {
    step: 4,
    title: "Atomic publish and manifest",
    detail: "Visitor pages and the public API read accepted local snapshots only.",
    connectorLabel: "publishes",
  },
  {
    step: 5,
    title: "SQLite snapshot",
    detail:
      "Retained local snapshot. Reimporting identical bytes yields the same result without duplicates.",
    connectorLabel: "writes",
  },
  {
    step: 6,
    title: "Read models",
    detail: "Site pages, read-only API, Radar checkpoints, Replay.",
    connectorLabel: null,
  },
];

export const PIPELINE_FAILURE_BRANCH =
  "Upstream failure: serve last-known-good with a visible stale label. One feed never freezes the others.";

export interface OrderingFlowStep {
  position: number;
  key: string;
  detail: string;
}

export const DEFAULT_PRIORITY_FLOW: OrderingFlowStep[] = [
  {
    position: 1,
    key: "KEV member before not listed",
    detail: "Membership in the accepted KEV snapshot splits the list first.",
  },
  {
    position: 2,
    key: "EPSS present before unknown",
    detail: "Scored records come before records with no current EPSS row.",
  },
  {
    position: 3,
    key: "EPSS probability descending",
    detail: "Raw source probability, actual zero still scored. Never formatted display text.",
  },
  {
    position: 4,
    key: "Known publication before unknown",
    detail: "Records with a publication timestamp come before the unknown-date bucket.",
  },
  {
    position: 5,
    key: "Publication descending",
    detail: "Newer publication timestamps first.",
  },
  {
    position: 6,
    key: "CVE ID ASCII ascending",
    detail: "Final deterministic tie-break.",
  },
];

export interface OrderingMode {
  mode: string;
  eligibility: string;
  sortKeys: string[];
}

export const ORDERING_MODES: OrderingMode[] = [
  {
    mode: "Known exploited",
    eligibility: "KEV members only",
    sortKeys: ["KEV dateAdded descending", "CVE ID ASCII ascending"],
  },
  {
    mode: "Highest forecast",
    eligibility: "Known EPSS only",
    sortKeys: [
      "Raw EPSS probability descending",
      "Known publication before unknown",
      "Publication descending",
      "CVE ID ASCII ascending",
    ],
  },
  {
    mode: "New critical",
    eligibility:
      "Published in [T - 30d, T), primary modern CVSS 9.0 or above; unknown, legacy-only, and ADP-only cases ineligible",
    sortKeys: ["Publication descending", "CVE ID ASCII ascending"],
  },
  {
    mode: "Rising forecast",
    eligibility:
      "Observations on exactly d and d-7 with the same model version, positive delta only",
    sortKeys: [
      "Delta percentage-points descending",
      "Current raw probability descending",
      "CVE ID ASCII ascending",
    ],
  },
];

export interface SignalLane {
  lane: string;
  signal: string;
  meaning: string;
  caution: string;
}

export const SIGNAL_LANES: SignalLane[] = [
  {
    lane: "Lane 1",
    signal: "CVSS",
    meaning: "Supplied severity from record metrics, not a prediction.",
    caution: "Unscored is unknown, not low. Versions are not calibrated alike.",
  },
  {
    lane: "Lane 2",
    signal: "KEV",
    meaning: "Confirmed exploitation evidence from the accepted catalog snapshot.",
    caution: "Absence means not listed, not proof of safety.",
  },
  {
    lane: "Lane 3",
    signal: "EPSS",
    meaning: "Dated 30-day forecast with a score date and model version.",
    caution: "Percentile is relative position, not probability. Missing is unknown, never zero.",
  },
];

export const SIGNALS_CONVERGENCE =
  "Kept separate: never multiplied into a risk score. No composite score is computed.";
