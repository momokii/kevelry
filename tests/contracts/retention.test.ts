import { describe, expect, it } from "vitest";

import {
  StubBaselineRegistry,
  StubCheckpointStore,
  checkManifestComplete,
  resolveReplay,
  type CheckpointManifest,
} from "../../src/lib/retention-types";

// Fixture-driven retention/replay contracts. No real history, no network, no
// database. All checkpoints below are synthetic fixtures pinned to explicit
// source revisions/dates; nothing here claims pre-launch site knowledge.

const POLICY_V1 = "ranking-policy-v1";
const LAUNCH_DAY = "2026-10-24";
const RETENTION_DAYS = 30;

function fixtureManifest(overrides: Partial<CheckpointManifest> = {}): CheckpointManifest {
  return {
    checkpointDate: "2026-10-20",
    observedAt: "2026-10-20T08:15:00.000Z",
    sourcePins: {
      cveRevision: "cve-rev-abc123",
      kevCatalogDate: "2026-10-19",
      epssScoreDate: "2026-10-19",
      epssModelVersion: "epss-model-2026-10-a",
    },
    cohort: { id: "published-2026-10-20", count: 3 },
    policyVersion: POLICY_V1,
    materializedResults: ["CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0003"],
    ...overrides,
  };
}

describe("checkpoint manifests", () => {
  it("a complete manifest pins source revisions/dates, observation time, cohort, policy version, and materialized results", () => {
    const manifest = fixtureManifest();
    expect(checkManifestComplete(manifest)).toEqual({ complete: true });
    expect(manifest.sourcePins.cveRevision).toBe("cve-rev-abc123");
    expect(manifest.sourcePins.epssScoreDate).toBe("2026-10-19");
    expect(manifest.observedAt).toBe("2026-10-20T08:15:00.000Z");
    expect(manifest.cohort).toEqual({ id: "published-2026-10-20", count: 3 });
    expect(manifest.policyVersion).toBe(POLICY_V1);
    expect(manifest.materializedResults).toHaveLength(3);
  });

  it("rejects a manifest missing the ranking policy version", () => {
    const manifest = fixtureManifest({ policyVersion: "" });
    const result = checkManifestComplete(manifest);
    expect(result.complete).toBe(false);
    if (!result.complete) {
      expect(result.reason).toMatch(/policy version/i);
    }
  });

  it("rejects a manifest whose observed timestamp falls on a different UTC day than the checkpoint date", () => {
    const manifest = fixtureManifest({ observedAt: "2026-10-21T00:05:00.000Z" });
    const result = checkManifestComplete(manifest);
    expect(result.complete).toBe(false);
    if (!result.complete) {
      expect(result.reason).toMatch(/observed/i);
    }
  });

  it("rejects cohort count that disagrees with materialized result length", () => {
    const manifest = fixtureManifest({ cohort: { id: "published-2026-10-20", count: 99 } });
    const result = checkManifestComplete(manifest);
    expect(result.complete).toBe(false);
  });
});

describe("reference-counted baseline retention", () => {
  it("retains a baseline while any checkpoint references it", () => {
    const registry = new StubBaselineRegistry();
    registry.retain("baseline-1", "2026-10-20");
    registry.retain("baseline-1", "2026-10-21");
    registry.release("baseline-1", "2026-10-20");
    expect(registry.isRetained("baseline-1")).toBe(true);
  });

  it("drops a baseline only after its last referencing checkpoint is released", () => {
    const registry = new StubBaselineRegistry();
    registry.retain("baseline-1", "2026-10-20");
    registry.release("baseline-1", "2026-10-20");
    expect(registry.isRetained("baseline-1")).toBe(false);
  });
});

describe("expiry", () => {
  it("replays an expired checkpoint as explicitly unavailable, never as current data", () => {
    const store = new StubCheckpointStore({ launchDay: LAUNCH_DAY, retentionDays: RETENTION_DAYS });
    store.save(fixtureManifest());
    const currentData = ["CVE-2099-9999-current-only"];
    const replay = resolveReplay(store, "2026-10-20", {
      asOfDate: "2026-11-25",
      currentData,
    });
    expect(replay.status).toBe("unavailable");
    if (replay.status === "unavailable") {
      expect(replay.reason).toMatch(/expired/i);
    }
    expect(replay).not.toHaveProperty("results", currentData);
  });

  it("keeps a checkpoint inside the 30-day window replayable", () => {
    const store = new StubCheckpointStore({ launchDay: LAUNCH_DAY, retentionDays: RETENTION_DAYS });
    store.save(fixtureManifest());
    const replay = resolveReplay(store, "2026-10-20", { asOfDate: "2026-11-10" });
    expect(replay.status).toBe("available");
  });
});

describe("replay eligibility boundaries", () => {
  it("marks cross-model comparison ineligible instead of interpolating a spike", () => {
    const store = new StubCheckpointStore({ launchDay: LAUNCH_DAY, retentionDays: RETENTION_DAYS });
    store.save(
      fixtureManifest({
        sourcePins: {
          cveRevision: "cve-rev-abc123",
          kevCatalogDate: "2026-10-19",
          epssScoreDate: "2026-10-19",
          epssModelVersion: "epss-model-2026-10-b",
        },
      }),
    );
    const replay = resolveReplay(store, "2026-10-20", {
      asOfDate: "2026-10-25",
      expectedModelVersion: "epss-model-2026-10-a",
    });
    expect(replay.status).toBe("unavailable");
    if (replay.status === "unavailable") {
      expect(replay.reason).toMatch(/model/i);
    }
  });

  it("marks a missing gap day ineligible instead of substituting the nearest day or zero", () => {
    const store = new StubCheckpointStore({ launchDay: LAUNCH_DAY, retentionDays: RETENTION_DAYS });
    store.save(fixtureManifest({ checkpointDate: "2026-10-20", observedAt: "2026-10-20T08:15:00.000Z" }));
    const replay = resolveReplay(store, "2026-10-19", { asOfDate: "2026-10-25" });
    expect(replay.status).toBe("unavailable");
    if (replay.status === "unavailable") {
      expect(replay.reason).toMatch(/no checkpoint|missing/i);
    }
  });

  it("refuses pre-launch backfill: no checkpoint exists before initial operation", () => {
    const store = new StubCheckpointStore({ launchDay: LAUNCH_DAY, retentionDays: RETENTION_DAYS });
    const replay = resolveReplay(store, "2026-10-01", { asOfDate: "2026-10-25" });
    expect(replay.status).toBe("unavailable");
    if (replay.status === "unavailable") {
      expect(replay.reason).toMatch(/pre-launch|no checkpoint/i);
    }
  });
});

describe("replay-equals-materialized validation", () => {
  it("returns replay results byte-equal to the materialized fixture results", () => {
    const store = new StubCheckpointStore({ launchDay: LAUNCH_DAY, retentionDays: RETENTION_DAYS });
    const manifest = fixtureManifest();
    store.save(manifest);
    const replay = resolveReplay(store, "2026-10-20", { asOfDate: "2026-10-25" });
    expect(replay.status).toBe("available");
    if (replay.status === "available") {
      expect(JSON.stringify(replay.results)).toBe(JSON.stringify(manifest.materializedResults));
    }
  });

  it("fails replay as unavailable when the cohort count disagrees with stored results", () => {
    const store = new StubCheckpointStore({ launchDay: LAUNCH_DAY, retentionDays: RETENTION_DAYS });
    store.save(fixtureManifest({ cohort: { id: "published-2026-10-20", count: 99 } }));
    const replay = resolveReplay(store, "2026-10-20", { asOfDate: "2026-10-25" });
    expect(replay.status).toBe("unavailable");
    if (replay.status === "unavailable") {
      expect(replay.reason).toMatch(/cohort|materialized/i);
    }
  });
});
