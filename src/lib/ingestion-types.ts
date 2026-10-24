// Minimal stub types for ingestion contract tests (plan todo 5).
//
// This module carries types only: no network fetching, no upstream clones, no
// importer logic. The stub importer behavior asserted by
// tests/contracts/ingestion.test.ts lives inside that test file so the real
// importers (plan todos 8-10) can later satisfy the same contracts.

export type CveRecordState = "PUBLISHED" | "REJECTED";

export const SUPPORTED_CVE_DATA_VERSIONS: readonly string[] = ["5.0", "5.1"];

export interface StubCveRecord {
  cveId: string;
  dataVersion: string;
  state: CveRecordState;
  datePublished?: string;
  dateUpdated?: string;
}

export interface StubKevEntry {
  cveId: string;
  dateAdded: string;
}

export interface StubEpssRow {
  cveId: string;
  epss: number;
  percentile: number;
}

export type IngestionSourceName = "cve" | "kev" | "epss";

export interface StubQuarantineEntry {
  source: IngestionSourceName;
  reason: string;
  identifier: string;
}

export interface StubPublicationManifest {
  cveRevision: string | null;
  kevVersion: string | null;
  epssDate: string | null;
}
