// The series loader lives in `src/lib/epss-history.ts` so the AI tool layer can
// read it without importing route code. Re-exported here because this module is
// the EPSS-history API the routes and pages already import from.

export * from "../../../../src/lib/epss-history";
