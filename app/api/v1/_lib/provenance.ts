// Route-layer alias for the provenance envelope.
//
// The shape and its builder live in `src/lib/provenance.ts`: component loaders
// render the envelope, and component code must import from `src/lib`, never
// from `app`. Everything is re-exported here so a route keeps reading its own
// `_lib` and a test can still import `buildProvenance` from the route layer.
export {
  buildProvenance,
  RANKING_POLICY_VERSION,
  type Provenance,
  type SourceProvenance,
} from "../../../../src/lib/provenance";
