# Atom 1.0 feed: what RFC 4287 requires

Reference note for `GET /api/v1/radar/feed.atom` (v3 epic E5). Normative source:
[RFC 4287 — The Atom Syndication Format](https://www.rfc-editor.org/rfc/rfc4287.txt).
Section numbers below are that RFC's.

## Document shape

- The root element is `atom:feed` in the namespace
  `http://www.w3.org/2005/Atom` (§4.1.1). Atom documents are well-formed XML
  serialized as XML 1.0 and are identified with the `application/atom+xml`
  media type (§2).
- A feed **MUST** contain exactly one `atom:id`, one `atom:title`, and one
  `atom:updated`, and **MUST** contain one or more `atom:author` elements
  unless every child `atom:entry` carries its own `atom:author` (§4.1.1).
  We put one feed-level `atom:author` with a `name` (site name, never a
  person) so entries need no author of their own.
- An entry **MUST** contain exactly one `atom:id`, one `atom:title`, and one
  `atom:updated` (§4.1.2). `atom:content` is optional; an entry without it
  **MUST** carry at least one `atom:link` with `rel="alternate"` (§4.1.2).
  `atom:summary` carries the human-readable text our feed emits, so the
  alternate link points at the canonical cve.org record.
- `atom:feed` **SHOULD** carry one `atom:link` with `rel="self"` — the
  preferred URI for retrieving this feed (§4.1.1). Its `type` is
  `application/atom+xml` (§4.2.7). We also emit `rel="alternate"` with
  `type="application/json"` for the JSON change feed.
- Text constructs (`atom:title`, `atom:summary`, `atom:subtitle`) **MAY** carry
  a `type` attribute; when present it must be `text`, `html`, or `xhtml`, and
  absent means `text` (§3.1.1). Ours are `type="text"` and XML-escaped, so no
  markup is ever implied.

## Identifiers

- `atom:id` content **MUST** be an IRI and **MUST NOT** be a relative
  reference: it is never resolved against a base URI (§4.2.6). It also must
  not change across relocation, syndication, or reformatting (§4.2.6), which
  is why our feed id is the feed's own absolute URL and our entry ids are the
  same stable `eventId` values RSS publishes as `<guid>`.
- Conformance note: our `eventId` values (`radar-YYYY-MM-DD-NNNN`) are opaque
  stable identifiers shared with the RSS `<guid>`, not IRIs. The cross-format
  identity is deliberate; promoting them to `urn:` IRIs would change the
  already-published JSON API's `eventId`, so the deviation is documented
  rather than silently "fixed" per format. Feed ids, which we control, are
  absolute URLs (falling back to the fixed `urn:cve-radar:feed:change-radar`
  when no public origin is resolvable).

## Dates and links

- Date constructs (`atom:updated`) **MUST** conform to RFC 3339's `date-time`
  production, with an uppercase `T` and an uppercase `Z` when no numeric
  offset is present (§3.3). RFC 822/1123 dates (`Sat, 24 Oct 2026 …`) are not
  acceptable in Atom, even though RSS uses them.
- Link attributes: `href` is required, `rel` defaults to `alternate`, and
  `type` is an advisory media type (§4.2.7). Relative `href` values are
  resolved against the document's base URI, so ours are absolute for the
  self/alternate links; entry links are absolute cve.org URLs.

## What this feed therefore emits

Feed: `id` (absolute feed URL), `title`, `subtitle` (the retention-window
provenance text RSS puts in `<description>`), `updated` (newest checkpoint
instant, RFC 3339), `author/name`, `link rel="self"` +
`link rel="alternate"`, `generator`. Entries: `id` (= RSS `<guid>`),
`title type="text"` (`<cveId> — <kind>`), `updated` (`observedAt`, RFC 3339),
`summary type="text"` (diff lines, reason, source revision), and
`link rel="alternate"` to the canonical cve.org record. Absolute links are
omitted, exactly as in RSS, when `resolvePublicBaseUrl` reports that the public
origin is unknown.
