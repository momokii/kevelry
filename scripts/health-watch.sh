#!/usr/bin/env bash
# Health watch for a running Kevelry instance.
#
# Polls the versioned health endpoint and exits non-zero when the instance is
# unreachable, reports a non-ok status, or has a source that is stale or failed.
# Designed for cron: cron mails the output of a job that exits non-zero, so the
# only thing this script prints on failure is the reason.
#
# Install (host):
#   (crontab -l 2>/dev/null; echo "*/15 * * * * /path/to/repo/scripts/health-watch.sh http://127.0.0.1:3100") | crontab -
#
# Manual:
#   ./scripts/health-watch.sh [base-url] [--verbose]
set -euo pipefail

BASE_URL="${1:-http://127.0.0.1:3100}"
VERBOSE="${2:-}"
URL="${BASE_URL%/}/api/v1/health"

if ! command -v node >/dev/null 2>&1; then
  echo "health-watch: node is required to parse the JSON response" >&2
  exit 3
fi

# curl keeps the failure mode simple (timeouts, TLS, redirects); node parses.
if ! BODY="$(curl -fsS --max-time 20 -H 'accept: application/json' "$URL" 2>/dev/null)"; then
  echo "health-watch: ${URL} is unreachable or returned an error status"
  exit 2
fi

REPORT="$(printf '%s' "$BODY" | node --input-type=module -e '
const chunks = [];
process.stdin.on("data", (chunk) => chunks.push(chunk));
process.stdin.on("end", () => {
  let body;
  try {
    body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    console.log("bad-json");
    process.exit(0);
  }
  if (body.status !== "ok") {
    console.log(`status=${body.status}`);
    process.exit(0);
  }
  const problems = [];
  for (const [name, source] of Object.entries(body.sources ?? {})) {
    if (source.error !== null && source.error !== undefined) problems.push(`${name}: error ${source.error}`);
    else if (source.stale === true) problems.push(`${name}: stale`);
  }
  console.log(problems.length === 0 ? "ok" : problems.join("; "));
});
')"

if [ "$REPORT" = "ok" ]; then
  if [ "$VERBOSE" = "--verbose" ]; then
    echo "health-watch: ok (${URL})"
  fi
  exit 0
fi

echo "health-watch: ${URL}: ${REPORT}"
exit 1
