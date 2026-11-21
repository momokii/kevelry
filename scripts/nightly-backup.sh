#!/usr/bin/env bash
# Nightly verified backup of the live CVE volume.
#
# Runs the hash-verified backup path inside a one-off container on the same
# named volume (the running worker is never disturbed), verifies the stored
# gzip against the manifest it was built with, then prunes backup generations
# older than the retention window. Verification runs twice: before compression
# inside the container, and again on the stored artifact — the gzip is
# decompressed into a throwaway directory and handed to the same
# `verifyBackup()` (SHA-256 + schema versions + row counts) the backup path
# runs. Every run appends to BACKUP_ROOT/backup-cron.log; failures exit
# non-zero so cron mails them.
#
# Install (host, from the repo root):
#   (crontab -l 2>/dev/null; echo "0 2 * * * /home/kelanach/Public/main-linux-kelanach/code-berkah-titipan-tuhan/code/personal_prjct/cybersec/cve-injector/scripts/nightly-backup.sh") | crontab -
#
# Manual run:
#   ./scripts/nightly-backup.sh [backup-root] [retain-days]
#   The backup root must be absolute, must resolve to at least two path
#   components (so `/`, `/tmp` and `/backups` are refused), and is never a
#   system-wide target for the prune below.
# Verify an already stored generation (one throwaway container, no pruning):
#   ./scripts/nightly-backup.sh --verify ~/cve-backups/2026-11-08
#   Needs free temp space the size of the decompressed image (several GB), in
#   $TMPDIR or /tmp. Set TMPDIR to a roomier volume when /tmp is small.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Temp directory for one verification; removed on success and on failure. It is
# only ever a `mktemp -d` path under this base, and the trap refuses to remove
# anything that is not one, so a future edit cannot turn cleanup into a broad
# delete.
VERIFY_TMP_BASE="${TMPDIR:-/tmp}"
VERIFY_TMP_BASE="${VERIFY_TMP_BASE%/}"
VERIFY_WORK=""
cleanup_verify_work() {
  case "$VERIFY_WORK" in
    "$VERIFY_TMP_BASE"/cve-verify.*) rm -rf -- "$VERIFY_WORK" ;;
  esac
}
trap cleanup_verify_work EXIT

# Re-verify one stored generation with the container's own `verifyBackup()`:
# decompress the gzip into a temp directory next to its manifest, run the
# one-off `RUN_VERIFY_ONCE` worker branch against it, then delete the temp
# directory. This checks the artifact cron actually kept, not just the file
# before compression, and it is the same verifier — hash, schema, row counts —
# so the two checks cannot drift apart.
verify_stored_backup() {
  local day_dir="${1:-}"
  if [ -z "$day_dir" ]; then
    echo "usage: $0 --verify <backup-dir>" >&2
    return 2
  fi
  if [ ! -d "$day_dir" ]; then
    echo "verify failed: not a directory: $day_dir" >&2
    return 1
  fi
  local gz="$day_dir/cve-backup.db.gz"
  local manifest="$day_dir/manifest.json"
  local out
  if [ ! -f "$gz" ]; then
    echo "verify failed: no gzip artifact at $gz" >&2
    return 1
  fi
  if [ ! -f "$manifest" ]; then
    echo "verify failed: no manifest at $manifest" >&2
    return 1
  fi

  # Fail closed on an image that predates this branch: without it the worker
  # would ignore RUN_VERIFY_ONCE and start a real import cycle against the live
  # volume. One cheap container checks the bundle before anything else runs.
  if ! (cd "$REPO_DIR" && docker compose run --rm -T --entrypoint sh app \
    -c 'grep -q RUN_VERIFY_ONCE worker.mjs' >/dev/null 2>&1); then
    echo "verify failed: this app image has no RUN_VERIFY_ONCE branch; rebuild it (docker compose build app) so a stored backup can be verified" >&2
    return 1
  fi

  VERIFY_WORK="$(mktemp -d "$VERIFY_TMP_BASE/cve-verify.XXXXXX")"
  # The container runs as uid 1001, so the host-created temp dir must be
  # readable by it.
  chmod 755 -- "$VERIFY_WORK"
  if ! gzip -dc -- "$gz" > "$VERIFY_WORK/cve-backup.db"; then
    echo "verify failed: $gz is not a readable gzip stream" >&2
    return 1
  fi
  if ! cp -- "$manifest" "$VERIFY_WORK/manifest.json"; then
    echo "verify failed: cannot stage $manifest for the verifier" >&2
    return 1
  fi
  chmod 644 -- "$VERIFY_WORK/cve-backup.db" "$VERIFY_WORK/manifest.json" 2>/dev/null || true

  if ! out="$(
    cd "$REPO_DIR" &&
      timeout 1800 docker compose run --rm -T \
        -v "$VERIFY_WORK:/verify" \
        -e RUN_VERIFY_ONCE=true \
        -e VERIFY_DIR=/verify \
        app node worker.mjs 2>&1
  )"; then
    echo "verify failed: $gz did not pass verifyBackup() (hash, schema or row counts)" >&2
    printf '%s\n' "$out" >&2
    return 1
  fi
  printf '%s\n' "$out"
  echo "verified: $gz passed verifyBackup() against $manifest"
}

if [ "${1:-}" = "--verify" ]; then
  shift
  # Terminal in both directions: a failed check exits non-zero via `set -e`
  # (cron sees the failure, nothing is pruned), and a successful one exits 0.
  # Without the `exit 0` a verified backup would fall through into the backup
  # path with the verified directory as BACKUP_ROOT.
  verify_stored_backup "${1:-}"
  exit 0
fi

# `-` not `:-`: an explicitly passed empty argument is a mistake, and the guard
# below must see it instead of silently falling back to the default.
BACKUP_ROOT="${1-$HOME/cve-backups}"
RETAIN_DAYS="${2-7}"

# Guard the operator-supplied root before anything touches the filesystem. The
# prune step below deletes directories under it, so an empty, relative, shallow
# or "/" value must fail loudly rather than turn into a broad `rm -rf`. Checked
# before `mkdir`, the log redirect and the container mount, and never prompted
# (this runs unattended from cron).
if [ -z "${BACKUP_ROOT//[[:space:]]/}" ]; then
  echo "refusing: backup root is empty; pass an absolute path" >&2
  exit 2
fi
case "$BACKUP_ROOT" in
  /*) ;;
  *)
    echo "refusing: backup root must be an absolute path, got '$BACKUP_ROOT'" >&2
    exit 2
    ;;
esac
BACKUP_ROOT="$(readlink -m -- "$BACKUP_ROOT")"
if [ "$BACKUP_ROOT" = "/" ]; then
  echo "refusing: backup root resolves to '/', which would prune system directories" >&2
  exit 2
fi
case "$BACKUP_ROOT" in
  /*/*) ;;
  *)
    echo "refusing: backup root needs at least two path components, got '$BACKUP_ROOT'" >&2
    exit 2
    ;;
esac

STAMP="$(date -u +%Y-%m-%d)"
DAY_DIR="$BACKUP_ROOT/$STAMP"
LOG="$BACKUP_ROOT/backup-cron.log"

mkdir -p "$BACKUP_ROOT"
# The backup container runs as non-root uid 1001 while this script (and the
# prune step) runs as the host user: grant both standing access so neither
# side can lock the other out. No-op when ACLs are unavailable.
if command -v setfacl >/dev/null 2>&1; then
  setfacl -m u:1001:rwx "$BACKUP_ROOT" 2>/dev/null || true
  setfacl -d -m u:1001:rwx "$BACKUP_ROOT" 2>/dev/null || true
  setfacl -d -m "u:$(id -un):rwx" "$BACKUP_ROOT" 2>/dev/null || true
fi
exec >>"$LOG" 2>&1

echo "=== backup start $(date -u +%FT%TZ) stamp=$STAMP retain_days=$RETAIN_DAYS ==="
cd "$REPO_DIR"

# One-off container on the compose volume; overrides the entrypoint command
# so only the backup one-shot runs (no web server, no scheduler).
docker compose run --rm \
  -v "$BACKUP_ROOT:/backups" \
  -e RUN_BACKUP_ONCE=true \
  -e BACKUP_DIR="/backups/$STAMP" \
  app node worker.mjs

echo "--- compressing dump (measured ~10% of original size) ---"
if [ ! -f "$DAY_DIR/cve-backup.db" ]; then
  echo "backup failed: the container wrote no $DAY_DIR/cve-backup.db" >&2
  exit 1
fi
gzip -3 "$DAY_DIR/cve-backup.db"
echo "compressed: $DAY_DIR/cve-backup.db.gz $(stat -c%s "$DAY_DIR/cve-backup.db.gz") bytes"

echo "--- verifying the stored gzip with verifyBackup() ---"
verify_stored_backup "$DAY_DIR"

echo "--- pruning generations older than $RETAIN_DAYS days ---"
# Never prune through a path that is not a real directory: mkdir above should
# have made one, and this refuses a missing, unreadable or replaced path rather
# than letting `find` walk something unexpected.
if [ ! -d "$BACKUP_ROOT" ]; then
  echo "refusing to prune: $BACKUP_ROOT is not a directory" >&2
  exit 1
fi
find "$BACKUP_ROOT" -maxdepth 1 -mindepth 1 -type d -mtime +"$RETAIN_DAYS" -print -exec rm -rf {} +
echo "=== backup done $(date -u +%FT%TZ) ==="
