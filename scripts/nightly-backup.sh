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
#   ./scripts/nightly-backup.sh [backup-root] [retain-days] [--date YYYY-MM-DD] [--force]
#   The backup root must be absolute, must resolve to at least two path
#   components (so `/`, `/tmp` and `/backups` are refused), and is never a
#   system-wide target for the prune below.
#   The generation stamp defaults to today (UTC). `--date` targets another one,
#   which is how a failed night is rebuilt the next morning — the failure is
#   normally discovered after the date has rolled over.
# Verify an already stored generation (one throwaway container, no pruning):
#   ./scripts/nightly-backup.sh --verify ~/cve-backups/2026-11-08
#   Needs free temp space the size of the decompressed image (several GB), in
#   $TMPDIR or /tmp. Set TMPDIR to a roomier volume when /tmp is small.
#
# Idempotency and atomicity (why a re-run is always safe):
#   The generation is built in a sibling staging directory on the same
#   filesystem (`.staging-<stamp>-<pid>`), compressed with `gzip -f`, verified
#   with the same `verifyBackup()` the app uses, and only then published into
#   `<backup-root>/<stamp>/` with an atomic `mv`. A failed run never writes into
#   the day directory, never leaves a raw dump behind (the EXIT trap removes the
#   staging tree) and never writes the `backup-done` marker, which is the only
#   thing that marks a generation complete. Today's stamp is always rebuilt, so
#   a re-run after a failure succeeds and the scheduled run still takes a fresh
#   dump. A *past* generation that already verifies is only overwritten with
#   `--force`.
set -euo pipefail

fail() {
  echo "backup failed: generation ${STAMP:-unknown}: $*" >&2
  exit 1
}

sha256_of() {
  sha256sum -- "$1" | cut -d' ' -f1
}

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Temp directory for one verification; removed on success and on failure. It is
# only ever a `mktemp -d` path under this base, and the trap refuses to remove
# anything that is not one, so a future edit cannot turn cleanup into a broad
# delete.
VERIFY_TMP_BASE="${TMPDIR:-/tmp}"
VERIFY_TMP_BASE="${VERIFY_TMP_BASE%/}"
VERIFY_WORK=""
# The staging tree of the current attempt. Removed on success (emptied by the
# publish step) and on every failure path, so an aborted run cannot leave a
# multi-GB raw dump on the backup filesystem.
STAGE_DIR=""
cleanup_work() {
  case "${VERIFY_WORK:-}" in
    "$VERIFY_TMP_BASE"/cve-verify.*) rm -rf -- "$VERIFY_WORK" ;;
  esac
  # Guarded: only ever a `.staging-*` child of the backup root, so a future
  # edit cannot turn this cleanup into a broad delete.
  case "${STAGE_DIR:-}" in
    */.staging-*) rm -rf -- "$STAGE_DIR" ;;
  esac
}
# Loud failure: `set -e` aborts on the first failed command, and this trap names
# the generation in the log before exiting non-zero. No `backup-done` marker is
# ever written on this path (it is written after verification, see below).
on_err() {
  local status="${1:-1}"
  echo "backup failed: generation ${STAMP:-unknown} aborted at exit status $status; no backup-done marker written" >&2
  exit "$status"
}
trap cleanup_work EXIT
trap 'on_err "$?"' ERR

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
  # The stored archive is what cron kept; if a marker exists it must name those
  # exact bytes, otherwise the generation was replaced without a fresh marker.
  local stored_sha
  stored_sha="$(sha256_of "$gz")"
  local marker="$day_dir/backup-done"
  if [ -f "$marker" ]; then
    local recorded
    recorded="$(sed -n 's/^gzip_sha256=//p' "$marker" | head -n1)"
    if [ -n "$recorded" ] && [ "$stored_sha" != "$recorded" ]; then
      echo "verify failed: $marker records gzip sha256 $recorded but the stored archive is $stored_sha" >&2
      return 1
    fi
    echo "marker: $marker matches the stored archive (gzip sha256 $stored_sha)"
  else
    echo "note: no backup-done marker in $day_dir (generation predates the marker); the archive itself verified"
  fi
  printf '%s\n' "$out"
  echo "verified: $gz passed verifyBackup() against $manifest"
}

# Flags are stripped first so both `--force <root> <days>` and
# `<root> <days> --force` work, and `--date` can appear anywhere. `--date`
# takes the next argument or `--date=YYYY-MM-DD`.
FORCE=0
STAMP_ARG=""
PARSED_ARGS=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --force) FORCE=1 ;;
    --date)
      if [ "$#" -lt 2 ]; then
        echo "refusing: --date needs a YYYY-MM-DD value" >&2
        exit 2
      fi
      STAMP_ARG="$2"
      shift
      ;;
    --date=*) STAMP_ARG="${1#--date=}" ;;
    *) PARSED_ARGS+=("$1") ;;
  esac
  shift
done
set -- ${PARSED_ARGS[@]+"${PARSED_ARGS[@]}"}

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

STAMP="${STAMP_ARG:-$(date -u +%Y-%m-%d)}"
TODAY_STAMP="$(date -u +%Y-%m-%d)"
# The stamp names a directory that is later pruned, so validate it before it is
# used as a path component: a date-shaped value only, never `../` or a glob.
case "$STAMP" in
  [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]) ;;
  *)
    echo "refusing: --date must be YYYY-MM-DD, got '$STAMP'" >&2
    exit 2
    ;;
esac
if [ "$(date -u -d "$STAMP" +%Y-%m-%d 2>/dev/null)" != "$STAMP" ]; then
  echo "refusing: --date '$STAMP' is not a calendar date" >&2
  exit 2
fi
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

echo "=== backup start $(date -u +%FT%TZ) stamp=$STAMP retain_days=$RETAIN_DAYS force=$FORCE ==="
cd "$REPO_DIR"

# Today's stamp is always rebuilt: re-running after a failure must succeed, and
# the 02:00 scheduled run still has to take a fresh dump even when an operator
# already ran the script earlier in the day. A *past* stamp that already holds a
# verified generation is refused without --force, so a good historical backup is
# never overwritten by a typo. A marker that does not match its archive is never
# a verified generation: that is the state the old script left on failure, and it
# is rebuilt without ceremony.
if [ -f "$DAY_DIR/backup-done" ] && [ -f "$DAY_DIR/cve-backup.db.gz" ]; then
  recorded_sha="$(sed -n 's/^gzip_sha256=//p' "$DAY_DIR/backup-done" | head -n1)"
  if [ -n "$recorded_sha" ] && [ "$(sha256_of "$DAY_DIR/cve-backup.db.gz")" = "$recorded_sha" ]; then
    if [ "$STAMP" != "$TODAY_STAMP" ] && [ "$FORCE" -eq 0 ]; then
      echo "refusing: generation $STAMP is already verified (gzip sha256 $recorded_sha); pass --force to overwrite a verified generation" >&2
      exit 2
    fi
    echo "replacing verified generation $STAMP (gzip sha256 $recorded_sha) with a fresh dump"
  else
    echo "rebuilding: $DAY_DIR has a backup-done marker that does not match its archive"
  fi
else
  echo "building: no verified generation for $STAMP yet (no backup-done marker)"
fi

# Reclaim staging trees of interrupted runs (kill -9, power loss). Older than a
# day only, so a concurrent attempt is never touched.
echo "--- clearing staging directories from interrupted runs older than a day ---"
find "$BACKUP_ROOT" -maxdepth 1 -mindepth 1 -type d -name '.staging-*' -mtime +1 -print -exec rm -rf {} +

# Build the generation in a sibling staging directory on the same filesystem.
# Nothing is written into $DAY_DIR until the archive has passed verifyBackup(),
# so a failed run cannot damage an existing generation, and the name is unique
# per attempt so two overlapping runs cannot collide. The EXIT trap removes it.
STAGE_DIR="$BACKUP_ROOT/.staging-$STAMP-$$"
STAGE_NAME="$(basename -- "$STAGE_DIR")"
mkdir -p -- "$STAGE_DIR"
chmod 775 -- "$STAGE_DIR"
if command -v setfacl >/dev/null 2>&1; then
  setfacl -m u:1001:rwx "$STAGE_DIR" 2>/dev/null || true
  setfacl -d -m u:1001:rwx "$STAGE_DIR" 2>/dev/null || true
  setfacl -d -m "u:$(id -un):rwx" "$STAGE_DIR" 2>/dev/null || true
fi

# One-off container on the compose volume; overrides the entrypoint command
# so only the backup one-shot runs (no web server, no scheduler).
docker compose run --rm \
  -v "$BACKUP_ROOT:/backups" \
  -e RUN_BACKUP_ONCE=true \
  -e BACKUP_DIR="/backups/$STAGE_NAME" \
  app node worker.mjs

echo "--- compressing dump (measured ~10% of original size) ---"
if [ ! -f "$STAGE_DIR/cve-backup.db" ]; then
  fail "the container wrote no cve-backup.db in $STAGE_DIR"
fi
if [ ! -f "$STAGE_DIR/manifest.json" ]; then
  fail "the container wrote no manifest.json in $STAGE_DIR"
fi
# `-f`: replace a leftover archive instead of aborting with
# "already exists; not overwritten", which is the failure that wedged
# 2026-11-21 (the run stopped before its marker and re-running could never win).
gzip -3f -- "$STAGE_DIR/cve-backup.db"
gz_bytes="$(stat -c%s -- "$STAGE_DIR/cve-backup.db.gz")"
echo "compressed: $STAGE_DIR/cve-backup.db.gz $gz_bytes bytes"

echo "--- verifying the compressed archive with verifyBackup() ---"
verify_stored_backup "$STAGE_DIR"
gz_sha="$(sha256_of "$STAGE_DIR/cve-backup.db.gz")"

# Publish atomically: same filesystem, so each `mv` is a rename. The marker is
# written last, after both artifacts are in place — its presence is the only
# claim that this generation was verified.
echo "--- publishing generation $STAMP into $DAY_DIR ---"
mkdir -p -- "$DAY_DIR"
mv -f -- "$STAGE_DIR/cve-backup.db.gz" "$DAY_DIR/cve-backup.db.gz"
mv -f -- "$STAGE_DIR/manifest.json" "$DAY_DIR/manifest.json"
if [ -f "$DAY_DIR/cve-backup.db" ]; then
  echo "reclaiming stray uncompressed dump from an earlier failed run: $DAY_DIR/cve-backup.db ($(stat -c%s -- "$DAY_DIR/cve-backup.db") bytes)"
  rm -f -- "$DAY_DIR/cve-backup.db"
fi
if [ "$(sha256_of "$DAY_DIR/cve-backup.db.gz")" != "$gz_sha" ]; then
  fail "the published archive at $DAY_DIR/cve-backup.db.gz does not match the verified one ($gz_sha)"
fi
printf 'generation=%s\ngzip_sha256=%s\ngzip_bytes=%s\nstaging=%s\nverified_with=verifyBackup (RUN_VERIFY_ONCE)\nverified_at=%s\n' \
  "$STAMP" "$gz_sha" "$gz_bytes" "$STAGE_NAME" "$(date -u +%FT%TZ)" \
  >"$DAY_DIR/backup-done.tmp"
mv -f -- "$DAY_DIR/backup-done.tmp" "$DAY_DIR/backup-done"
echo "published: $DAY_DIR (gzip sha256 $gz_sha, $gz_bytes bytes)"

echo "--- pruning generations older than $RETAIN_DAYS days ---"
# Never prune through a path that is not a real directory: mkdir above should
# have made one, and this refuses a missing, unreadable or replaced path rather
# than letting `find` walk something unexpected.
if [ ! -d "$BACKUP_ROOT" ]; then
  echo "refusing to prune: $BACKUP_ROOT is not a directory" >&2
  exit 1
fi
find "$BACKUP_ROOT" -maxdepth 1 -mindepth 1 -type d -mtime +"$RETAIN_DAYS" -print -exec rm -rf {} +
echo "=== backup done $(date -u +%FT%TZ) stamp=$STAMP gzip_sha256=$gz_sha ==="
