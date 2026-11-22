#!/usr/bin/env bash
# Backup freshness and integrity check — makes a silent backup failure loud.
#
# Why this exists: the nightly job writes to ~/cve-backups/backup-cron.log and
# only mails on a non-zero exit. A night where cron never ran, or a run that died
# without leaving the evidence anyone reads, stays invisible: the 2026-11-21
# failure went unnoticed for a day. This script asserts the outcome from the
# outside — a marker, an artifact and a hash that agree — so absence of evidence
# is itself a failure.
#
# Four assertions, one PASS/FAIL line each:
#   1. freshness   the newest `backup-done` marker is at most MAX_AGE_HOURS old.
#                  Cron runs at 02:00 daily; 36h tolerates one missed night and
#                  flags two.
#   2. integrity   the archive beside that marker is non-empty and its gzip
#                  sha256 (and byte count) match what that generation recorded.
#                  This is the same comparison `nightly-backup.sh` makes (see
#                  verify_stored_backup there; keep the two in step). The gzip
#                  hash lives in `backup-done`, not in `manifest.json` — the
#                  manifest records the *decompressed* database sha256, so a
#                  gzip hash cannot be compared against it. The manifest is
#                  checked for presence and a `dbSha256` entry, and `--deep`
#                  streams `gzip -dc | sha256sum` and compares the result to the
#                  manifest's `dbSha256` (what verifyBackup() checks, without the
#                  container and without a multi-GB temp copy).
#   3. no raw dump no generation holds an uncompressed `cve-backup.db`. That
#                  leftover is what hid the 2026-11-21 break: a raw dump looked
#                  like a backup, and every re-run failed the same way.
#   4. retention   the newest *verified* generation is inside the retention
#                  window, i.e. at least one restorable point still exists.
#
# Exit codes (same contract as scripts/health-watch.sh, so one external monitor
# can watch both): 0 = healthy, 1 = unhealthy, 2 = usage or config error.
# No network calls, Docker, or writes: this only reads the backup root.
#
# Environment overrides (absolute root, positive integers):
#   BACKUP_ROOT   default ~/cve-backups
#   MAX_AGE_HOURS default 36
#   RETAIN_DAYS   default 7 — must match the retention argument the cron runs
#                 nightly-backup.sh with, otherwise this check and the pruner
#                 disagree about how much history should exist.
# They exist so the failure path can be proven against a fake root, never the
# real backups:
#   BACKUP_ROOT=/tmp/fake-backups ./scripts/backup-check.sh
#
# Manual:
#   ./scripts/backup-check.sh [--deep] [--help]
#
# Install (host, from the repo root): runs after the 02:00 backup window, so a
# failed or missing night is recorded with a timestamp instead of only mailing:
#   (crontab -l 2>/dev/null; echo "0 3 * * * <repo>/scripts/backup-check.sh >> ~/cve-backups/check.log 2>&1") | crontab -
set -euo pipefail

BACKUP_ROOT="${BACKUP_ROOT-$HOME/cve-backups}"
MAX_AGE_HOURS="${MAX_AGE_HOURS-36}"
RETAIN_DAYS="${RETAIN_DAYS-7}"
DEEP=0

usage() {
  echo "usage: $0 [--deep]   (env: BACKUP_ROOT, MAX_AGE_HOURS, RETAIN_DAYS)" >&2
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --deep) DEEP=1 ;;
    -h | --help)
      sed -n '2,50p' "$0"
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
  shift
done

TS="$(date -u +%FT%TZ)"
now_epoch="$(date +%s)"
fail_count=0

say() { printf '%s %s\n' "$TS" "$*"; }
fail() {
  say "FAIL  $*"
  fail_count=$((fail_count + 1))
}
pass() { say "PASS  $*"; }

# --- configuration guards (exit 2, never a check result) ---------------------
for pair in "MAX_AGE_HOURS:$MAX_AGE_HOURS" "RETAIN_DAYS:$RETAIN_DAYS"; do
  name="${pair%%:*}"
  value="${pair#*:}"
  case "$value" in
    '' | *[!0-9]*)
      echo "config error: $name must be a positive integer, got '$value'" >&2
      exit 2
      ;;
  esac
  if [ "$value" -le 0 ]; then
    echo "config error: $name must be greater than 0, got '$value'" >&2
    exit 2
  fi
done
if [ -z "${BACKUP_ROOT//[[:space:]]/}" ]; then
  echo "config error: BACKUP_ROOT is empty" >&2
  exit 2
fi
case "$BACKUP_ROOT" in
  /*) ;;
  *)
    echo "config error: BACKUP_ROOT must be an absolute path, got '$BACKUP_ROOT'" >&2
    exit 2
    ;;
esac
BACKUP_ROOT="$(readlink -m -- "$BACKUP_ROOT")"
if [ "$BACKUP_ROOT" = "/" ]; then
  echo "config error: BACKUP_ROOT resolves to '/', which is not a backup root" >&2
  exit 2
fi
case "$BACKUP_ROOT" in
  /*/*) ;;
  *)
    echo "config error: BACKUP_ROOT needs at least two path components, got '$BACKUP_ROOT'" >&2
    exit 2
    ;;
esac

gzip_sha256() { sha256sum -- "$1" | cut -d' ' -f1; }
marker_field() { sed -n "s/^$2=//p" "$1" | head -n1; }

# A missing root is not a config error: it is the loudest possible "there are no
# backups". Report it as unhealthy so a monitor alarms, and skip the checks.
if [ ! -d "$BACKUP_ROOT" ]; then
  say "FAIL  backup root: $BACKUP_ROOT does not exist — no backup has ever landed there"
  say "VERDICT: UNHEALTHY (backup root missing; the four checks could not run)"
  exit 1
fi

# Generation directories, newest name first. `.staging-*` trees are in-flight
# builds, not generations, and the leading dot keeps them out of the glob too.
generations() {
  find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d -not -name '.staging-*' -print | sort -r
}

gen_count=0
newest_dir=""
newest_marker=""
newest_mtime=0
while IFS= read -r dir; do
  gen_count=$((gen_count + 1))
  marker="$dir/backup-done"
  [ -f "$marker" ] || continue
  mtime="$(stat -c %Y -- "$marker")"
  if [ "$mtime" -gt "$newest_mtime" ]; then
    newest_mtime="$mtime"
    newest_marker="$marker"
    newest_dir="$dir"
  fi
done < <(generations)

# 1. freshness ---------------------------------------------------------------
if [ -z "$newest_marker" ]; then
  fail "freshness: no backup-done marker under $BACKUP_ROOT ($gen_count generation director(ies) present) — nothing claims to be a complete backup"
else
  age_seconds=$((now_epoch - newest_mtime))
  age_hours=$((age_seconds / 3600))
  verified_at="$(marker_field "$newest_marker" verified_at)"
  if [ "$age_seconds" -le $((MAX_AGE_HOURS * 3600)) ]; then
    pass "freshness: newest backup-done is ${newest_dir##*/} (age ${age_hours}h, limit ${MAX_AGE_HOURS}h${verified_at:+, verified_at $verified_at})"
  else
    fail "freshness: newest backup-done is ${newest_dir##*/} (age ${age_hours}h, limit ${MAX_AGE_HOURS}h) — the nightly backup has not completed; check $BACKUP_ROOT/backup-cron.log"
  fi
fi

# 2. integrity ---------------------------------------------------------------
if [ -z "$newest_marker" ]; then
  fail "integrity: nothing to verify — no generation has a backup-done marker"
else
  gz="$newest_dir/cve-backup.db.gz"
  manifest="$newest_dir/manifest.json"
  problem=""
  recorded_sha="$(marker_field "$newest_marker" gzip_sha256)"
  recorded_bytes="$(marker_field "$newest_marker" gzip_bytes)"
  recorded_gen="$(marker_field "$newest_marker" generation)"

  if [ ! -f "$gz" ]; then
    problem="no archive at $gz"
  elif [ ! -s "$gz" ]; then
    problem="archive is empty: $gz (0 bytes)"
  elif [ -n "$recorded_gen" ] && [ "$recorded_gen" != "${newest_dir##*/}" ]; then
    problem="backup-done says generation=$recorded_gen but it sits in ${newest_dir##*/}"
  elif [ -z "$recorded_sha" ]; then
    problem="backup-done records no gzip_sha256, so the archive is unverified"
  else
    actual_sha="$(gzip_sha256 "$gz")"
    actual_bytes="$(stat -c %s -- "$gz")"
    if [ "$actual_sha" != "$recorded_sha" ]; then
      problem="gzip sha256 is $actual_sha but backup-done records $recorded_sha — the archive was replaced or is damaged"
    elif [ -n "$recorded_bytes" ] && [ "$actual_bytes" != "$recorded_bytes" ]; then
      problem="archive is $actual_bytes bytes but backup-done records $recorded_bytes"
    elif [ ! -f "$manifest" ]; then
      problem="no manifest.json beside the archive"
    elif ! grep -Eq '"dbSha256"[[:space:]]*:[[:space:]]*"[0-9a-fA-F]{64}"' "$manifest"; then
      problem="manifest.json has no 64-hex dbSha256 entry"
    elif [ "$DEEP" -eq 1 ]; then
      expected_db_sha="$(sed -n 's/.*"dbSha256"[[:space:]]*:[[:space:]]*"\([0-9a-fA-F]\{64\}\)".*/\1/p' "$manifest" | head -n1)"
      if ! actual_db_sha="$(gzip -dc -- "$gz" | sha256sum | cut -d' ' -f1)"; then
        problem="$gz is not a readable gzip stream"
      elif [ "$actual_db_sha" != "$expected_db_sha" ]; then
        problem="decompressed db sha256 is $actual_db_sha but manifest.json records $expected_db_sha"
      fi
    fi
  fi

  if [ -n "$problem" ]; then
    fail "integrity: ${newest_dir##*/}: $problem"
  else
    deep_note=""
    [ "$DEEP" -eq 1 ] && deep_note="; decompressed db sha256 matches manifest.json"
    pass "integrity: ${newest_dir##*/}: gzip sha256 ${recorded_sha} and ${recorded_bytes:-$actual_bytes} bytes match backup-done, manifest.json present${deep_note}"
  fi
fi

# 3. no raw dump -------------------------------------------------------------
raw_dumps=()
while IFS= read -r raw; do
  raw_dumps+=("$raw")
done < <(find "$BACKUP_ROOT" -mindepth 2 -maxdepth 2 -type f -name 'cve-backup.db' -print | sort)
if [ "${#raw_dumps[@]}" -eq 0 ]; then
  pass "no raw dump: no uncompressed cve-backup.db in any of $gen_count generation(s)"
else
  fail "no raw dump: uncompressed cve-backup.db found at ${raw_dumps[*]} — a raw dump is not a verified backup, and leaving one behind is what hid the 2026-11-21 failure"
fi

# 4. retention ---------------------------------------------------------------
# A generation counts as restorable when its marker and archive agree; that is
# the same pair of facts the nightly script refuses to overwrite. Hashing is
# skipped for the newest generation only when it is also the one check 2 already
# hashed, which is the common case.
newest_verified=""
newest_verified_mtime=0
while IFS= read -r dir; do
  marker="$dir/backup-done"
  gz="$dir/cve-backup.db.gz"
  [ -f "$marker" ] && [ -s "$gz" ] || continue
  recorded_sha="$(marker_field "$marker" gzip_sha256)"
  [ -n "$recorded_sha" ] || continue
  if [ "$dir" = "$newest_dir" ] && [ -n "${actual_sha:-}" ]; then
    [ "$actual_sha" = "$recorded_sha" ] || continue
  else
    [ "$(gzip_sha256 "$gz")" = "$recorded_sha" ] || continue
  fi
  newest_verified="$dir"
  newest_verified_mtime="$(stat -c %Y -- "$marker")"
  break
done < <(generations)

if [ -z "$newest_verified" ]; then
  fail "retention: no generation is verified (marker and archive agree), so nothing is restorable"
else
  verified_age_hours=$(((now_epoch - newest_verified_mtime) / 3600))
  if [ "$verified_age_hours" -le $((RETAIN_DAYS * 24)) ]; then
    pass "retention: newest verified generation is ${newest_verified##*/} (age ${verified_age_hours}h, window ${RETAIN_DAYS}d)"
  else
    fail "retention: newest verified generation is ${newest_verified##*/} (age ${verified_age_hours}h) — outside the ${RETAIN_DAYS}-day window, so nothing restorable is left"
  fi
fi

# verdict --------------------------------------------------------------------
if [ "$fail_count" -eq 0 ]; then
  say "VERDICT: HEALTHY (4/4 checks passed, root $BACKUP_ROOT)"
  exit 0
fi
say "VERDICT: UNHEALTHY ($fail_count of 4 checks failed, root $BACKUP_ROOT)"
exit 1
