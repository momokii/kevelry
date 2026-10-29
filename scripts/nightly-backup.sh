#!/usr/bin/env bash
# Nightly verified backup of the live CVE volume.
#
# Runs the hash-verified backup path inside a one-off container on the same
# named volume (the running worker is never disturbed), then prunes backup
# generations older than the retention window. Every run appends to
# BACKUP_ROOT/backup-cron.log; failures exit non-zero so cron mails them.
#
# Install (host, from the repo root):
#   (crontab -l 2>/dev/null; echo "0 2 * * * /home/kelanach/Public/main-linux-kelanach/code-berkah-titipan-tuhan/code/personal_prjct/cybersec/cve-injector/scripts/nightly-backup.sh") | crontab -
#
# Manual run:
#   ./scripts/nightly-backup.sh [backup-root] [retain-days]
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKUP_ROOT="${1:-$HOME/cve-backups}"
RETAIN_DAYS="${2:-7}"
STAMP="$(date -u +%Y-%m-%d)"
DAY_DIR="$BACKUP_ROOT/$STAMP"
LOG="$BACKUP_ROOT/backup-cron.log"

mkdir -p "$BACKUP_ROOT"
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

echo "--- pruning generations older than $RETAIN_DAYS days ---"
find "$BACKUP_ROOT" -maxdepth 1 -mindepth 1 -type d -mtime +"$RETAIN_DAYS" -print -exec rm -rf {} +
echo "=== backup done $(date -u +%FT%TZ) ==="
