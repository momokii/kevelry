# Backup, Restore, and Upgrade Runbook

Backup is database-consistent: the app TRUNCATE-checkpoints the WAL, then
copies the image with `VACUUM INTO` on the open handle. **Never back up by
copying the live `cve.db` file** — a raw copy of a written database is not
a valid backup. Histories (`kev_history`, `sync_runs`), retained Radar
checkpoints, baseline refs, tombstones, and manifests travel inside the
backup image plus a `manifest.json` sidecar.

## Size and time are bounded by the retention window

The backup size is dominated by `cve_records` (~3.9 GB at the current 402k
corpus) plus the EPSS history window. `EPSS_RETENTION_DAYS` (default 45) is what
keeps the second term predictable: ~400k rows and ~40 MB with indexes per day
after the 008 slimming, so 45 days is roughly 18M rows / 1.8 GB. Lowering the window shortens both the backup image
and the nightly hashing time; it does not shrink the live database file (freed
pages are reused, see `DATA_WORKFLOW.md`).

## Restore drill (rehearsed 2026-11-08)

A restore is only a backup once it has been restored. The drill runs against a
throwaway named volume, never the production one:

```bash
# 1. Fresh, verified backup (host cron does this nightly at 02:00)
./scripts/nightly-backup.sh /tmp/drill-backups 1
mkdir -p /tmp/drill-restore
gunzip -c /tmp/drill-backups/<date>/cve-backup.db.gz > /tmp/drill-restore/cve-backup.db
cp /tmp/drill-backups/<date>/manifest.json /tmp/drill-restore/manifest.json

# 2. Restore into a separate volume (verifies hashes + schema compatibility)
docker volume create cve-drill
docker compose run --rm -v /tmp/drill-restore:/backups -v cve-drill:/data \
  -e RUN_RESTORE_ONCE=true -e RESTORE_DIR=/backups -e INGEST_ON_START=false \
  app node worker.mjs        # logs {"event":"restore-done", rowCounts:{...}}

# 3. Serve from the restored volume and check it (read-only, no scheduler)
docker run -d --name cve-drill-app -p 127.0.0.1:3101:3000 -v cve-drill:/data \
  -e APP_ENV=production -e NODE_ENV=production -e PORT=3000 -e DATA_DIR=/data \
  -e SCHEDULE_ENABLED=false -e INGEST_ON_START=false cve-change-radar:local
curl -fsS http://127.0.0.1:3101/api/v1/health

# 4. Tear down
docker stop cve-drill-app && docker rm cve-drill-app && docker volume rm cve-drill
rm -rf /tmp/drill-restore /tmp/drill-backups
```

Result of the 2026-11-08 rehearsal: `restore-done` reported
`schema_migrations: 7, cve_records: 402045, cvss_metrics: 294739,
epss_daily: 5585191, kev_entries: 1769, cve_tombstones: 19141`; the app served
`/`, `/explore`, `/priority` and `/methodology` from the restored volume
(200s), `/api/v1/health` reported `status: ok` with all four sources current, and
the first filtered Explore request cost 33 s on the cold volume (0.05 s warm) —
expected page-cache effects, not a data problem.

## Procedures (see `src/lib/backup.ts`)

- **Back up:** `createBackup({ dataDir, backupDir })`. Staged as `*.tmp`,
  hash-verified, then promoted. `*.tmp` files alone are never a backup.
- **Verify:** `verifyBackup({ backupDir })` — hash match, readable schema,
  row counts agree.
- **Restore into a fresh volume:** `restoreBackup({ backupDir, dataDir })`.
  Forward migrations apply on open.
- **Pre-upgrade:** `preUpgradeBackup({ dataDir, backupDir })`. Keep the
  backup until the upgraded app passes health/readiness checks.
- **Roll back:** `rollbackUpgrade({ backupDir, dataDir, preRestoreBackupDir })`.

## Nightly automation (host cron)

`scripts/nightly-backup.sh` runs the same verified path on a schedule:
a one-off container on the compose volume executes the `RUN_BACKUP_ONCE`
worker branch (create + verify `cve-backup.db` against `manifest.json`, never an
import cycle). Verification happens twice, deliberately:

1. **Before compression, inside the container.** `verifyBackup()` checks the
   database SHA-256 against the manifest, opens the schema read-only and compares
   every row count. This is what proves the image is a usable backup.
2. **After compression, on the stored artifact.** The script decompresses
   `cve-backup.db.gz` into a `mktemp -d` directory beside a copy of
   `manifest.json`, mounts that directory at `/verify` in a one-off container, and
   runs the same `verifyBackup()` through the `RUN_VERIFY_ONCE` worker branch
   (`RUN_VERIFY_ONCE=true VERIFY_DIR=/verify node worker.mjs`). The temp directory
   is deleted afterwards, on success and on failure. Because it is the same
   function the backup path runs, the two checks cannot drift apart, and a
   truncated or corrupted gzip fails while decompressing. This step reads and
   re-hashes the whole image, so it needs free temp space the size of the
   decompressed database (several GB — point `TMPDIR` at a roomy volume when
   `/tmp` is small) and takes minutes on a multi-GB backup. A failure exits
   non-zero, cron mails it, and pruning is skipped.

The verify branch must exist in the app image, which is the image that wrote the
backup: after pulling this code, rebuild once (`docker compose build app`) as
part of the normal upgrade. The script checks the image bundle for the branch and
refuses with an explicit message instead of running an older worker that would
start an import cycle.

Generations older than 7 days are pruned only after both checks pass, and only
through a path that still exists and is a directory. Install from the repo root:

```bash
(crontab -l 2>/dev/null; echo "0 2 * * * <repo>/scripts/nightly-backup.sh") | crontab -
```

Backups land in `~/cve-backups/<UTC date>/` with `backup-cron.log` beside
them. A non-zero exit means cron mails the failure; the live container is
never restarted by a backup run.

**Verifying a stored backup.** Any generation can be re-checked without touching
the backup volume, using the same check the nightly run applies:

```bash
./scripts/nightly-backup.sh --verify ~/cve-backups/<date>
# {"event":"verify-done",...}  then  verified: .../cve-backup.db.gz passed verifyBackup()
```

It exits `0` on a match and `1` with the failing artifact named otherwise (missing
gzip or manifest, unreadable gzip, hash/schema/row-count mismatch, or an image
without the verify branch), so it can be used from a cron check or a restore
drill. `--verify` never mounts the backup root and never prunes; it does require
Docker (one throwaway container) and the temp space described above. The
decompressed copy lives in a `mktemp -d` directory under `$TMPDIR`, and an `EXIT`
trap removes it only when the path still matches that `mktemp` pattern — a future
edit cannot turn the cleanup into a broad delete, and the directory is removed on
the failure path too.

**The backup root argument is guarded.** The script refuses (exit `2`, message on
stderr, never a prompt — it runs unattended) a backup root that is empty, not
absolute, `/`, or resolves to fewer than two path components (`/tmp` and
`/backups` are refused; `~/cve-backups` and `/srv/cve-backups` are accepted),
before creating anything, redirecting the log, or mounting the volume: the prune
step runs `find "$BACKUP_ROOT" … -exec rm -rf`, so a shallow or empty value would
be a broad system delete. It also re-checks that the root still exists and is a
directory immediately before pruning, and skips pruning entirely when either
verification failed. `--verify <dir>` is exempt from the root guard because it
never prunes: it only reads one existing directory.

## Compatibility policy

- A backup newer than the running code is **refused** — an old image must
  never read a new schema. Upgrade the app image first, then restore.
- A backup older than the target volume is a **downgrade** and is refused
  unless the current volume is backed up first (`allowDowngrade: true`
  plus `preRestoreBackupDir`). Downgrade without a backup is never allowed.
