# Backup, Restore, and Upgrade Runbook

Backup is database-consistent: the app TRUNCATE-checkpoints the WAL, then
copies the image with `VACUUM INTO` on the open handle. **Never back up by
copying the live `cve.db` file** — a raw copy of a written database is not
a valid backup. Histories (`kev_history`, `sync_runs`), retained Radar
checkpoints, baseline refs, tombstones, and manifests travel inside the
backup image plus a `manifest.json` sidecar.

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
worker branch (create + verify, never an import cycle), then generations
older than 7 days are pruned. Install from the repo root:

```bash
(crontab -l 2>/dev/null; echo "0 2 * * * <repo>/scripts/nightly-backup.sh") | crontab -
```

Backups land in `~/cve-backups/<UTC date>/` with `backup-cron.log` beside
them. A non-zero exit means cron mails the failure; the live container is
never restarted by a backup run.

## Compatibility policy

- A backup newer than the running code is **refused** — an old image must
  never read a new schema. Upgrade the app image first, then restore.
- A backup older than the target volume is a **downgrade** and is refused
  unless the current volume is backed up first (`allowDowngrade: true`
  plus `preRestoreBackupDir`). Downgrade without a backup is never allowed.
