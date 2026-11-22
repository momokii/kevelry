// Single-container process supervisor: runs the Next.js standalone server
// and the ingestion worker side by side, pipes their stdio, forwards
// SIGTERM/SIGINT to both, reaps children, and exits non-zero if either dies
// (a dead web server must not leave a zombie worker, and vice versa).
// Plain Node only: no extra dependencies.
//
// Boot order is part of the contract: the aggregate cache is warmed *before*
// the web server binds, so no user-facing request ever waits on a full
// aggregate build. On a current volume the warm is a single cache read
// (~0.3s); after a data change it is one recompute (~10s on a 410k corpus).
// The warm is a plain `node worker.mjs` one-off, not a second supervisor: it
// exits before either long-running child starts, which keeps the single-writer
// SQLite contract intact. A failed warm is logged and the server still starts —
// the live read path answers correctly, only slower, and availability must not
// depend on the cache.
/* global process, setTimeout, clearTimeout */

import { spawn } from "node:child_process";

const PREWARM_TIMEOUT_MS = 300_000;

const children = new Set();

function spawnChild(name, script) {
  const child = spawn("node", [script], {
    cwd: import.meta.dirname,
    stdio: "inherit",
    env: process.env,
  });
  children.add(child);
  child.on("exit", (code, signal) => {
    children.delete(child);
    const detail = signal === null ? `exit code ${code ?? "unknown"}` : `signal ${signal}`;
    process.stderr.write(`[entrypoint] ${name} died (${detail}); shutting down.\n`);
    // Any child death is abnormal for this pair (even a clean exit breaks the
    // web+worker contract), so the supervisor always exits non-zero.
    shutdown(1);
  });
  child.on("error", (error) => {
    children.delete(child);
    process.stderr.write(
      `[entrypoint] ${name} failed to start: ${error.message}; shutting down.\n`,
    );
    shutdown(1);
  });
  return child;
}

let shuttingDown = false;

function shutdown(exitCode) {
  if (shuttingDown) {
    return;
  }
  shuttingDown = true;
  for (const child of children) {
    try {
      child.kill("SIGTERM");
    } catch {
      // Best effort: the child may already be gone.
    }
  }
  const deadline = setTimeout(() => {
    for (const child of children) {
      try {
        child.kill("SIGKILL");
      } catch {
        // Best effort.
      }
    }
    process.exit(exitCode);
  }, 10_000);
  deadline.unref?.();

  const reap = () => {
    if (children.size === 0) {
      clearTimeout(deadline);
      process.exit(exitCode);
    }
  };
  for (const child of children) {
    child.on("exit", reap);
  }
  reap();
}

for (const signal of ["SIGTERM", "SIGINT"]) {
  process.on(signal, () => {
    process.stderr.write(`[entrypoint] received ${signal}; forwarding SIGTERM to children.\n`);
    shutdown(0);
  });
}

/**
 * Run `worker.mjs` once in warm-only mode and resolve with its exit status.
 * Deliberately not routed through spawnChild: a non-zero exit here is a logged
 * warning (serve live), not a reason to take the supervisor down.
 */
function warmAggregates() {
  return new Promise((resolve) => {
    let settled = false;
    let timeout = null;
    const child = spawn("node", ["worker.mjs"], {
      cwd: import.meta.dirname,
      stdio: "inherit",
      env: { ...process.env, WARM_AGGREGATES_ONCE: "true" },
    });
    children.add(child);
    const finish = (result) => {
      if (settled) return;
      settled = true;
      if (timeout !== null) clearTimeout(timeout);
      children.delete(child);
      resolve(result);
    };
    timeout = setTimeout(() => {
      process.stderr.write(
        `[entrypoint] aggregate warm exceeded ${PREWARM_TIMEOUT_MS / 1000}s; starting anyway.\n`,
      );
      child.kill("SIGKILL");
      finish({ ok: false, detail: "timeout" });
    }, PREWARM_TIMEOUT_MS);
    timeout.unref?.();
    child.on("exit", (code, signal) => {
      finish({
        ok: code === 0,
        detail: signal === null ? `exit code ${code ?? "unknown"}` : `signal ${signal}`,
      });
    });
    child.on("error", (error) => {
      finish({ ok: false, detail: error.message });
    });
  });
}

async function main() {
  process.stderr.write("[entrypoint] warming the aggregate cache before serving traffic\n");
  const startedAt = Date.now();
  const warm = await warmAggregates();
  if (shuttingDown) return;
  const elapsedMs = Date.now() - startedAt;
  if (warm.ok) {
    process.stderr.write(`[entrypoint] aggregate cache warm (${elapsedMs} ms)\n`);
  } else {
    process.stderr.write(
      `[entrypoint] aggregate warm failed (${warm.detail}) after ${elapsedMs} ms; ` +
        "starting the server on the live read path.\n",
    );
  }
  process.stderr.write("[entrypoint] starting server.js + worker.mjs\n");
  spawnChild("web", "server.js");
  spawnChild("worker", "worker.mjs");
}

void main();
