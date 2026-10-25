// Single-container process supervisor: runs the Next.js standalone server
// and the ingestion worker side by side, pipes their stdio, forwards
// SIGTERM/SIGINT to both, reaps children, and exits non-zero if either dies
// (a dead web server must not leave a zombie worker, and vice versa).
// Plain Node only: no extra dependencies.
/* global process, setTimeout, clearTimeout */

import { spawn } from "node:child_process";

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
    process.stderr.write(`[entrypoint] ${name} failed to start: ${error.message}; shutting down.\n`);
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

process.stderr.write("[entrypoint] starting server.js + worker.mjs\n");
spawnChild("web", "server.js");
spawnChild("worker", "worker.mjs");
