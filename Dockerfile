# cve-change-radar single-image Dockerfile (todo 25).
#
# One release image runs the complete app as one container: Next.js
# standalone server + embedded SQLite (better-sqlite3) on a persistent
# volume. No Compose file here (todo 27), no data baked in, no secrets.
#
# Build stages: deps -> builder -> runner. Only the runner ships.
# Base images are pinned by exact tag (never `latest`).
#
# NOTE on next.config.ts: the repo file does not set `output: "standalone"`
# and this Dockerfile must not change app code, so the builder stage enables
# standalone + serverExternalPackages ephemerally INSIDE the build layer only
# (the repo file is untouched; `git status` in the worktree stays clean apart
# from this Dockerfile / .dockerignore).

ARG NODE_TAG=24.12.0-bookworm-slim

# --------------------------------------------------------------------------
# Stage 1: deps — full install (dev deps needed to run `next build`).
# --------------------------------------------------------------------------
FROM node:${NODE_TAG} AS deps
WORKDIR /app
# better-sqlite3 ships no prebuild for this Node ABI, so it compiles from
# source here (build tools stay in non-shipped stages only).
RUN apt-get update \
  && apt-get install -y --no-install-recommends python3 make g++ \
  && rm -rf /var/lib/apt/lists/*
COPY package.json package-lock.json ./
RUN npm ci
# libc guard: package-lock.json lists @next/swc-linux-x64-gnu and -musl WITHOUT
# the `libc` field npm uses to filter optional platform deps, so `npm ci` on
# this glibc base can resolve to the musl build alone. Next then loads no
# native swc binding and `next build` aborts with "Turbopack is not supported
# on this platform (linux/x64) because native bindings are not available" and
# "@next/swc-linux-x64-musl ... /lib/x86_64-linux-gnu/libc.so: invalid ELF
# header". Assert the glibc binding, repair it if missing, then hard-fail if it
# still will not load. Do not delete this step: without it a musl-only install
# only surfaces one cached layer later, at `npm run build`.
RUN NEXT_SWC_VERSION="$(node -p "require('./package.json').dependencies.next")" \
  && if ! node -e "require('@next/swc-linux-x64-gnu')" >/dev/null 2>&1; then \
       echo "==> @next/swc-linux-x64-gnu is not loadable on this glibc base; installing ${NEXT_SWC_VERSION}"; \
       npm install --no-save --include=optional --ignore-scripts --no-audit --no-fund \
         "@next/swc-linux-x64-gnu@${NEXT_SWC_VERSION}"; \
     fi \
  && node -e "try{const p=require.resolve('@next/swc-linux-x64-gnu');require('@next/swc-linux-x64-gnu');console.log('Next SWC glibc binding OK:',p)}catch(e){console.error('FATAL: @next/swc-linux-x64-gnu is not loadable on this glibc image ('+e.message+').');console.error('Cause: only the musl variant was installed; next build would fall back to WASM and Turbopack would abort.');process.exit(1)}"

# --------------------------------------------------------------------------
# Stage 2: builder — ephemeral standalone config, production build,
# explicit native-addon verification (build FAILS if the .node binary is
# missing from traced output or cannot be loaded).
# --------------------------------------------------------------------------
FROM node:${NODE_TAG} AS builder
WORKDIR /app
RUN apt-get update \
  && apt-get install -y --no-install-recommends python3 make g++ \
  && rm -rf /var/lib/apt/lists/*
COPY --from=deps /app/node_modules ./node_modules
COPY . .
# Enable standalone output + keep better-sqlite3 external (traced, not
# bundled) for this build layer only. The repo's next.config.ts is not
# modified on the host: this edit exists only inside the image layer.
# The patch inserts the two standalone keys after the config opening brace,
# preserving any other keys (e.g. headers) the repo file defines.
RUN node -e "const fs=require('fs');let s=fs.readFileSync('next.config.ts','utf8');if(!s.includes('standalone')){if(!s.includes('const nextConfig: NextConfig = {')){console.error('FATAL: next.config.ts shape changed; update the ephemeral standalone patch');process.exit(1);}s=s.replace('const nextConfig: NextConfig = {','const nextConfig: NextConfig = {\n  output: \"standalone\",\n  serverExternalPackages: [\"better-sqlite3\"],');fs.writeFileSync('next.config.ts',s);}console.log(fs.readFileSync('next.config.ts','utf8'))" \
  && mkdir -p public \
  && npm run build
# Adversarial gate 1: standalone server must exist.
RUN test -f .next/standalone/server.js || (echo "FATAL: .next/standalone/server.js missing — standalone output not produced" >&2 && exit 1)
# Adversarial gate 2: at least one native .node binary must be traced.
RUN find .next/standalone -name '*.node' -print | tee /tmp/native-modules.txt \
  && test -s /tmp/native-modules.txt || (echo "FATAL: no .node native binary in standalone output — better-sqlite3 was not traced" >&2 && exit 1)
# Adversarial gate 3: the traced binary must actually load on this libc.
RUN node -e "const path=require('path');const fs=require('fs');const f=fs.readFileSync('/tmp/native-modules.txt','utf8').trim().split('\n').map(l=>l.trim()).filter(l=>l.includes('better-sqlite3'))[0]||fs.readFileSync('/tmp/native-modules.txt','utf8').trim().split('\n')[0].trim();const abs=path.resolve('/app',f);require(abs);console.log('native addon loads OK:',abs)"

# --------------------------------------------------------------------------
# Stage 3: runner — minimal production image, non-root, no dev tools.
# --------------------------------------------------------------------------
FROM node:${NODE_TAG} AS runner
ENV NODE_ENV=production \
  APP_ENV=production \
  PORT=3000 \
  HOSTNAME=0.0.0.0 \
  DATA_DIR=/data \
  SCHEDULE_ENABLED=true
WORKDIR /app
# git + CA certificates supply the in-container CVE List V5 clone/fetch
# over HTTPS (git alone fails with "CAfile: none").
RUN apt-get update \
  && apt-get install -y --no-install-recommends git ca-certificates \
  && rm -rf /var/lib/apt/lists/* \
  && git --version \
  && groupadd --system --gid 1001 nodejs \
  && useradd --system --uid 1001 --gid nodejs nextjs \
  && mkdir -p /data /tmp \
  && chown nextjs:nodejs /data \
  && chmod 1777 /tmp \
  && rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx \
  && apt-get purge -y --auto-remove 2>/dev/null || true
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static
COPY --from=builder --chown=nextjs:nodejs /app/public ./public
# Ingestion worker bundle (built by `npm run build:worker` in the builder
# stage) plus the plain-JS supervisor. No extra runtime deps required.
# The migrations/ directory ships next to worker.mjs because the bundled
# migration runner resolves its SQL files relative to its own location.
COPY --from=builder --chown=nextjs:nodejs /app/dist/worker.mjs ./worker.mjs
COPY --from=builder --chown=nextjs:nodejs /app/dist/migrations ./migrations
COPY --from=builder --chown=nextjs:nodejs /app/docker/entrypoint.mjs ./entrypoint.mjs
USER nextjs
EXPOSE 3000
VOLUME /data
# Liveness: the process answers. Readiness (data accepted vs initializing) is
# reported by the JSON body at the same endpoint for the todo-26 supervisor.
# The start period covers the boot warm: the entrypoint rebuilds the aggregate
# read model before server.js binds its port, so the port can stay closed for
# the length of one rebuild (seconds on current data, ~10s on a 410k corpus).
HEALTHCHECK --interval=30s --timeout=5s --start-period=120s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||'3000')+'/api/v1/health').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"
CMD ["node", "entrypoint.mjs"]
