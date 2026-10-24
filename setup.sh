#!/bin/sh
# setup.sh — prerequisite checks only. Never installs, never uses sudo,
# never downloads, never writes config or data. Exits non-zero when a
# prerequisite is unmet, with an actionable message. Safe to re-run.
set -eu

PORT="${PORT:-3000}"
FAIL=0

pass() { printf 'PASS: %s\n' "$1"; }
fail() { printf 'FAIL: %s\n  fix: %s\n' "$1" "$2"; FAIL=1; }
skip() { printf 'SKIP: %s\n  note: %s\n' "$1" "$2"; }

# 1. Docker CLI present.
if command -v docker >/dev/null 2>&1; then
  pass "docker CLI found ($(command -v docker))"
else
  fail "docker CLI not found on PATH" \
    "install Docker Engine for your OS, then re-run ./setup.sh"
fi

# 2. Docker daemon reachable (also proves permission to talk to it).
if [ "$FAIL" -eq 0 ]; then
  if docker info >/dev/null 2>&1; then
    pass "docker daemon reachable"
  else
    fail "docker daemon not reachable" \
      "start the Docker service; on Linux check 'sudo systemctl start docker' and that your user is in the docker group, then re-run ./setup.sh"
  fi
else
  skip "docker daemon reachability" "docker CLI missing; install it first"
fi

# 3. Compose plugin present.
if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  pass "docker compose plugin available ($(docker compose version --short 2>/dev/null || echo yes))"
else
  fail "docker compose plugin not available" \
    "install Docker Compose v2 plugin (docker-compose-plugin package), then re-run ./setup.sh"
fi

# 4. Host port free (loopback bind used by compose.yaml).
if command -v python3 >/dev/null 2>&1; then
  if python3 -c "import socket,sys; s=socket.socket(); s.settimeout(2); sys.exit(0 if s.connect_ex(('127.0.0.1', int('$PORT'))) != 0 else 1)" 2>/dev/null; then
    pass "port 127.0.0.1:${PORT} is free"
  else
    fail "port 127.0.0.1:${PORT} is already in use" \
      "stop the process on ${PORT} (try 'ss -ltnp | grep ${PORT}') or run with a free port, e.g. PORT=3001 ./setup.sh"
  fi
else
  skip "port ${PORT} availability" "python3 not found; check manually with 'ss -ltn | grep ${PORT}'"
fi

# 5. Volume subsystem writable — create + immediately remove a probe
# volume. Net effect: nothing persists (trap guarantees removal).
if [ "$FAIL" -eq 0 ] && docker info >/dev/null 2>&1; then
  PROBE="cve-setup-probe-$$"
  cleanup() { docker volume rm "$PROBE" >/dev/null 2>&1 || true; }
  trap cleanup EXIT INT TERM
  if docker volume create "$PROBE" >/dev/null 2>&1; then
    docker volume rm "$PROBE" >/dev/null 2>&1
    trap - EXIT INT TERM
    pass "docker volume subsystem writable (probe created and removed, nothing left behind)"
  else
    trap - EXIT INT TERM
    fail "cannot create docker volumes" \
      "check daemon storage ('docker system df') and disk space, then re-run ./setup.sh"
  fi
else
  skip "volume writability probe" "daemon not reachable; fix that first"
fi

if [ "$FAIL" -ne 0 ]; then
  printf '\nPrerequisites NOT met. Fix the FAIL items above, then re-run ./setup.sh.\n'
  exit 1
fi

cat <<EOF

All prerequisites met. Next steps:
  docker compose build
  docker compose up -d   # start the single container on 127.0.0.1:${PORT}
  docker compose logs -f app
EOF
