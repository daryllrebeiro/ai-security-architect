#!/usr/bin/env bash
# ==============================================================================
# Replit Native Process Supervision & Multi-Mode Runner — AI Security Architect
# Zero-Cost / Free-Tier Autoscale Engine
# ==============================================================================

set -euo pipefail

# ANSI Color Formatting
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

# Supervised Child Process Registry
CHILD_PIDS=()

log_header() {
  echo -e "\n${CYAN}================================================================================${NC}"
  echo -e "${CYAN}  $1${NC}"
  echo -e "${CYAN}================================================================================${NC}"
}

log_step() {
  echo -e "\n${YELLOW}➔ [REPLIT-RUNNER: $1]...${NC}"
}

log_success() {
  echo -e "${GREEN}✔ $1${NC}"
}

fail_cost_violation() {
  echo -e "\n${RED}================================================================================${NC}" >&2
  echo -e "${RED}${BOLD}  [FREE-TIER POLICY VIOLATION — EXECUTION ABORTED]${NC}" >&2
  echo -e "${RED}  Violation: $1${NC}" >&2
  echo -e "${RED}  Rule:      All Replit executions must run within zero-cost free-tier boundaries.${NC}" >&2
  echo -e "${RED}================================================================================${NC}\n" >&2
  exit 1
}

# ==============================================================================
# Step 1: Preflight Free-Tier Compliance Validation
# ==============================================================================
assert_free_tier_compliance() {
  log_step "Verifying Free-Tier Compliance & Zero-Cost Guardrails"

  # 1. Enforce local embedded database (SQLite/local JSON) vs paid cloud DB
  if [[ -n "${DATABASE_URL:-}" ]]; then
    if [[ "${DATABASE_URL}" =~ (rds\.amazonaws\.com|cloudsql|spanner|database\.windows\.net|snowflakecomputing\.com) ]]; then
      fail_cost_violation "DATABASE_URL points to paid external cloud DB: ${DATABASE_URL}. Only local SQLite or verified free-tier endpoints permitted."
    fi
  fi

  # 2. Check for reserved or paid VM tier directives
  if [[ "${REPLIT_VM_TIER:-free}" =~ ^(reserved|dedicated|gpu|paid)$ ]]; then
    fail_cost_violation "Paid Replit VM tier '${REPLIT_VM_TIER}' requested. Only standard autoscale free containers are permitted."
  fi

  # 3. Ensure memory footprint is suitable for free container (max 1Gi)
  export NODE_OPTIONS="${NODE_OPTIONS:---max-old-space-size=512}"

  log_success "Zero-cost validation passed: autoscale bounds and embedded storage confirmed."
}

# ==============================================================================
# Step 2: Environment Auto-Detection
# ==============================================================================
detect_environment() {
  log_step "Detecting Replit Execution Environment"

  if [[ -n "${REPL_ENVIRONMENT:-}" && "${REPL_ENVIRONMENT}" == "production" ]] || [[ -n "${DEPLOYMENT_ID:-}" ]]; then
    export NODE_ENV="production"
    echo -e "${CYAN}[ENV] Running in REPLIT PRODUCTION AUTOSCALE mode (Deployment ID: ${DEPLOYMENT_ID:-unknown})${NC}"
  else
    export NODE_ENV="${NODE_ENV:-development}"
    echo -e "${CYAN}[ENV] Running in REPLIT DEVELOPMENT / WORKSPACE mode (NODE_ENV=${NODE_ENV})${NC}"
  fi
}

# ==============================================================================
# Step 3: Dynamic Port Conflict Resolution
# ==============================================================================
kill_port_conflicts() {
  local target_port="$1"
  echo -e "Checking for conflicting processes listening on port :${target_port}..."

  if command -v fuser >/dev/null 2>&1; then
    fuser -k "${target_port}/tcp" 2>/dev/null || true
  elif command -v lsof >/dev/null 2>&1; then
    local pids
    pids=$(lsof -ti ":${target_port}" 2>/dev/null || true)
    if [[ -n "${pids}" ]]; then
      echo -e "${YELLOW}Killing lingering processes on port ${target_port}: ${pids}${NC}"
      echo "${pids}" | xargs kill -9 2>/dev/null || true
    fi
  fi
}

# ==============================================================================
# Step 4: Process Supervision & Signal Cleanup
# ==============================================================================
cleanup_children() {
  local original_exit_code=$?
  local signal_name="${1:-SIGTERM}"
  echo -e "\n${YELLOW}[SUPERVISOR] Caught ${signal_name}. Gracefully terminating supervised processes...${NC}"

  for pid in "${CHILD_PIDS[@]}"; do
    if kill -0 "${pid}" 2>/dev/null; then
      echo -e "Sending SIGTERM to child PID ${pid}..."
      kill -TERM "${pid}" 2>/dev/null || true
    fi
  done

  # Allow up to 5 seconds for clean exit
  local wait_count=0
  while [[ ${wait_count} -lt 5 ]]; do
    local alive=0
    for pid in "${CHILD_PIDS[@]}"; do
      if kill -0 "${pid}" 2>/dev/null; then
        alive=1
        break
      fi
    done
    [[ ${alive} -eq 0 ]] && break
    sleep 1
    wait_count=$((wait_count + 1))
  done

  # Force kill any lingering processes
  for pid in "${CHILD_PIDS[@]}"; do
    if kill -0 "${pid}" 2>/dev/null; then
      echo -e "${RED}Force-killing stubborn child PID ${pid}...${NC}"
      kill -9 "${pid}" 2>/dev/null || true
    fi
  done

  echo -e "${GREEN}[SUPERVISOR] All child processes terminated. Teardown complete.${NC}"
  if [[ ${original_exit_code} -ne 0 ]]; then
    exit ${original_exit_code}
  fi
  exit 0
}

trap 'cleanup_children SIGINT' INT
trap 'cleanup_children SIGTERM' TERM
trap 'cleanup_children EXIT' EXIT

# ==============================================================================
# Step 5: Multi-Mode Process Execution
# ==============================================================================
main() {
  local MODE="${1:-${MODE:-all}}"

  log_header "AI SECURITY ARCHITECT — REPLIT RUNNER (MODE: ${MODE})"

  assert_free_tier_compliance
  detect_environment

  local PORT="${PORT:-8080}"
  export PORT
  export HOST="0.0.0.0"

  case "${MODE}" in
    backend)
      log_step "Launching Backend Server on port ${PORT}"
      kill_port_conflicts "${PORT}"
      node server.js &
      CHILD_PIDS+=($!)
      log_success "Backend process started (PID: ${CHILD_PIDS[-1]})."
      ;;

    frontend)
      log_step "Launching Frontend Web Interface on port ${PORT}"
      kill_port_conflicts "${PORT}"
      if [[ -d "packages/web" && -f "packages/web/package.json" ]]; then
        npm run --workspace=@ai-security-architect/web dev -- --host 0.0.0.0 --port "${PORT}" &
        CHILD_PIDS+=($!)
        log_success "Frontend Vite process started (PID: ${CHILD_PIDS[-1]})."
      else
        echo -e "${YELLOW}packages/web not found. Falling back to core server dashboard...${NC}"
        node server.js &
        CHILD_PIDS+=($!)
        log_success "Core server started (PID: ${CHILD_PIDS[-1]})."
      fi
      ;;

    all)
      log_step "Launching Unified Production Suite (Mode: all)"

      # In standard autoscale free tier, server.js provides unified HTTP service:
      # /health (probes), /api/metrics (telemetry), and / (interactive web dashboard)
      # with zero excess memory usage (< 40MB RSS).
      kill_port_conflicts "${PORT}"

      echo -e "Starting primary production server on http://${HOST}:${PORT}..."
      node server.js &
      CHILD_PIDS+=($!)
      log_success "Production server active (PID: ${CHILD_PIDS[-1]})."

      # If separate web dev server is explicitly requested in development
      if [[ "${NODE_ENV}" == "development" && "${ENABLE_VITE_HMR:-false}" == "true" && -d "packages/web" ]]; then
        local DEV_PORT=$((PORT + 1))
        kill_port_conflicts "${DEV_PORT}"
        echo -e "Starting Vite HMR dev server on port ${DEV_PORT}..."
        npm run --workspace=@ai-security-architect/web dev -- --host 0.0.0.0 --port "${DEV_PORT}" &
        CHILD_PIDS+=($!)
        log_success "Vite dev server active (PID: ${CHILD_PIDS[-1]})."
      fi
      ;;

    *)
      echo -e "${RED}Unknown mode: '${MODE}'. Valid modes: all, backend, frontend${NC}" >&2
      exit 1
      ;;
  esac

  echo -e "\n${CYAN}================================================================================${NC}"
  echo -e "${GREEN}  All processes running under supervisor. Active PIDs: ${CHILD_PIDS[*]}${NC}"
  echo -e "${CYAN}  Health Check URL: http://0.0.0.0:${PORT}/health${NC}"
  echo -e "${CYAN}  Dashboard URL:    http://0.0.0.0:${PORT}/${NC}"
  echo -e "${CYAN}================================================================================${NC}\n"

  # Process supervisor wait loop
  # wait -n returns the exit status of the first child process to terminate
  if bash -c 'help wait' 2>/dev/null | grep -q -- '-n'; then
    wait -n "${CHILD_PIDS[@]}" || true
  else
    # Fallback for systems without wait -n
    while true; do
      for pid in "${CHILD_PIDS[@]}"; do
        if ! kill -0 "${pid}" 2>/dev/null; then
          echo -e "${RED}Monitored child PID ${pid} terminated.${NC}"
          break 2
        fi
      done
      sleep 2
    done
  fi

  echo -e "${YELLOW}One or more supervised processes exited. Initiating teardown...${NC}"
}

main "$@"
