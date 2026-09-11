#!/usr/bin/env bash
# ==============================================================================
# Pull & Deploy Orchestrator — AI Security Architect
# Architecture Pattern: daryllrebeiro/support-master
# 100% Free-Tier & Zero-Cost Automated Delivery Engine
# ==============================================================================

set -euo pipefail

# ANSI Color Codes
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

log_header() {
  echo -e "\n${CYAN}================================================================================${NC}"
  echo -e "${CYAN}  $1${NC}"
  echo -e "${CYAN}================================================================================${NC}"
}

log_step() {
  echo -e "${YELLOW}➔ [STEP] $1...${NC}"
}

log_success() {
  echo -e "${GREEN}✔ [SUCCESS] $1${NC}"
}

log_error() {
  echo -e "${RED}✖ [ERROR] $1${NC}" >&2
}

START_TIME=$(date +%s)
STASH_CREATED=0
STASH_TAG=""

log_header "AI Security Architect — Pull & Deploy Pipeline"

# ------------------------------------------------------------------------------
# 1. Inspect Git Working Tree
# ------------------------------------------------------------------------------
log_step "Inspecting local git working tree"

if [ -n "$(git status --porcelain)" ]; then
  STASH_TAG="pull-and-deploy-auto-stash-$(date +%Y%m%d%H%M%S)"
  echo -e "   Uncommitted working changes detected. Creating temporary stash: ${STASH_TAG}"
  git stash push -u -m "${STASH_TAG}"
  STASH_CREATED=1
  log_success "Working changes safely stashed (${STASH_TAG})"
else
  echo "   Working tree is clean. Proceeding directly."
fi

# ------------------------------------------------------------------------------
# 2. Synchronize with Remote Branch (origin/main)
# ------------------------------------------------------------------------------
log_step "Pulling latest commits from origin/main"

if ! git pull origin main; then
  log_error "Failed to pull from origin/main. Aborting deployment."
  if [ "${STASH_CREATED}" -eq 1 ]; then
    echo "   Restoring previously stashed working state..."
    git stash pop || true
  fi
  exit 1
fi
log_success "Repository successfully synchronized to $(git rev-parse --short HEAD)"

# ------------------------------------------------------------------------------
# 3. Restore Stashed Changes (if applicable)
# ------------------------------------------------------------------------------
if [ "${STASH_CREATED}" -eq 1 ]; then
  log_step "Restoring stashed changes (${STASH_TAG})"
  if git stash pop; then
    log_success "Stashed changes reapplied cleanly"
  else
    log_error "Conflict detected while reapplying stash. Resolve conflicts before deploying."
    exit 1
  fi
fi

# ------------------------------------------------------------------------------
# 4. Chain into Zero-Cost Deployment Engine
# ------------------------------------------------------------------------------
log_step "Handoff to zero-cost cloud deployment engine (scripts/deploy.sh)"

DEPLOY_SCRIPT="${SCRIPT_DIR}/deploy.sh"
if [ ! -f "${DEPLOY_SCRIPT}" ]; then
  log_error "Deployment engine script not found at ${DEPLOY_SCRIPT}"
  exit 1
fi

chmod +x "${DEPLOY_SCRIPT}"
bash "${DEPLOY_SCRIPT}" "$@"

TOTAL_DURATION=$(( $(date +%s) - START_TIME ))
log_header "Pull & Deploy Complete in ${TOTAL_DURATION}s"
