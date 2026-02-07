#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  VaultSecureCLI — Linux / macOS Installer
#  Installs dependencies and links the `vault` command globally.
# ═══════════════════════════════════════════════════════════════

set -euo pipefail

# ── Colors ────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

banner() {
  echo ""
  echo -e "${CYAN}${BOLD}"
  echo "  ╔═══════════════════════════════════════════════╗"
  echo "  ║       🔐  VaultSecureCLI  Installer          ║"
  echo "  ╚═══════════════════════════════════════════════╝"
  echo -e "${RESET}"
}

info()    { echo -e "  ${CYAN}ℹ${RESET}  $1"; }
success() { echo -e "  ${GREEN}✔${RESET}  $1"; }
warn()    { echo -e "  ${YELLOW}⚠${RESET}  $1"; }
fail()    { echo -e "  ${RED}✖${RESET}  $1"; exit 1; }

# ── Pre-flight checks ────────────────────────────────────────
banner

# Check Node.js
if ! command -v node &>/dev/null; then
  fail "Node.js is not installed. Please install Node.js 16+ from https://nodejs.org"
fi

NODE_VERSION=$(node -v | sed 's/v//' | cut -d. -f1)
if [ "$NODE_VERSION" -lt 16 ]; then
  fail "Node.js 16+ required (found v${NODE_VERSION}). Please upgrade."
fi
success "Node.js $(node -v) detected"

# Check npm
if ! command -v npm &>/dev/null; then
  fail "npm is not installed. It should come with Node.js."
fi
success "npm $(npm -v) detected"

# ── Install ───────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

info "Installing dependencies..."
npm install --production 2>&1 | sed 's/^/    /'
success "Dependencies installed"

info "Linking 'vault' command globally..."
if npm link 2>&1 | sed 's/^/    /'; then
  success "Global link created"
else
  warn "npm link failed — trying with sudo..."
  sudo npm link 2>&1 | sed 's/^/    /'
  success "Global link created (with sudo)"
fi

# ── Verify ────────────────────────────────────────────────────
echo ""
if command -v vault &>/dev/null; then
  success "Installation complete! Run ${BOLD}vault${RESET} to start."
else
  warn "Link created but 'vault' not found in PATH."
  info "Try running: ${BOLD}node ${SCRIPT_DIR}/bin/vault.js${RESET}"
fi

echo ""
echo -e "${DIM}  ─────────────────────────────────────────────${RESET}"
echo -e "  ${GREEN}${BOLD}Quick start:${RESET}"
echo -e "    ${CYAN}vault${RESET}          — Launch the vault"
echo -e "    ${CYAN}vault --quick${RESET}  — Skip boot animation"
echo -e "${DIM}  ─────────────────────────────────────────────${RESET}"
echo ""
