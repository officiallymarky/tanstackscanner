#!/usr/bin/env bash
set -uo pipefail

echo "=== TanStack Mini Shai-Hulud IOC Scanner ==="
echo "Running on $(hostname) - $(date)"
echo

readonly MALICIOUS_HASH="ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c"
readonly MALICIOUS_COMMIT="79ac49eedf774dd4b0cfa308722bc463cfe5885c"

readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m'

found=false

warn() {
    printf "%b%s%b\n" "${RED}" "$*" "${NC}"
    found=true
}

info() {
    printf "%b%s%b\n" "${YELLOW}" "$*" "${NC}"
}

sha256_file() {
    local file="$1"

    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$file" 2>/dev/null | awk '{print $1}'
    else
        shasum -a 256 "$file" 2>/dev/null | awk '{print $1}'
    fi
}

check_file() {
    local file="$1"
    local file_hash
    local file_size

    [[ -f "$file" ]] || return 0

    info "Candidate found: $file"
    ls -la "$file" 2>/dev/null || true

    file_hash="$(sha256_file "$file")"
    file_size="$(stat -c %s "$file" 2>/dev/null || echo 0)"
    echo "SHA-256: ${file_hash:-unknown}"
    echo "Size: ${file_size} bytes"

    if [[ "$file_hash" == "$MALICIOUS_HASH" ]]; then
        warn "CRITICAL: known malicious file hash detected"
    elif [[ "$file_size" =~ ^[0-9]+$ && "$file_size" -gt 2000000 ]]; then
        warn "WARNING: suspicious large IOC-named file detected"
    elif grep -aEq '@tanstack/setup|tanstack_runner|gh-token-monitor|GITHUB_TOKEN|NPM_TOKEN|ACTIONS_ID_TOKEN_REQUEST' "$file" 2>/dev/null; then
        warn "WARNING: IOC-named file contains suspicious token/persistence strings"
    else
        printf "%bHash/content checks did not match known IOCs.%b\n" "${GREEN}" "${NC}"
    fi

    echo "-----------------------------------"
}

scan_named_iocs() {
    local -a roots=(
        "$PWD"
        "$HOME"
        "$HOME/.cache"
        "$HOME/.config"
        "$HOME/.local"
        "$HOME/.npm"
        "$HOME/.pnpm-store"
        /tmp
        /opt
        /usr/local
        /etc
    )
    local npm_root

    if command -v npm >/dev/null 2>&1; then
        npm_root="$(npm root -g 2>/dev/null || true)"
        [[ -n "$npm_root" ]] && roots+=("$npm_root")
    fi

    echo "→ Scanning filesystem for known TanStack/Mini Shai-Hulud file IOCs..."
    while IFS= read -r -d '' file; do
        check_file "$file"
    done < <(
        find "${roots[@]}" \
            \( -path '*/.git/*' -o -path '*/proc/*' -o -path '*/sys/*' -o -path '*/dev/*' \) -prune -o \
            -type f \( \
                -name 'router_init.js' -o \
                -name 'router_runtime.js' -o \
                -name 'tanstack_runner.js' -o \
                -name 'gh-token-monitor.sh' -o \
                -name 'setup.mjs' \
            \) -print0 2>/dev/null
    )
}

scan_manifests() {
    echo "→ Checking package manifests/lockfiles for malicious dependency IOCs..."
    while IFS= read -r -d '' file; do
        if grep -aEq "@tanstack/setup|${MALICIOUS_COMMIT}|github:tanstack/router" "$file" 2>/dev/null; then
            warn "WARNING: suspicious dependency IOC in $file"
            grep -anE "@tanstack/setup|${MALICIOUS_COMMIT}|github:tanstack/router" "$file" 2>/dev/null | head -20
            echo "-----------------------------------"
        fi
    done < <(
        find "$PWD" "$HOME/.npm" "$HOME/.pnpm-store" \
            \( -path '*/.git/*' \) -prune -o \
            -type f \( \
                -name 'package.json' -o \
                -name 'package-lock.json' -o \
                -name 'npm-shrinkwrap.json' -o \
                -name 'pnpm-lock.yaml' -o \
                -name 'yarn.lock' -o \
                -name 'bun.lock' -o \
                -name 'bun.lockb' \
            \) -print0 2>/dev/null
    )
}

scan_persistence() {
    echo "→ Checking for gh-token-monitor persistence..."

    if command -v systemctl >/dev/null 2>&1 && systemctl --user list-unit-files 2>/dev/null | grep -q 'gh-token-monitor'; then
        warn "CRITICAL: gh-token-monitor user systemd service detected"
        systemctl --user status gh-token-monitor.service --no-pager 2>/dev/null || true
    fi

    for file in \
        "$HOME/.config/systemd/user/gh-token-monitor.service" \
        "$HOME/.local/bin/gh-token-monitor.sh" \
        "$HOME/.config/autostart/gh-token-monitor.desktop"; do
        if [[ -e "$file" ]]; then
            warn "CRITICAL: persistence artifact detected: $file"
            ls -la "$file" 2>/dev/null || true
        fi
    done
}

scan_running_processes() {
    echo "→ Checking running processes for known IOC names..."
    if pgrep -af 'router_init\.js|router_runtime\.js|tanstack_runner\.js|gh-token-monitor'; then
        warn "CRITICAL: running process matches known IOC"
    fi
}

scan_named_iocs
scan_manifests
scan_persistence
scan_running_processes

if [[ "$found" == true ]]; then
    printf "\n%b=== SUSPICIOUS OR MALICIOUS IOCs FOUND ===%b\n" "${RED}" "${NC}"
    echo "Containment tip: stop suspicious services/processes before revoking or rotating GitHub/npm tokens."
    exit 1
fi

printf "\n%bNo confirmed malicious IOCs found.%b\n" "${GREEN}" "${NC}"
echo "Scan finished."
