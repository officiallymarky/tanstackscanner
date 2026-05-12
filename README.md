# TanStack Mini Shai-Hulud IOC Scanner

A small Bash scanner for indicators of compromise related to the TanStack npm supply-chain compromise and Mini Shai-Hulud activity.

The scanner checks for known suspicious files, dependency indicators, persistence artifacts, and running processes associated with the campaign.

## What it checks

- Known IOC filenames:
  - `router_init.js`
  - `router_runtime.js`
  - `tanstack_runner.js`
  - `gh-token-monitor.sh`
  - `setup.mjs`
- Known malicious SHA-256 hash:
  - `ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c`
- Suspicious dependency strings in manifests and lockfiles:
  - `@tanstack/setup`
  - `github:tanstack/router`
  - `79ac49eedf774dd4b0cfa308722bc463cfe5885c`
- User-level persistence artifacts for `gh-token-monitor`
- Running processes matching known IOC names

## Usage

```bash
chmod +x scan.sh
./scan.sh
```

The script exits with:

- `0` when no confirmed malicious IOCs are found
- `1` when suspicious or malicious IOCs are found

## Scan locations

The scanner searches common locations including:

- Current directory
- Home directory
- npm and pnpm cache/store directories
- User config and local binary directories
- Global npm package root, when `npm` is installed
- `/tmp`, `/opt`, `/usr/local`, and `/etc`

Some system paths may require additional permissions for complete coverage.

## If IOCs are found

Do not immediately revoke or rotate GitHub/npm tokens while suspicious persistence may still be active.

Recommended order:

1. Disconnect the host from untrusted networks if needed.
2. Stop suspicious `gh-token-monitor`, `router_*`, or `tanstack_runner` processes/services.
3. Preserve relevant files and logs for investigation.
4. Remove persistence artifacts after evidence is collected.
5. Rotate GitHub, npm, CI/CD, and package publishing tokens from a clean machine.
6. Reinstall affected dependencies from known-good versions.

## Notes

This is an IOC scanner, not a full forensic tool. A clean result means the script did not find the indicators it knows about; it does not prove the host was never compromised.
