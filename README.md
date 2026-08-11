# TDS GA7 Release Gate Policy Service

Deterministic policy endpoint that decides whether a GitHub Actions run may promote a container image.

## Features
- **Least Privilege Permissions**: `contents: read`, `packages: write`, `id-token: none`.
- **Safe PR Triggers**: `pull_request` only (no `pull_request_target`).
- **Complete Testing**: `testsPassed: true`, `matrixComplete: true`, `failFast: false`.
- **Action Pinning**: `actions` tags or 40-char commit SHAs; third-party 40-char hex commit SHAs.
- **Hardened Image**: Multi-stage, non-root, BuildKit secret mount or no secrets, 0 critical CVEs, digest-pinned.
- **Production Validation**: `push` on `refs/heads/main` and `environmentApproval: true`.

## Identity
TDS identity: `22f1000561@ds.study.iitm.ac.in`
