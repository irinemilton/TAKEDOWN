# PR-First Security Workflow

This repository uses a pull-request-only security model:

1. Security tooling detects a vulnerability.
2. A fix is proposed on a branch via pull request.
3. A human reviews and merges.

No silent direct changes are made to `main`.

## What is configured

- **Dependabot** (`.github/dependabot.yml`)
  - Scans dependencies and raises fix PRs automatically.
  - Keeps dependency and Actions updates in PR form.

- **Security Scan workflow** (`.github/workflows/security-scan.yml`)
  - Runs on PRs, pushes to `main`, schedule, and manual trigger.
  - Uses:
    - `bandit` for source-level Python security checks.
    - `pip-audit` for dependency vulnerability checks.
  - Publishes artifacts and step summary for auditability.

- **PR template** (`.github/pull_request_template.md`)
  - Forces vulnerability context and fix rationale in every PR.

## Recommended repository settings

In GitHub repository settings, enable:

- Branch protection on `main`:
  - Require a pull request before merging.
  - Require status checks to pass (include `Security Scan`).
  - Require at least 1 approving review.
- Auto-delete branch after merge (optional).

This enforces the model:
read for detection, controlled write through PR, human-approved merge.
