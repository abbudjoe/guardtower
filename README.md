# Guardtower

Guardtower is a Codex plugin for scheduled vulnerability exposure checks across local projects and deployment surfaces.

The root `.codex-plugin/plugin.json` is the installable Codex plugin manifest. The implementation lives in `plugins/guardtower`.

It inventories dependency manifests, checks exact package/version exposure through OSV, pulls current vulnerability intelligence from CISA KEV, NVD, RSS feeds, and optional X recent search, then writes timestamped Markdown and JSON reports with:

- new, resolved, still-present, and source-failure-aware exposure deltas
- deployment inventory and Vercel production verification when configured
- a clustered Remediation Plan that groups many advisories into package-level work items
- permission requests that ask before Codex starts bounded remediation work
- an Action View for triage
- strict threat-intel filtering so generic AI/tech roundups do not become security findings

## Codex Skills

The plugin ships two skills:

- `guardtower`: run and maintain the daily exposure scanner.
- `guardtower-dependency-preflight`: trigger before Codex installs, adds, upgrades, or refreshes dependencies so Guardtower checks current vulnerability intelligence first.

The dependency preflight skill tells Codex to run Guardtower before dependency mutations, inspect the newest Action View, avoid adding dependency churn when the target project already has package-linked findings, and rerun Guardtower after security-motivated dependency changes.

## Run Locally

```bash
python3 plugins/guardtower/scripts/guardtower.py --config plugins/guardtower/config.json
```

For a parser/report smoke test without network calls:

```bash
python3 plugins/guardtower/scripts/guardtower.py --config plugins/guardtower/config.json --no-network
```

## Environment

Create a local `.env` from `.env.example`. `.env` is gitignored.

```bash
X_BEARER_TOKEN=
VERCEL_TOKEN=
VERCEL_TEAM_SLUG=
```

`X_BEARER_TOKEN` enables X recent search. Without it, Guardtower still uses OSV, CISA KEV, NVD, and RSS.

`VERCEL_TOKEN` enables Vercel production deployment discovery. Optional `VERCEL_TEAM_ID` or `VERCEL_TEAM_SLUG` scopes Vercel API requests to a team.

## Daily Automation

The saved Codex cron automation should match [plugins/guardtower/automations/daily-guardtower.automation.toml](/Users/joseph/guard/plugins/guardtower/automations/daily-guardtower.automation.toml). A readable prompt copy is kept in [plugins/guardtower/automations/daily-guardtower-prompt.md](/Users/joseph/guard/plugins/guardtower/automations/daily-guardtower-prompt.md), and tests verify both files stay aligned.

The important contract is that Guardtower loads `/Users/joseph/guard/.env` through `config.json`; automation workers should only report `X_BEARER_TOKEN` or `VERCEL_TOKEN` as missing when the scanner output or report explicitly records a skipped source.

## Reports

Reports are written to `/Users/joseph/.codex/guardtower/reports` by default. Edit [plugins/guardtower/config.json](plugins/guardtower/config.json) to change scan roots, report paths, watched surfaces, deployment mappings, or source settings.

The Action View is the daily triage surface:

```text
urgency | vulnerability | project/directory | deployment status | severity | recommended action
```

The `severity` column is a triage class: `deployed`, `active repo`, `lockfile-only`, `dev dependency`, or `unmatched intel`.

The Remediation Plan groups findings by package/version or unmatched intelligence item, ranks the clusters by urgency and deployment status, and includes package-manager attribution commands such as `npm explain`, `cargo tree -i`, or `pipdeptree -r -p`.

The Permission Requests section is the approval hook. Guardtower never patches by itself; it emits approval IDs such as `GT-FIX-...` for direct package findings and `GT-REVIEW-...` for watched-surface intel that needs applicability review first. Reply with the approval phrase in Codex to start one bounded task. The default prompt explicitly excludes deploys, paid cloud/job mutations, and merges unless separately approved.

## Review State

When a `GT-REVIEW-...` item is checked and found not applicable, record that decision instead of re-reviewing the same false positive every day:

```bash
python3 plugins/guardtower/scripts/guardtower.py \
  --config plugins/guardtower/config.json \
  --record-review /Users/joseph/.codex/guardtower/reports/<report>.json \
  --request-id GT-REVIEW-... \
  --review-status not_affected \
  --reason "Installed version is outside the affected range."
```

Review decisions are written to `/Users/joseph/.codex/guardtower/reviews.json` by default. Suppressing statuses are `not_affected`, `false_positive`, and `risk_accepted`; `affected` records review context without removing the finding from active remediation. Reports keep reviewed findings under `reviewed_exposures` and exclude them from the Action View, Remediation Plan, and future Permission Requests.

## Deployment Discovery

Guardtower treats deployment status as a control-plane fact:

- explicit `deployment_status` entries in config are authoritative
- Vercel projects can be verified through the Vercel deployments API when `VERCEL_TOKEN` is set
- local markers such as `vercel.json` only mean `deployable marker found`, not deployed

Example Vercel mapping:

```json
"deployment_discovery": {
  "vercel": {
    "enabled": true,
    "token_env": "VERCEL_TOKEN",
    "team_slug_env": "VERCEL_TEAM_SLUG",
    "projects": [
      {
        "path_prefix": "/workspace/liquidshell/apps/web",
        "project_name": "liquidshell"
      }
    ]
  }
}
```

## Example Action View

This example uses fictional project names and directories:

| Urgency | Vulnerability | Project/Directory | Deployment Status | Severity | Recommended Action |
| --- | --- | --- | --- | --- | --- |
| critical | CVE-2026-12345: Remote code execution in example-framework | `/workspace/customer-portal` | deployed | deployed | Confirm runtime exposure, patch or redeploy `npm:example-framework@1.2.3`, and add a post-fix scan note. |
| high | GHSA-abcd-1234-wxyz: Request smuggling in api-router | `/workspace/api-service` | unknown | active repo | Upgrade or remove `npm:api-router@4.5.6`; rerun tests and the scanner. |
| medium | RUSTSEC-2026-0001: Archive traversal in bundle-tool | `/workspace/cli-tools` | unknown | lockfile-only | Check whether `crates.io:bundle-tool@0.7.0` is transitive/runtime; update the parent dependency or refresh the lockfile. |
| medium | PYSEC-2026-42: Unsafe parsing in test-helper | `/workspace/build-scripts` | unknown | dev dependency | Update dev tooling package `PyPI:test-helper@8.0.0`; prioritize if CI or build artifacts consume untrusted input. |
| watch | Threat report mentions ExampleOS zero-day exploitation | unmatched | not applicable | unmatched intel | Verify whether this product/surface is used in any project or deployment; add package or deployment mapping if yes. |
