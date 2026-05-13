# Guardtower

Guardtower is a Codex plugin for scheduled vulnerability exposure checks across local projects and deployment surfaces.

It inventories dependency manifests, checks exact package/version exposure through OSV, pulls current vulnerability intelligence from CISA KEV, NVD, RSS feeds, and optional X recent search, then writes timestamped Markdown and JSON reports with:

- new, resolved, still-present, and source-failure-aware exposure deltas
- deployment inventory and Vercel production verification when configured
- an Action View for triage
- strict threat-intel filtering so generic AI/tech roundups do not become security findings

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

## Reports

Reports are written to `/Users/joseph/.codex/guardtower/reports` by default. Edit [plugins/guardtower/config.json](plugins/guardtower/config.json) to change scan roots, report paths, watched surfaces, deployment mappings, or source settings.

The Action View is the daily triage surface:

```text
urgency | vulnerability | project/directory | deployment status | severity | recommended action
```

The `severity` column is a triage class: `deployed`, `active repo`, `lockfile-only`, `dev dependency`, or `unmatched intel`.

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
