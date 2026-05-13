# Guardtower Plugin

Guardtower is a Codex plugin for daily vulnerability exposure checks.

It does three things in one deterministic pass:

1. Inventories local project dependencies from common manifests and lockfiles.
2. Queries OSV for known vulnerabilities in exact package/version pairs.
3. Pulls current vulnerability intelligence from CISA KEV, NVD recent CVEs, RSS feeds, and optional X recent search, then matches those items against explicit watched surfaces.

Threat-intel matching is intentionally strict: generic AI/tech news roundups, newsletters, and meta-discussion replies are filtered out unless the item is centered on a concrete security exploit, CVE, compromised package, or actively exploited vulnerability.

## Run

```bash
python3 /Users/joseph/guard/plugins/guardtower/scripts/guardtower.py \
  --config /Users/joseph/guard/plugins/guardtower/config.json
```

Run without network calls for parser/report smoke tests:

```bash
python3 /Users/joseph/guard/plugins/guardtower/scripts/guardtower.py \
  --config /Users/joseph/guard/plugins/guardtower/config.json \
  --no-network
```

## Environment

Put local secrets in `/Users/joseph/guard/.env`, which is gitignored.

```bash
X_BEARER_TOKEN=your-x-bearer-token
VERCEL_TOKEN=your-vercel-token
VERCEL_TEAM_SLUG=your-team-slug
```

`VERCEL_TEAM_ID` can be used instead of `VERCEL_TEAM_SLUG`.

## Reports

Reports are written to `/Users/joseph/.codex/guardtower/reports` by default as timestamped Markdown and JSON files.

Each report includes:

- exposure delta: new, resolved, still present, and not observed because a source failed
- source failures such as NVD timeout or missing X/Vercel credentials
- deployment inventory
- clustered remediation plan grouped by package/version
- Action View triage table
- raw exposure and threat-item details in JSON

Action View columns:

```text
urgency | vulnerability | project/directory | deployment status | severity | recommended action
```

The `severity` column is a triage class: `deployed`, `active repo`, `lockfile-only`, `dev dependency`, or `unmatched intel`.

The Remediation Plan groups findings by package/version or unmatched intelligence item, ranks the clusters by urgency and deployment status, and includes package-manager attribution commands such as `npm explain`, `cargo tree -i`, or `pipdeptree -r -p`.

## Configure

Edit `config.json` to add scan roots, deployment directories, RSS feeds, or explicit watched surfaces. By default, broad scan roots are reduced to Git repository roots before manifest scanning so caches and home-level tool stores are not treated as active projects.

Watched surfaces are the contract between unstructured threat chatter and your actual project surfaces; package matches are exact by ecosystem and package name.

OSV direct-exposure alerts require concrete package versions by default. Set `threat_intel.osv_query_versionless` to `true` only when you intentionally want broad package-history findings.

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
