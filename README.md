# Guardtower

Guardtower is a Codex plugin for scheduled vulnerability exposure checks across local projects and deployment surfaces.

The current plugin, `vuln-watch`, inventories dependency manifests, checks exact package/version exposure through OSV, pulls current vulnerability intelligence from CISA KEV, NVD, RSS feeds, and optional X recent search, then writes timestamped Markdown and JSON reports with new/resolved/still-present exposure deltas and an action view for triage.

## Run Locally

```bash
python3 plugins/vuln-watch/scripts/vuln_watch.py --config plugins/vuln-watch/config.json
```

Set `X_BEARER_TOKEN` to enable X recent search. Without it, the scanner still uses OSV, CISA KEV, NVD, and RSS sources.

## Reports

Reports are written to `/Users/joseph/.codex/vuln-watch/reports` by default. Edit `plugins/vuln-watch/config.json` to change scan roots, watched surfaces, or report paths.

### Example Action View

The Action View is meant to be the daily triage surface. This example uses fictional project names and directories:

| Urgency | Vulnerability | Project/Directory | Deployment Status | Severity | Recommended Action |
| --- | --- | --- | --- | --- | --- |
| critical | CVE-2026-12345: Remote code execution in example-framework | `/workspace/customer-portal` | deployed | deployed | Confirm runtime exposure, patch or redeploy `npm:example-framework@1.2.3`, and add a post-fix scan note. |
| high | GHSA-abcd-1234-wxyz: Request smuggling in api-router | `/workspace/api-service` | unknown | active repo | Upgrade or remove `npm:api-router@4.5.6`; rerun tests and the scanner. |
| medium | RUSTSEC-2026-0001: Archive traversal in bundle-tool | `/workspace/cli-tools` | unknown | lockfile-only | Check whether `crates.io:bundle-tool@0.7.0` is transitive/runtime; update the parent dependency or refresh the lockfile. |
| medium | PYSEC-2026-42: Unsafe parsing in test-helper | `/workspace/build-scripts` | unknown | dev dependency | Update dev tooling package `PyPI:test-helper@8.0.0`; prioritize if CI or build artifacts consume untrusted input. |
| watch | Threat report mentions ExampleOS zero-day exploitation | unmatched | not applicable | unmatched intel | Verify whether this product/surface is used in any project or deployment; add package or deployment mapping if yes. |
