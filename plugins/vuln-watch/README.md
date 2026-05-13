# Vuln Watch

Vuln Watch is a repo-local Codex plugin for daily vulnerability exposure checks.

It does three things in one deterministic pass:

1. Inventories local project dependencies from common manifests and lockfiles.
2. Queries OSV for known vulnerabilities in those packages.
3. Pulls current threat intelligence from CISA KEV, NVD recent CVEs, RSS feeds, and optional X recent search, then matches those items against explicit watched surfaces.

Reports are written to `/Users/joseph/.codex/vuln-watch/reports` by default as timestamped Markdown and JSON files. Each report compares against the latest previous JSON report and includes new, resolved, and still-present exposure counts.

Reports also include an Action View table with:

```text
urgency | vulnerability | project/directory | deployment status | severity | recommended action
```

The `severity` column is a triage class: `deployed`, `active repo`, `lockfile-only`, `dev dependency`, or `unmatched intel`.

## Run

```bash
python3 /Users/joseph/guard/plugins/vuln-watch/scripts/vuln_watch.py \
  --config /Users/joseph/guard/plugins/vuln-watch/config.json
```

Set `X_BEARER_TOKEN` to enable X recent search. You can put it in `/Users/joseph/guard/.env`, which is gitignored:

```bash
X_BEARER_TOKEN=your-token-here
```

Without it, the scanner still uses OSV, CISA KEV, NVD, and RSS sources.

## Configure

Edit `config.json` to add scan roots, deployment directories, RSS feeds, or explicit watched surfaces. By default, broad scan roots are reduced to Git repository roots before manifest scanning so caches and home-level tool stores are not treated as active projects.

Watched surfaces are the contract between unstructured threat chatter and your actual project surfaces; package matches are exact by ecosystem and package name.

OSV direct-exposure alerts require concrete package versions by default. Set `threat_intel.osv_query_versionless` to `true` only when you intentionally want broad package-history findings.
