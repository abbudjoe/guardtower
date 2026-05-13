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
