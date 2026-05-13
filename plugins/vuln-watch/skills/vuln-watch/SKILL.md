---
name: vuln-watch
description: Run or maintain the Vuln Watch daily security exposure scanner for local projects and deployments.
---

# Vuln Watch

Use this skill when the user asks to run the daily vulnerability exposure scan, update the watched security surfaces, or inspect reports produced by this plugin.

## Commands

Run the scanner:

```bash
python3 /Users/joseph/guard/plugins/vuln-watch/scripts/vuln_watch.py --config /Users/joseph/guard/plugins/vuln-watch/config.json
```

Run without network calls for parser smoke tests:

```bash
python3 /Users/joseph/guard/plugins/vuln-watch/scripts/vuln_watch.py --config /Users/joseph/guard/plugins/vuln-watch/config.json --no-network
```

## Operating Contract

- Treat `config.json` as the explicit contract for scan roots, watched surfaces, and intelligence sources.
- Add new package/product aliases to `watched_surfaces`; do not bury important matching behavior in prose.
- X search is optional and requires `X_BEARER_TOKEN`.
- Reports live under `/Users/joseph/.codex/vuln-watch/reports`.
- The scanner reads local manifests and public vulnerability sources. It must not mutate cloud jobs or paid compute.
