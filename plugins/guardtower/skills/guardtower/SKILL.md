---
name: guardtower
description: Run or maintain the Guardtower daily security exposure scanner for local projects and deployments.
---

# Guardtower

Use this skill when the user asks to run the daily vulnerability exposure scan, update the watched security surfaces, or inspect reports produced by this plugin.

## Commands

Run the scanner:

```bash
python3 /Users/joseph/guard/plugins/guardtower/scripts/guardtower.py --config /Users/joseph/guard/plugins/guardtower/config.json
```

Run without network calls for parser smoke tests:

```bash
python3 /Users/joseph/guard/plugins/guardtower/scripts/guardtower.py --config /Users/joseph/guard/plugins/guardtower/config.json --no-network
```

## Operating Contract

- Treat `config.json` as the explicit contract for scan roots, watched surfaces, and intelligence sources.
- Load credentials through the configured `env_file` before judging source availability. The default config points at `/Users/joseph/guard/.env`; do not conclude `X_BEARER_TOKEN` or `VERCEL_TOKEN` is missing only because it is absent from the worker shell.
- Add new package/product aliases to `watched_surfaces`; do not bury important matching behavior in prose.
- X search is optional and requires `X_BEARER_TOKEN`.
- Reports live under `/Users/joseph/.codex/guardtower/reports`.
- The scanner reads local manifests and public vulnerability sources. It must not mutate cloud jobs or paid compute.
