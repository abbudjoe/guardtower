---
name: guardtower-dependency-preflight
description: Use before installing, adding, upgrading, or changing project dependencies, package managers, lockfiles, manifests, SDKs, libraries, plugins, or build tooling. Runs Guardtower first so Codex checks current vulnerability intelligence and local exposure before mutating dependency surfaces.
---

# Guardtower Dependency Preflight

Use this skill before dependency mutations such as `npm install`, `pnpm add`, `yarn add`, `bun add`, `pip install`, `uv add`, `poetry add`, `cargo add`, `cargo update`, `go get`, lockfile refreshes, SDK upgrades, or framework/library installs.

## Preflight

1. Identify the target project directory and the intended dependency change.
2. Run Guardtower before installing or updating packages:

```bash
python3 /Users/joseph/guard/plugins/guardtower/scripts/guardtower.py --config /Users/joseph/guard/plugins/guardtower/config.json
```

3. Read the newest report path printed by Guardtower. Treat the Action View and Permission Requests as the primary triage surfaces.
4. If Guardtower shows package-linked findings for the target project, resolve or report them before adding more dependency churn unless the user explicitly asks to proceed.
5. If Guardtower reports only unmatched intel, do not block the install solely on unmatched items. Mention the residual intel briefly when relevant.

For a deterministic parser/report smoke test while editing Guardtower itself, use:

```bash
python3 /Users/joseph/guard/plugins/guardtower/scripts/guardtower.py --config /Users/joseph/guard/plugins/guardtower/config.json --no-network
```

## After The Change

After dependency files are changed:

1. Run the ecosystem validation that matches the project, such as `npm audit`, `cargo check`, `cargo audit` if available, `pip-audit`, or the repo's established tests.
2. Rerun Guardtower when the change was security-motivated or materially changes runtime dependencies.
3. Compare the new report's delta. Call out new, resolved, and still-present package-linked exposures.

## Guardrails

- Do not mutate cloud jobs, paid compute, deployments, or production resources as part of dependency preflight unless the user explicitly authorizes that action in the current turn.
- Do not treat local deployment markers as proof of production deployment; rely on Guardtower deployment status, explicit config, or verified provider APIs.
- Do not suppress or record review decisions without evidence. Use `--record-review` only after checking applicability.
- Keep dependency edits scoped to the user's requested package or the minimum parent upgrades needed to remove the vulnerable package.
