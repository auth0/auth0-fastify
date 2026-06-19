# Conventional Commit Enforcement

**Date:** 2026-06-19  
**Status:** Approved

## Goal

Enforce conventional commit message format across all contributions — both locally for fast feedback and in CI as a safety net. Scope validation ensures consistent package-level attribution.

## Dependencies

New root-level dev dependencies:

| Package | Purpose |
|---|---|
| `husky` | Git hook management via `npm prepare` |
| `@commitlint/cli` | Commit message linting |
| `@commitlint/config-conventional` | Standard conventional commits ruleset |

## commitlint Configuration

`commitlint.config.js` at the repo root:

```js
export default {
  extends: ['@commitlint/config-conventional'],
  rules: {
    'scope-enum': [2, 'always', [
      'auth0-fastify',
      'auth0-fastify-api',
      'ci',
      'security',
      'deps',
    ]],
    'scope-empty': [1, 'never'],
  },
};
```

- `scope-enum` (error): scope must be one of the listed values when present
- `scope-empty` (warning): encourages use of a scope but does not block commits

The scope list reflects the existing commit history. New scopes can be added here as the repo evolves.

## Local Hook (Husky)

1. `npm pkg set scripts.prepare="husky"` — adds the prepare lifecycle hook
2. `npx husky init` — creates `.husky/` directory
3. `.husky/commit-msg` contains: `npx --no -- commitlint --edit $1`

Devs receive the hook automatically after `npm install` because npm runs `prepare` post-install.

## CI Enforcement

A new `commitlint` job added to `.github/workflows/test.yml`, triggered on `pull_request` events only (commits to `main` have already passed a PR):

```yaml
commitlint:
  name: Commitlint
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@<sha> # v6
      with:
        fetch-depth: 0
    - uses: wagoid/commitlint-github-action@<sha> # v6
      with:
        configFile: commitlint.config.js
```

The action is pinned to a SHA following the repo's existing security convention for GitHub Actions.

## Scope List

| Scope | When to use |
|---|---|
| `auth0-fastify` | Changes to `packages/auth0-fastify` |
| `auth0-fastify-api` | Changes to `packages/auth0-fastify-api` |
| `ci` | GitHub Actions / CI workflow changes |
| `security` | Security hardening (actions pinning, Snyk, etc.) |
| `deps` | Dependency updates (Dependabot, manual bumps) |

## Examples

```
feat(auth0-fastify): add logout redirect support
fix(auth0-fastify-api): handle expired token edge case
chore(deps): bump vitest from 2.0 to 2.1
ci: add commitlint enforcement
```
