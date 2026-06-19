# Conventional Commits Enforcement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enforce conventional commit message format locally via a Husky git hook and in CI via a GitHub Actions job.

**Architecture:** Install commitlint + Husky as root dev dependencies. Husky registers a `commit-msg` hook via the npm `prepare` lifecycle so it installs automatically for all contributors. A new `commitlint` CI job validates PR commits using `wagoid/commitlint-github-action` pinned to a SHA.

**Tech Stack:** Husky v9, @commitlint/cli, @commitlint/config-conventional, wagoid/commitlint-github-action v6.2.1

---

## File Map

| Action | File | Change |
|--------|------|--------|
| Create | `commitlint.config.js` | commitlint rule config |
| Create | `.husky/commit-msg` | git hook script |
| Modify | `package.json` | add deps + `prepare` script |
| Modify | `.github/workflows/test.yml` | add `commitlint` job |

---

### Task 1: Install dependencies and configure the prepare script

**Files:**
- Modify: `package.json`

- [ ] **Step 1: Install commitlint and husky as root dev dependencies**

Run from the repo root:

```bash
npm install --save-dev husky @commitlint/cli @commitlint/config-conventional
```

Expected: `package.json` `devDependencies` now includes `husky`, `@commitlint/cli`, and `@commitlint/config-conventional`.

- [ ] **Step 2: Add the prepare script to package.json**

```bash
npm pkg set scripts.prepare="husky"
```

Expected: `package.json` `scripts` now contains `"prepare": "husky"`.

- [ ] **Step 3: Verify package.json looks correct**

`package.json` scripts section should now be:

```json
"scripts": {
  "prepare": "husky",
  "build": "turbo run build",
  "clean": "turbo run clean",
  "test": "turbo run test",
  "lint": "turbo run lint",
  "docs": "typedoc"
}
```

- [ ] **Step 4: Commit**

```bash
git add package.json package-lock.json
git commit -m "chore(deps): install husky and commitlint"
```

---

### Task 2: Create the commitlint configuration

**Files:**
- Create: `commitlint.config.js`

- [ ] **Step 1: Create the config file**

Create `commitlint.config.js` at the repo root with this exact content:

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

Rule severity meanings: `2` = error (blocks commit), `1` = warning (allows commit).

`scope-enum` (error): when a scope is provided it must be one of the five listed values.  
`scope-empty` (warning): nudges contributors to include a scope but does not block commits that omit one.

- [ ] **Step 2: Smoke-test the config with a valid message**

```bash
echo "feat(auth0-fastify): add something" | npx commitlint
```

Expected: exits 0 with no output.

- [ ] **Step 3: Smoke-test the config with an invalid message**

```bash
echo "this is not conventional" | npx commitlint
```

Expected: exits non-zero and prints an error mentioning `subject-full-stop` or `type-empty`.

- [ ] **Step 4: Smoke-test scope enforcement**

```bash
echo "feat(bad-scope): something" | npx commitlint
```

Expected: exits non-zero and prints an error mentioning `scope-enum`.

- [ ] **Step 5: Commit**

```bash
git add commitlint.config.js
git commit -m "chore(ci): add commitlint configuration"
```

---

### Task 3: Set up the Husky commit-msg hook

**Files:**
- Create: `.husky/commit-msg`

- [ ] **Step 1: Initialise Husky**

```bash
npx husky init
```

Expected: `.husky/` directory created (or already exists) and a `.husky/pre-commit` file created.

- [ ] **Step 2: Remove the default pre-commit hook**

The `husky init` command creates a `.husky/pre-commit` stub. Delete it — this repo doesn't use a pre-commit hook:

```bash
rm .husky/pre-commit
```

- [ ] **Step 3: Create the commit-msg hook**

Create `.husky/commit-msg` with this exact content:

```sh
npx --no -- commitlint --edit $1
```

> `--no` prevents npx from installing packages not already present. `--edit $1` tells commitlint to read the commit message file passed by git.

- [ ] **Step 4: Make the hook executable**

```bash
chmod +x .husky/commit-msg
```

- [ ] **Step 5: Test the hook locally with a valid message**

```bash
echo "feat(auth0-fastify): test hook" > /tmp/test-commit-msg
npx --no -- commitlint --edit /tmp/test-commit-msg
```

Expected: exits 0.

- [ ] **Step 6: Test the hook locally with an invalid message**

```bash
echo "bad commit message" > /tmp/test-bad-msg
npx --no -- commitlint --edit /tmp/test-bad-msg
```

Expected: exits non-zero with a commitlint error.

- [ ] **Step 7: Commit**

```bash
git add .husky/commit-msg
git commit -m "chore(ci): add husky commit-msg hook"
```

---

### Task 4: Add the commitlint CI job

**Files:**
- Modify: `.github/workflows/test.yml`

- [ ] **Step 1: Add the commitlint job to the workflow**

Open `.github/workflows/test.yml` and add the following job after the existing `lint` job:

```yaml
  commitlint:
    name: Commitlint
    runs-on: ubuntu-latest
    if: github.event_name == 'pull_request'
    steps:
      - name: Checkout code
        uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10 # v6.0.3
        with:
          fetch-depth: 0

      - name: Validate conventional commits
        uses: wagoid/commitlint-github-action@b948419dd99f3fd78a6548d48f94e3df7f6bf3ed # v6.2.1
        with:
          configFile: commitlint.config.js
```

Notes:
- `fetch-depth: 0` is required — the action needs the full history to compare against the base branch.
- The SHA `b948419dd99f3fd78a6548d48f94e3df7f6bf3ed` pins to `wagoid/commitlint-github-action@v6.2.1`, following the repo's security convention (all other actions are pinned by SHA with a version comment).
- `if: github.event_name == 'pull_request'` skips this job on direct pushes to `main` and on `workflow_dispatch` — those commits have already been validated via a PR.

- [ ] **Step 2: Verify the workflow YAML is valid**

```bash
cat .github/workflows/test.yml
```

Check that the indentation is consistent and the `commitlint` job aligns with the other jobs under the `jobs:` key.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/test.yml
git commit -m "ci: add commitlint GitHub Actions job"
```
