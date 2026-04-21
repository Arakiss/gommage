# Policy cookbook

Recipes for common policy patterns. Drop any of these into `~/.gommage/policy.d/`.

## Filesystem

### Deny writes to build artifacts

```yaml
- name: no-writes-to-build-artifacts
  decision: gommage
  match:
    any_capability:
      - "fs.write:**/node_modules/**"
      - "fs.write:**/.next/**"
      - "fs.write:**/target/**"
      - "fs.write:**/dist/**"
      - "fs.write:**/.git/**"
  reason: "build artifacts are not edit targets"
```

### Sandbox the agent to the current project

```yaml
- name: allow-project-writes
  decision: allow
  match:
    all_capability:
      - "fs.write:${EXPEDITION_ROOT}/**"
```

Everything outside `${EXPEDITION_ROOT}` will fall through and fail closed.

### Protect user credentials

```yaml
- name: block-dotfiles
  decision: gommage
  hard_stop: true
  match:
    any_capability:
      - "fs.write:${HOME}/.ssh/**"
      - "fs.write:${HOME}/.aws/**"
      - "fs.write:${HOME}/.gnupg/**"
      - "fs.read:${HOME}/.ssh/id_*"
      - "fs.read:${HOME}/.aws/credentials"
  reason: "credential directories are out of bounds"
```

Note `hard_stop: true` — even a picto can't bypass this.

## Git

### Gate pushes to main/master behind a picto

```yaml
- name: gate-main-push
  decision: ask_picto
  required_scope: "git.push:main"
  match:
    any_capability:
      - "git.push:refs/heads/main"
      - "git.push:refs/heads/master"
  reason: "pushes to main require a signed picto"
```

Then, when you want to push: `gommage grant --scope git.push:main --uses 1 --ttl 5m`.

### Allow pushes on feature branches

```yaml
- name: allow-feature-push
  decision: allow
  match:
    any_capability:
      - "git.push:refs/heads/feature/**"
      - "git.push:refs/heads/fix/**"
```

### Deny force-push (but allow with picto)

```yaml
- name: no-force-push
  decision: gommage
  hard_stop: false   # allow break-glass
  match:
    any_capability:
      - "git.push.force:*"
  reason: "force push requires a picto"
```

## Network / package managers

### Only allow installs from known registries

```yaml
- name: allow-known-registries
  decision: allow
  match:
    any_capability:
      - "net.out:registry.npmjs.org"
      - "net.out:crates.io"
      - "net.out:pypi.org"

- name: deny-other-outbound
  decision: gommage
  match:
    any_capability:
      - "net.out:**"
  reason: "outbound network limited to approved registries"
```

Order matters — the `allow` rule must come before the `deny`.

## Deployments

### Gate production deploys

```yaml
- name: gate-prod-deploy
  decision: ask_picto
  required_scope: "deploy.vercel:prod"
  match:
    any_capability:
      - "deploy.vercel:<prod-or-preview>"
  reason: "vercel prod requires a picto"
```

## Composing rules

The evaluator runs rules in **declared order** (lexicographic filename, then declared index). First match wins. If you're having trouble getting the decision you want, check:

1. Is an earlier rule accidentally matching? Run `gommage policy check` and inspect.
2. Is your glob too permissive? Globs use `/` as a segment separator — `*` does NOT cross `/`. Use `**` for recursive matches.
3. Is `${EXPEDITION_ROOT}` set? Run `gommage expedition status`.

## Debugging

```sh
# Show which rule matched a given call
echo '{"tool":"Bash","input":{"command":"git push origin main"}}' | gommage decide --pretty

# Print the loaded policy version hash
gommage policy hash
```
