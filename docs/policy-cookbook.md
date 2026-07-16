# Policy cookbook

Recipes for common policy patterns. Unless a recipe says otherwise, place it in
the user layer at `~/.gommage/policy.d/`. Project policy is tightening-only and
cannot contain `decision: allow`.

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

This is a user-policy allow. Do not place it in
`<project>/.gommage/policy.d/`, because project layers cannot grant authority.

```yaml
- name: allow-project-writes
  decision: allow
  match:
    all_capability:
      - "fs.write:${EXPEDITION_ROOT}/**"
```

Everything outside `${EXPEDITION_ROOT}` will fall through and fail closed.
When no expedition is active, the runtime supplies a non-matching sentinel;
the pattern never expands to `/**`.

### Gate writes to a specific checkout

Hook adapters resolve write-like tools and parsed Bash write effects against
their trusted working directory. Gate the resulting canonical path before broad
allow rules:

```yaml
- name: gate-example-checkout-writes
  decision: gommage
  match:
    any_capability:
      - "fs.write:/Users/alex/src/example/**"
  reason: "writes to this checkout require a narrower project policy"
```

This works for direct `Write` / `Edit` tools, parsed `apply_patch` file paths,
and typed Bash write effects (`tee`, `cp` / `install`, `mv`, `touch`, `mkdir`,
`rm`, `sed -i`, `dd of=`, `>` / `>>`). Filesystem authorization is path-based;
ambient Git branch metadata may be retained in the canonical input for audit,
but it is not emitted as a capability that a policy can authorize.

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

### Bind a picto to one observed tool call

Use `bind_input: true` when approving one command is meant to authorize that
exact tool call, rather than another call with the same scope. The canonical
tool-call hash is signed into the resulting picto and checked again when it is
consumed.

```yaml
- name: gate-exact-main-push
  decision: ask_picto
  required_scope: "git.push:main"
  bind_input: true
  match:
    any_capability:
      - "git.push:refs/heads/main"
      - "git.push:refs/heads/master"
  reason: "review the exact main push before it runs"
```

`bind_input` defaults to `false` and is valid only with `decision: ask_picto`.
Direct `gommage grant --scope …` remains scope-bound; approve the pending
request from an input-bound rule to mint the exact-input form.

Current Picto signatures bind id, scope, maximum uses, expiry, creation time,
reason, and optional input hash. Mutable `uses` and `status` remain trusted
SQLite state under the operator UID. Exact-input binding prevents a grant from
authorizing a different canonical tool call; it does not make user-owned state
tamper-resistant.

### Allow pushes on feature branches

```yaml
- name: allow-feature-push
  decision: allow
  match:
    any_capability:
      - "git.push:refs/heads/feature/**"
      - "git.push:refs/heads/fix/**"
```

### Deny force-push by default, but allow with a break-glass picto

Use `decision: ask_picto` for the break-glass pattern. A `decision: gommage`
deny — even with `hard_stop: false` — is terminal: the picto store is never
consulted, so no picto can unlock it. Only an `ask_picto` rule with a
`required_scope` is picto-bypassable.

```yaml
- name: no-force-push
  decision: ask_picto
  required_scope: "git.push.force"
  match:
    any_capability:
      - "git.push.force:*"
  reason: "force push rewrites shared history; require a signed picto"
```

Unlock a single force push with:

```bash
gommage grant --scope git.push.force --reason "rebase landed; rewriting my topic branch"
gommage confirm <picto-id>
```

To make force-push an un-bypassable hard deny instead, use
`decision: gommage` with `hard_stop: true`.

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

Within one layer and one capability, order matters: the first positively
covering rule contributes for that layer. The deny still wins if it contributes
from another active layer or covers a sibling capability in the same call.

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

The evaluator does not choose one rule for the whole tool call. It normalizes,
sorts, and deduplicates capabilities, resolves each capability independently,
and records at most one first-match contribution per layer and capability.
Active layers are unique and ordered `org`, `user`, `project`. Project policy
may contribute only `ask_picto` or `gommage`.

The final aggregation is conservative:

1. A policy deny wins.
2. Otherwise, any capability unresolved by every layer fails closed.
3. Otherwise, `ask_picto` wins over allow.
4. Two distinct required Picto scopes in one call fail closed; split the call.
5. Only when every capability resolves and no deny or ask remains is the call
   allowed.

Declared order still matters inside one layer and capability: filenames are
lexicographic, then rules use declaration order. If the result is unexpected,
check:

1. Does every emitted capability have positive coverage? Run `gommage map
   --json`, then inspect signed capability provenance in the decision audit
   record.
2. Is an earlier rule in the same layer covering that capability? Run
   `gommage policy check` and inspect.
3. Is your glob too permissive? Globs use `/` as a segment separator — `*` does
   not cross `/`; use `**` for recursive matches.
4. Are the active layers really `org`, `user`, `project`? Run `gommage policy
   layers --json`.
5. Is `${EXPEDITION_ROOT}` active? Run `gommage expedition status`.

### Policy variable substitution

Policy loading accepts `${VAR}` and `${VAR:-default}`. A missing or empty value
is an error unless the expression supplies a non-empty default. This is a
security boundary: an unset path variable cannot silently turn
`fs.write:${ROOT}/**` into `fs.write:/**`.

Project policy is reviewed tightening input, not a source of grants. For
example, this is valid in a project layer:

```yaml
- name: gate-this-project-deploy
  decision: ask_picto
  required_scope: "deploy.example:production"
  bind_input: true
  match:
    any_capability:
      - "deploy.example:production"
  reason: "this repository requires review of the exact production deploy"
```

The same file with `decision: allow` fails policy loading.

## Regression fixtures

Policy behavior should be versioned next to the policies themselves. Keep a
small fixture file in the repository and run it in CI:

```yaml
version: 1
cases:
  - name: main_push_requires_picto
    tool: Bash
    input:
      command: git push origin main
    expect:
      decision: ask_picto
      required_scope: git.push:main
      matched_rule: gate-main-push

  - name: feature_push_is_allowed
    tool: Bash
    input:
      command: git push origin chore/test-branch
    expect:
      decision: allow
      matched_rule: allow-feature-push
```

Run it with:

```sh
gommage policy test examples/policy-fixtures.yaml
gommage policy test examples/policy-fixtures.yaml --json
```

Export the fixture JSON Schema when an editor, CI generator, or agent needs to
validate the file contract before running semantic checks:

```sh
gommage policy schema > gommage-policy-fixture.schema.json
```

Generate a fixture from the current mapper and policy behavior when you want to
capture what happened before editing the YAML:

```sh
echo '{"tool":"Bash","input":{"command":"git push origin main"}}' \
  | gommage policy snapshot --name main_push_requires_picto
```

Inspect mapper output alone before deciding which policy rule to write:

```sh
echo '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git push --force origin main"}}' \
  | gommage map --json --hook
```

`gommage map` reports `input_hash`, the active `capabilities_dir`, mapper rule
count, and emitted capabilities without loading policy or writing audit entries.
Use `--hook` for real PreToolUse payloads; omit it for canonical `ToolCall`
JSON.

The generated YAML includes the observed decision, `hard_stop` or
`required_scope` when relevant, and the matched policy rule if one matched.
Review the output before committing it; the snapshot captures current behavior,
not necessarily desired behavior.

`policy test --json` reports the emitted capabilities, matched rule, actual
decision, expected decision, and mismatch errors for every case. Use
`gommage smoke --json` to verify the shipped stdlib, then use `policy test` to
verify the policy behavior your repository depends on. `policy schema` emits
the official JSON Schema for both supported fixture shapes: a wrapped document
with `version: 1` plus `cases`, or a top-level list of cases.

## Debugging

```sh
# Show mapper output without policy evaluation
echo '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git push --force origin main"}}' | gommage map --hook

# Show which rule matched a given call
echo '{"tool":"Bash","input":{"command":"git push origin main"}}' | gommage decide --pretty

# Print the loaded policy version hash
gommage policy hash
```
