# Updating Gommage

Gommage uses two verbs deliberately:

- `gommage update` checks whether a newer installable release exists. It does
  not install or replace binaries, policy, or host integration files, but it may
  refresh the local update-check cache.
- `gommage upgrade` installs or reinstalls Gommage through an installer that
  verifies the selected release archive.

Use `update` when you want release information without changing the installed
product. Use `upgrade` when you want the local installation to change.

## Check For Updates

```sh
gommage update
gommage update --json
```

The check compares the running `gommage` version with the newest
`gommage-cli-v*` GitHub Release that contains an archive for the current
platform. Human output includes the current tag, latest tag, release asset, and
the next command.

For scripts, use:

```sh
gommage update --check
```

`--check` exits with status `1` only when an upgrade is available. That makes it
useful in periodic workstation checks or CI jobs that only need to detect drift.

## Upgrade Binaries

```sh
gommage upgrade
```

`upgrade` downloads the repository installer and delegates binary installation
to `scripts/install.sh`. The installer verifies the release archive with
Sigstore and SHA-256 before writing `gommage`, `gommage-daemon`, and
`gommage-mcp`.

The downloaded installer is sourced from the repository's mutable `main` branch
unless the caller supplies a different reviewed source. Binary files are then
replaced sequentially with per-file backups; the operation is not an atomic
three-binary transaction. A failure can leave a mixed installation. The current
`--verify` path reports each companion's version string but does not compare
binary compatibility, so it cannot certify that the installed set is coherent
and does not roll prior writes back. Keep the backups until the three files have
been restored or reinstalled from the intended verified archive and the normal
health checks pass. For a stricter bootstrap, download and review the installer
at a pinned commit before executing it.

By default, `gommage upgrade` targets the directory containing the running
`gommage` executable. Override that when the install location is different:

```sh
gommage upgrade --bin-dir "$HOME/.local/bin"
```

Preview the operation before running it:

```sh
gommage upgrade --dry-run
```

Pin a specific release when testing or rolling back:

```sh
gommage upgrade --version gommage-cli-vX.Y.Z-beta.N
```

If the latest release is already installed, `gommage upgrade` exits without
reinstalling. Use `--force` to repair or reinstall the current release:

```sh
gommage upgrade --force
```

Run the readiness health gate after binary installation. It checks the local
operator path, not three-binary version compatibility:

```sh
gommage upgrade --verify
```

## Update Agent Skills

The Codex and Claude Code skill can change independently of binary releases.
Refresh only the skill when docs, agent workflows, or setup guidance changed:

```sh
gommage upgrade --skill-only --skill-agent codex --skill-agent claude --no-prompt
```

Upgrade binaries and refresh skills in one operation:

```sh
gommage upgrade \
  --with-skill \
  --skill-agent codex \
  --skill-agent claude \
  --verify
```

Restart Codex or Claude Code after skill updates so the host discovers the new
skill files.

Remote skill updates default to the mutable `main` ref and are not protected by
the binary archive's Sigstore signature. Use `--skill-ref <reviewed-commit>` when
you need a reproducible skill snapshot.

## When To Run Each Command

Run `gommage update`:

- before a beta test pass;
- when Gommage reports behavior that does not match current docs;
- after a teammate says a newer release exists;
- from automation that should report drift without mutating the workstation.

Run `gommage upgrade`:

- when `gommage update` reports `upgrade_available`;
- after a release note fixes a host-agent compatibility issue that affects you;
- when `gommage verify` or `gommage beta check` reports a local health failure;
- with `--force` when reinstalling the same release to repair missing companion
  binaries.

Run `gommage upgrade --skill-only`:

- after documentation-only or skill-only improvements;
- before asking an agent to operate an existing Gommage checkout;
- when Codex or Claude Code behavior changed but no binary upgrade is needed.
