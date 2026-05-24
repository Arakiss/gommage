import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";

const providerDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(providerDir, "../..");

function repoPath(...parts) {
  return join(repoRoot, ...parts);
}

function gommageBinary() {
  return process.env.GOMMAGE_BIN || repoPath("target", "debug", "gommage");
}

function setupIsolatedHome(agent) {
  const root = mkdtempSync(join(tmpdir(), "gommage-promptfoo-"));
  const home = join(root, "home");
  const claudeDir = join(home, ".claude");
  const codexDir = join(home, ".codex");
  const systemdDir = join(root, "systemd-user");
  const launchdDir = join(root, "launchd");

  mkdirSync(claudeDir, { recursive: true });
  mkdirSync(codexDir, { recursive: true });
  mkdirSync(systemdDir, { recursive: true });
  mkdirSync(launchdDir, { recursive: true });

  writeFileSync(
    join(claudeDir, "settings.json"),
    JSON.stringify(
      {
        permissions: {
          allow: ["Bash", "Read(./docs/**)"],
          deny: ["Read(./secrets/**)"],
        },
        hooks: { PreToolUse: [] },
      },
      null,
      2,
    ),
  );
  writeFileSync(join(codexDir, "hooks.json"), '{"PreToolUse":[]}\n');
  writeFileSync(join(codexDir, "config.toml"), 'sandbox_mode = "workspace-write"\n[features]\n');

  return {
    root,
    env: {
      HOME: home,
      GOMMAGE_HOME: join(home, ".gommage"),
      GOMMAGE_CLAUDE_SETTINGS: join(claudeDir, "settings.json"),
      GOMMAGE_CODEX_HOOKS: join(codexDir, "hooks.json"),
      GOMMAGE_CODEX_CONFIG: join(codexDir, "config.toml"),
      GOMMAGE_SYSTEMD_USER_DIR: systemdDir,
      GOMMAGE_LAUNCHD_DIR: launchdDir,
      GOMMAGE_EVAL_AGENT: agent || "claude",
    },
  };
}

function parseStdin(raw) {
  if (!raw) {
    return null;
  }
  try {
    return JSON.parse(raw);
  } catch {
    return raw;
  }
}

function runCommand(vars, env) {
  const argv = Array.isArray(vars.argv)
    ? vars.argv
    : typeof vars.argvJson === "string"
      ? JSON.parse(vars.argvJson)
      : null;
  if (!Array.isArray(argv) || argv.length === 0) {
    throw new Error("Each eval case must define vars.argvJson as a non-empty JSON array");
  }
  const stdin = vars.stdinJson ? parseStdin(vars.stdinJson) : parseStdin(vars.stdin);

  if (vars.seedStdlib) {
    for (const seedArgv of [
      ["init"],
      ["policy", "init", "--stdlib"],
    ]) {
      const seed = spawnSync(gommageBinary(), seedArgv, {
        cwd: repoRoot,
        env: {
          ...process.env,
          ...env,
        },
        encoding: "utf8",
        timeout: Number(vars.timeoutMs || 30_000),
      });
      if (seed.status !== 0) {
        return {
          command: [gommageBinary(), ...seedArgv].join(" "),
          exitCode: seed.status,
          signal: seed.signal,
          stdout: seed.stdout || "",
          stderr: seed.stderr || "",
          json: null,
          env: {
            GOMMAGE_HOME: env.GOMMAGE_HOME,
            GOMMAGE_EVAL_AGENT: env.GOMMAGE_EVAL_AGENT,
          },
        };
      }
    }
  }

  const child = spawnSync(gommageBinary(), argv, {
    cwd: repoRoot,
    env: {
      ...process.env,
      ...env,
    },
    input: stdin ? JSON.stringify(stdin) : undefined,
    encoding: "utf8",
    timeout: Number(vars.timeoutMs || 30_000),
  });

  const stdout = child.stdout || "";
  const stderr = child.stderr || "";
  let json = null;
  if (stdout.trim().startsWith("{") || stdout.trim().startsWith("[")) {
    try {
      json = JSON.parse(stdout);
    } catch {
      json = null;
    }
  }

  return {
    command: [gommageBinary(), ...argv].join(" "),
    exitCode: child.status,
    signal: child.signal,
    stdout,
    stderr,
    json,
    env: {
      GOMMAGE_HOME: env.GOMMAGE_HOME,
      GOMMAGE_EVAL_AGENT: env.GOMMAGE_EVAL_AGENT,
    },
  };
}

export default class GommageCliProvider {
  id() {
    return "gommage-cli";
  }

  async callApi(_prompt, context) {
    const vars = {
      ...(context?.test?.vars || {}),
      ...(context?.vars || {}),
    };
    const agent = vars.agent || "claude";
    const isolated = setupIsolatedHome(agent);

    try {
      const result = runCommand(vars, isolated.env);
      return {
        output: JSON.stringify(result),
        metadata: {
          scenario: vars.scenario,
          command: result.command,
          exitCode: result.exitCode,
        },
      };
    } finally {
      if (!vars.keepTemp) {
        rmSync(isolated.root, { recursive: true, force: true });
      }
    }
  }
}
