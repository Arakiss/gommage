#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { createHash } from "node:crypto";
import path from "node:path";
import { tmpdir } from "node:os";
import process from "node:process";

const PUBLISH_ORDER = [
  "gommage-stdlib",
  "gommage-core",
  "gommage-audit",
  "gommage-cli",
  "gommage-daemon",
  "gommage-mcp",
];

const CRATES_IO_INDEX = "registry+https://github.com/rust-lang/crates.io-index";
const REGISTRY_API = "https://crates.io/api/v1/crates/new";
const FORMAT = "cargo-registry-publish-bundle-v1";

function usage() {
  process.stdout.write(`Usage: node scripts/prepare-crates-publish-bundles.mjs [options]\n\nOptions:\n  --output <dir>       Empty destination directory for sealed publish bundles\n  --source-sha <sha>   Expected source commit (defaults to git HEAD)\n  --cli-tag <tag>      Require gommage-cli-v<version> to match this release tag\n  --allow-dirty        Permit local test generation from a dirty tree\n  -h, --help           Show this help\n\nThe generated .publish files are complete Cargo registry upload request bodies.\nThis command never reads a registry credential and never mutates crates.io.\n`);
}

function fail(message) {
  throw new Error(`prepare-crates-publish-bundles: ${message}`);
}

function parseArgs(argv) {
  const options = {
    output: "",
    sourceSha: "",
    cliTag: "",
    allowDirty: false,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    switch (argument) {
      case "--output":
        options.output = argv[index + 1] ?? "";
        index += 1;
        break;
      case "--source-sha":
        options.sourceSha = argv[index + 1] ?? "";
        index += 1;
        break;
      case "--cli-tag":
        options.cliTag = argv[index + 1] ?? "";
        index += 1;
        break;
      case "--allow-dirty":
        options.allowDirty = true;
        break;
      case "-h":
      case "--help":
        usage();
        process.exit(0);
        break;
      default:
        fail(`unknown argument: ${argument}`);
    }
  }

  if (!options.output) {
    fail("--output is required");
  }
  if (options.sourceSha && !/^[0-9a-f]{40,64}$/.test(options.sourceSha)) {
    fail("--source-sha must be a lowercase hexadecimal Git object ID");
  }
  return options;
}

function run(command, args, options = {}) {
  return execFileSync(command, args, {
    cwd: options.cwd,
    encoding: "utf8",
    stdio: options.capture ? ["ignore", "pipe", "inherit"] : "inherit",
    env: {
      ...process.env,
      CARGO_TERM_COLOR: "never",
    },
  });
}

function runBuffer(command, args, options = {}) {
  return execFileSync(command, args, {
    cwd: options.cwd,
    encoding: null,
    stdio: ["ignore", "pipe", "inherit"],
    env: {
      ...process.env,
      CARGO_TERM_COLOR: "never",
    },
  });
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function writeSealed(filePath, bytes) {
  writeFileSync(filePath, bytes, { flag: "wx", mode: 0o444 });
  chmodSync(filePath, 0o444);
}

function relativeManifestPath(packageRoot, absolutePath) {
  if (!absolutePath) {
    return null;
  }
  const relative = path.relative(packageRoot, absolutePath);
  if (!relative || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    fail(`metadata path is outside package root: ${absolutePath}`);
  }
  return relative.split(path.sep).join("/");
}

function sortedObject(value) {
  return Object.fromEntries(
    Object.entries(value ?? {}).sort(([left], [right]) => left.localeCompare(right)),
  );
}

function dependencyMetadata(dependency) {
  if (dependency.registry !== null) {
    fail(`alternate registry dependency is not publishable to crates.io: ${dependency.name}`);
  }
  if (dependency.source !== CRATES_IO_INDEX) {
    fail(`non-crates.io dependency is not publishable: ${dependency.name}`);
  }

  const metadata = {
    optional: dependency.optional,
    default_features: dependency.uses_default_features,
    name: dependency.name,
    features: dependency.features,
    version_req: dependency.req,
    target: dependency.target,
    kind: dependency.kind ?? "normal",
  };
  if (dependency.rename !== null) {
    metadata.explicit_name_in_toml = dependency.rename;
  }
  return metadata;
}

function readArchiveEntry(cratePath, archiveEntry) {
  return runBuffer("tar", ["-xOzf", cratePath, archiveEntry]);
}

function normalizedPackageMetadata(cratePath, name, version) {
  const archiveRoot = `${name}-${version}`;
  const normalizedManifest = readArchiveEntry(cratePath, `${archiveRoot}/Cargo.toml`);
  const metadataRoot = mkdtempSync(path.join(tmpdir(), "gommage-publish-metadata-"));
  const manifestPath = path.join(metadataRoot, "Cargo.toml");
  writeFileSync(manifestPath, normalizedManifest, { flag: "wx", mode: 0o444 });
  try {
    const metadata = JSON.parse(
      run(
        "cargo",
        ["metadata", "--format-version", "1", "--no-deps", "--manifest-path", manifestPath],
        { capture: true },
      ),
    );
    if (metadata.packages.length !== 1 || metadata.packages[0].name !== name) {
      fail(`normalized package metadata does not identify ${name}`);
    }
    return {
      pkg: metadata.packages[0],
      archiveRoot,
      normalizedManifest: normalizedManifest.toString("utf8"),
    };
  } finally {
    rmSync(metadataRoot, { recursive: true, force: false });
  }
}

function packageMetadata(cratePath, normalized) {
  const { pkg, archiveRoot, normalizedManifest } = normalized;
  const packageRoot = path.dirname(pkg.manifest_path);
  if (/^\s*\[badges\]\s*$/m.test(normalizedManifest)) {
    fail(`${pkg.name} uses deprecated badges that this sealed-bundle generator does not support`);
  }

  const readmeFile = relativeManifestPath(packageRoot, pkg.readme);
  const licenseFile = relativeManifestPath(packageRoot, pkg.license_file);

  if (licenseFile !== null) {
    readArchiveEntry(cratePath, `${archiveRoot}/${licenseFile}`);
  }

  return {
    name: pkg.name,
    vers: pkg.version,
    deps: pkg.dependencies.map(dependencyMetadata),
    features: sortedObject(pkg.features),
    authors: pkg.authors,
    description: pkg.description,
    documentation: pkg.documentation,
    homepage: pkg.homepage,
    readme:
      readmeFile === null
        ? null
        : readArchiveEntry(cratePath, `${archiveRoot}/${readmeFile}`).toString("utf8"),
    readme_file: readmeFile,
    keywords: pkg.keywords,
    categories: pkg.categories,
    license: pkg.license,
    license_file: licenseFile,
    repository: pkg.repository,
    badges: {},
    links: pkg.links,
    rust_version: pkg.rust_version,
  };
}

function u32le(value) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) {
    fail(`publish frame length is outside u32: ${value}`);
  }
  const buffer = Buffer.allocUnsafe(4);
  buffer.writeUInt32LE(value);
  return buffer;
}

function framePublishRequest(metadataBytes, crateBytes) {
  return Buffer.concat([
    u32le(metadataBytes.length),
    metadataBytes,
    u32le(crateBytes.length),
    crateBytes,
  ]);
}

function verifyFrame(requestBytes, metadataBytes, crateBytes) {
  if (requestBytes.length < 8) {
    fail("publish request body is truncated");
  }
  const metadataLength = requestBytes.readUInt32LE(0);
  if (metadataLength !== metadataBytes.length) {
    fail("publish request metadata length does not match");
  }
  const crateLengthOffset = 4 + metadataLength;
  if (crateLengthOffset + 4 > requestBytes.length) {
    fail("publish request crate length is truncated");
  }
  const crateLength = requestBytes.readUInt32LE(crateLengthOffset);
  if (crateLength !== crateBytes.length) {
    fail("publish request crate length does not match");
  }
  if (!requestBytes.subarray(4, crateLengthOffset).equals(metadataBytes)) {
    fail("publish request metadata bytes do not match");
  }
  if (!requestBytes.subarray(crateLengthOffset + 4).equals(crateBytes)) {
    fail("publish request crate bytes do not match");
  }
}

function ensureEmptyOutput(outputDir) {
  if (existsSync(outputDir)) {
    if (!lstatSync(outputDir).isDirectory()) {
      fail(`output path is not a directory: ${outputDir}`);
    }
    if (readdirSync(outputDir).length > 0) {
      fail(`output directory must be empty: ${outputDir}`);
    }
  } else {
    mkdirSync(outputDir, { recursive: true, mode: 0o755 });
  }
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  const repoRoot = run("git", ["rev-parse", "--show-toplevel"], { capture: true }).trim();
  const headSha = run("git", ["rev-parse", "HEAD"], { cwd: repoRoot, capture: true }).trim();
  const sourceSha = options.sourceSha || headSha;
  if (sourceSha !== headSha) {
    fail(`source SHA ${sourceSha} does not match checked-out HEAD ${headSha}`);
  }

  const dirty = run("git", ["status", "--porcelain", "--untracked-files=all"], {
    cwd: repoRoot,
    capture: true,
  }).trim().length > 0;
  if (dirty && !options.allowDirty) {
    fail("source tree is dirty; release bundles require an exact committed tree");
  }

  const outputDir = path.resolve(repoRoot, options.output);
  ensureEmptyOutput(outputDir);

  const cargoMetadata = JSON.parse(
    run("cargo", ["metadata", "--format-version", "1", "--no-deps", "--locked"], {
      cwd: repoRoot,
      capture: true,
    }),
  );
  const packages = new Map(cargoMetadata.packages.map((pkg) => [pkg.name, pkg]));
  for (const name of PUBLISH_ORDER) {
    if (!packages.has(name)) {
      fail(`workspace package is missing: ${name}`);
    }
  }

  const cliPackage = packages.get("gommage-cli");
  const expectedCliTag = `gommage-cli-v${cliPackage.version}`;
  if (options.cliTag && options.cliTag !== expectedCliTag) {
    fail(`release tag ${options.cliTag} does not match ${expectedCliTag}`);
  }

  const manifestPackages = [];
  for (const [order, name] of PUBLISH_ORDER.entries()) {
    const pkg = packages.get(name);
    const crateFile = `${name}-${pkg.version}.crate`;
    const metadataFile = `${name}-${pkg.version}.metadata.json`;
    const requestFile = `${name}-${pkg.version}.publish`;
    const cargoCratePath = path.join(cargoMetadata.target_directory, "package", crateFile);
    if (existsSync(cargoCratePath)) {
      unlinkSync(cargoCratePath);
    }

    const packageArgs = ["package", "--locked", "-p", name];
    if (name !== "gommage-stdlib") {
      packageArgs.push("--no-verify");
    }
    if (options.allowDirty) {
      packageArgs.push("--allow-dirty");
    }
    process.stdout.write(`package ${name} ${pkg.version}\n`);
    run("cargo", packageArgs, { cwd: repoRoot });

    if (!existsSync(cargoCratePath) || !statSync(cargoCratePath).isFile()) {
      fail(`cargo did not produce ${cargoCratePath}`);
    }
    const crateBytes = readFileSync(cargoCratePath);
    const normalized = normalizedPackageMetadata(cargoCratePath, name, pkg.version);
    const metadata = packageMetadata(cargoCratePath, normalized);
    // Cargo serializes the metadata with serde_json::to_string, without
    // trailing whitespace, before adding the little-endian length prefix.
    const metadataBytes = Buffer.from(JSON.stringify(metadata), "utf8");
    const requestBytes = framePublishRequest(metadataBytes, crateBytes);
    verifyFrame(requestBytes, metadataBytes, crateBytes);

    writeSealed(path.join(outputDir, crateFile), crateBytes);
    writeSealed(path.join(outputDir, metadataFile), metadataBytes);
    writeSealed(path.join(outputDir, requestFile), requestBytes);

    manifestPackages.push({
      order,
      name,
      version: pkg.version,
      crate_file: crateFile,
      crate_sha256: sha256(crateBytes),
      crate_size: crateBytes.length,
      metadata_file: metadataFile,
      metadata_sha256: sha256(metadataBytes),
      metadata_size: metadataBytes.length,
      request_file: requestFile,
      request_sha256: sha256(requestBytes),
      request_size: requestBytes.length,
    });
  }

  const manifest = {
    format: FORMAT,
    registry_api: REGISTRY_API,
    repository: "Arakiss/gommage",
    source_sha: sourceSha,
    release_tag: options.cliTag || expectedCliTag,
    dirty,
    packages: manifestPackages,
  };
  const manifestBytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  writeSealed(path.join(outputDir, "manifest.json"), manifestBytes);
  const manifestChecksum = `${sha256(manifestBytes)}  manifest.json\n`;
  writeSealed(path.join(outputDir, "manifest.sha256"), manifestChecksum);

  process.stdout.write(
    `prepared ${manifestPackages.length} sealed crates.io publish bundles for ${sourceSha}\n`,
  );
}

try {
  main();
} catch (error) {
  process.stderr.write(`${error.message}\n`);
  process.exit(1);
}
