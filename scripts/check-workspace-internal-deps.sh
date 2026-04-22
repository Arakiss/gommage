#!/bin/sh
set -eu

repo_root="${GOMMAGE_WORKSPACE_ROOT:-}"
if [ -z "$repo_root" ]; then
  repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
fi

cd "$repo_root"

metadata_file="$(mktemp)"
trap 'rm -f "$metadata_file"' EXIT

cargo metadata --locked --format-version 1 --no-deps > "$metadata_file"

GOMMAGE_METADATA_JSON="$metadata_file" ruby <<'RUBY'
require "json"

metadata = JSON.parse(File.read(ENV.fetch("GOMMAGE_METADATA_JSON")))
workspace_ids = metadata.fetch("workspace_members")
packages = metadata.fetch("packages").select { |package| workspace_ids.include?(package.fetch("id")) }
versions = packages.to_h { |package| [package.fetch("name"), package.fetch("version")] }
internal_versions = versions.select { |name, _version| name.start_with?("gommage-") }

failures = []
checked_edges = 0

packages.each do |package|
  package.fetch("dependencies", []).each do |dependency|
    name = dependency.fetch("name")
    expected_version = internal_versions[name]
    next unless expected_version

    checked_edges += 1
    expected_req = "=#{expected_version}"
    actual_req = dependency.fetch("req")
    unless actual_req == expected_req
      failures << "#{package.fetch("name")}: #{name} uses #{actual_req.inspect}; expected #{expected_req.inspect}"
    end

    unless dependency["path"]
      failures << "#{package.fetch("name")}: #{name} must point at the local workspace path"
    end
  end
end

root_manifest = ENV.fetch("GOMMAGE_ROOT_CARGO_TOML", "Cargo.toml")
root_text = File.read(root_manifest)
in_workspace_dependencies = false

root_text.each_line.with_index(1) do |line, line_number|
  if (section = line.match(/^\s*\[([^\]]+)\]\s*$/))
    in_workspace_dependencies = section[1] == "workspace.dependencies"
    next
  end

  next unless in_workspace_dependencies
  next if line.strip.empty? || line.lstrip.start_with?("#")

  assignment = line.match(/^\s*(gommage-[A-Za-z0-9_-]+)\s*=\s*(.+?)\s*(?:#.*)?$/)
  next unless assignment

  name = assignment[1]
  next unless internal_versions.key?(name)

  body = assignment[2]
  expected_req = "=#{internal_versions.fetch(name)}"
  version = body[/\bversion\s*=\s*"([^"]+)"/, 1]
  path = body[/\bpath\s*=\s*"([^"]+)"/, 1]

  if !body.start_with?("{") || !body.end_with?("}")
    failures << "#{root_manifest}:#{line_number}: workspace dependency #{name} must use an inline table with version and path"
  end
  if version != expected_req
    failures << "#{root_manifest}:#{line_number}: workspace dependency #{name} uses #{version.inspect}; expected #{expected_req.inspect}"
  end
  if path.nil? || path.empty?
    failures << "#{root_manifest}:#{line_number}: workspace dependency #{name} must include a local path"
  end
end

if failures.any?
  warn "workspace internal dependency invariant failed:"
  failures.each { |failure| warn "  - #{failure}" }
  exit 1
end

puts "workspace internal dependency invariants ok (#{internal_versions.size} internal crates, #{checked_edges} dependency edges)"
RUBY
