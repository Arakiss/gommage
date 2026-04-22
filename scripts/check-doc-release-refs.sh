#!/bin/sh
set -eu

repo_root="${GOMMAGE_WORKSPACE_ROOT:-}"
if [ -z "$repo_root" ]; then
  repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
fi

cd "$repo_root"

ruby <<'RUBY'
paths = [
  "README.md",
  "docs",
  "scripts",
  "skills",
  ".github/workflows",
].select { |path| File.exist?(path) }

pattern = /gommage-cli-v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?/
allowed = [
  %r{\ACHANGELOG\.md\z},
  %r{\Acrates/[^/]+/CHANGELOG\.md\z},
]

files = paths.flat_map do |path|
  if File.directory?(path)
    Dir.glob("#{path}/**/*", File::FNM_DOTMATCH).select { |entry| File.file?(entry) }
  else
    [path]
  end
end

failures = []

files.sort.each do |file|
  relative = file.sub(%r{\A\./}, "")
  next if allowed.any? { |rule| rule.match?(relative) }

  File.readlines(file, chomp: true).each_with_index do |line, index|
    line.scan(pattern).each do |tag|
      failures << "#{relative}:#{index + 1}: hardcoded #{tag.inspect}"
    end
  end
end

if failures.any?
  warn "living release docs must not pin concrete gommage-cli release tags:"
  failures.each { |failure| warn "  - #{failure}" }
  warn
  warn "Use the installer default latest resolution for live docs, or placeholder"
  warn "tags such as gommage-cli-vX.Y.Z-alpha.N when explaining pinned installs."
  exit 1
end

puts "living release docs avoid concrete gommage-cli release tags"
RUBY
