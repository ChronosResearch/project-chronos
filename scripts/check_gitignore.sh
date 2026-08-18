#!/usr/bin/env bash
#
# Assert that standard Cargo layout paths are not excluded by .gitignore.
#
# Why this exists: the legacy Python-era ignore block used unanchored directory
# patterns (`tests/`, `bin/`, `security/`). An unanchored pattern matches a
# directory of that name at ANY depth, so `tests/` silently excluded
# `crates/*/tests/` — the standard location for Cargo integration tests.
#
# The failure mode is quiet and expensive: you add an integration test, commit,
# push, and CI goes green because the file was never committed. Nothing warns you.
# Files already tracked are exempt from .gitignore, so existing tests kept working
# and hid the problem.
#
# Usage:
#   ./scripts/check_gitignore.sh
#
# Exits non-zero and prints the offending pattern if any path is ignored.

set -uo pipefail

# Paths that must always be committable. They need not exist — `git check-ignore`
# is a pure pattern match.
REQUIRED_PATHS=(
  # Cargo integration tests, one per crate.
  "crates/chronos-core/tests/integration.rs"
  "crates/chronos-vdf/tests/integration.rs"
  "crates/chronos-snark/tests/integration.rs"
  "crates/chronos-agent/tests/e2e.rs"
  "crates/chronos-bench/tests/integration.rs"

  # Cargo's layout for additional binaries and examples.
  "crates/chronos-agent/src/bin/helper.rs"
  "crates/chronos-snark/examples/export_solidity.rs"

  # Plausible future module directories that unanchored patterns would eat.
  "crates/chronos-core/src/security/mod.rs"
  "crates/chronos-agent/src/test/helpers.rs"

  # First-class Solidity source.
  "contracts/Groth16Verifier.sol"
  "contracts/ChronosRegistry.sol"
)

failed=0

for path in "${REQUIRED_PATHS[@]}"; do
  if reason=$(git check-ignore -v "$path" 2>/dev/null); then
    printf 'FAIL  %s\n' "$path"
    printf '      excluded by: %s\n' "$reason"
    failed=1
  fi
done

if [[ "$failed" -ne 0 ]]; then
  cat <<'EOF'

One or more required paths are excluded by .gitignore.

Almost always this is an unanchored directory pattern. `tests/` matches a
directory named `tests` at any depth; `/tests/` matches only the one at the
repository root. Add the leading slash.
EOF
  exit 1
fi

printf 'ok    %d required paths are committable\n' "${#REQUIRED_PATHS[@]}"
