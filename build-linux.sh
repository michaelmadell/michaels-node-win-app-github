#!/usr/bin/env bash
# Kept for backward compatibility: native Linux build via the unified build.sh.
# Accepts the same arguments (--profile, --config, -D...). See docs/dev-config.md.
exec "$(dirname "${BASH_SOURCE[0]}")/build.sh" --target linux "$@"
