#!/bin/sh
# Read repository paths, one per line, and print those that can affect the native suites:
# every path that no pattern in .github/native-exempt-paths matches.
set -euf
here=$(cd "$(dirname "$0")" && pwd)
patterns=$(grep -v -e '^#' -e '^$' "$here/../../.github/native-exempt-paths")
while IFS= read -r path; do
    [ -n "$path" ] || continue
    exempt=0
    for pattern in $patterns; do
        # shellcheck disable=SC2254
        case $path in $pattern)
            exempt=1
            break
            ;;
        esac
    done
    [ "$exempt" -eq 1 ] || printf '%s\n' "$path"
done
