#!/bin/sh
# Run the native suites through run-tests.sh and record a commit status on HEAD for each
# release that passes, locally and in CI alike. See docs/quality.md#native-suites.
#
# Arguments are passed to run-tests.sh, and BARECTL_DISPOSABLE_RELEASE selects releases as
# it does there. Statuses are recorded through the GitHub CLI, so gh must be authenticated
# (GH_TOKEN in CI), and only for a clean working tree whose HEAD is on GitHub.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
cd "$here/../.."

refuse_unrecordable() {
    if [ -n "$(git status --porcelain)" ]; then
        echo "native-check: the working tree has uncommitted or untracked changes; commit" \
            "them, push, and run again. The results would not describe HEAD." >&2
        exit 1
    fi
    if ! gh api "repos/{owner}/{repo}/commits/$1" --silent 2>/dev/null; then
        echo "native-check: $1 is not on GitHub, or gh cannot reach it; push it and run" \
            "again. Statuses can only be recorded on a pushed commit." >&2
        exit 1
    fi
}

head=$(git rev-parse HEAD)
refuse_unrecordable "$head"
results=$(mktemp -d)
trap 'rm -rf "$results"' EXIT INT TERM

status=0
BARECTL_DISPOSABLE_RESULTS=$results "$here/run-tests.sh" "$@" || status=$?

# A checkout or edit during the run would make the results describe another tree.
if [ "$(git rev-parse HEAD)" != "$head" ]; then
    echo "native-check: HEAD moved during the run; nothing recorded." >&2
    exit 1
fi
refuse_unrecordable "$head"

if [ "${GITHUB_ACTIONS:-}" = true ]; then
    where="in CI"
    target="$GITHUB_SERVER_URL/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID"
else
    where=locally
    target=""
fi
for result in "$results"/*; do
    [ -f "$result" ] || continue
    release=$(basename "$result")
    context="native (Ubuntu $release)"
    gh api "repos/{owner}/{repo}/statuses/$head" --silent \
        -f state=success \
        -f context="$context" \
        -f description="passed $where on $(cat "$result")" \
        ${target:+-f target_url="$target"}
    echo "native-check: recorded $context on $head."
done
exit "$status"
