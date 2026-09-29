#!/bin/sh
# Usage: native-gate.sh BASE HEAD
# docs/quality.md#native-affecting-paths
set -eu
here=$(cd "$(dirname "$0")" && pwd)
base=$1
head=$2

affecting=$(git diff --name-only --no-renames "$base...$head" | "$here/native-paths.sh")
if [ -z "$affecting" ]; then
    state=success
    description="no native-affecting changes"
else
    echo "Native-affecting changes:"
    echo "$affecting"
    state=pending
    description="run native-check.sh locally or add the native-ci label"
fi

for release in 24.04 26.04; do
    context="native (Ubuntu $release)"
    recorded=$(gh api "repos/{owner}/{repo}/commits/$head/status" \
        --jq ".statuses[] | select(.context == \"$context\") | .state")
    if [ "$recorded" = success ]; then
        echo "$context: success already recorded."
        continue
    fi
    gh api "repos/{owner}/{repo}/statuses/$head" --silent \
        -f state="$state" -f context="$context" -f description="$description"
    echo "$context: $state, $description."
done
