#!/bin/sh
# docs/quality.md#native-layer
#
# One screen for a failed Native run: each shard's phase time, scenario total and the
# failing items, without pulling every multi-megabyte job log into a conversation.
set -eu

run=${1:?usage: native-summary.sh RUN_ID}
repository=${BARECTL_REPOSITORY:-rajandangi/barectl}

printf 'Run %s\n' "$run"
gh run view "$run" --repo "$repository" --json jobs \
    --jq '.jobs[] | select(.name | test("scenarios \\(|/")) | "\(.databaseId) \(.name) \(.conclusion // .status)"' |
while read -r id name state; do
    printf '\n== %s (%s)\n' "$name" "$state"
    gh run view "$run" --repo "$repository" --job "$id" --log 2>/dev/null |
        grep -E 'Complete native phase|Fast validators:|Native scenarios:|\[native\] (FAIL|ok .*— over)|Preparing the missing' |
        sed 's/^.*Z //' | tail -25 || true
done
