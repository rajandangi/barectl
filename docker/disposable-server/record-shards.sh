#!/bin/sh
# Usage: record-shards.sh HEAD RESULTS SHARDS TARGET
# Records `native (Ubuntu <release>)` on HEAD for each release whose SHARDS CI shards all
# passed; see docs/quality.md#running-them-in-ci.
set -eu
head=$1
results=$2
shards=$3
target=$4
status=0
for release in 26.04; do
    passed=0
    architecture=""
    for shard in $(seq "$shards"); do
        result="$results/$release.shard-$shard-of-$shards"
        if [ -f "$result" ]; then
            passed=$((passed + 1))
            architecture=$(cat "$result")
        fi
    done
    [ "$passed" -gt 0 ] || continue
    context="native (Ubuntu $release)"
    if [ "$passed" -ne "$shards" ]; then
        echo "$context: $passed of $shards shards passed; nothing recorded."
        status=1
        continue
    fi
    gh api "repos/{owner}/{repo}/statuses/$head" --silent \
        -f state=success \
        -f context="$context" \
        -f description="passed in CI on $architecture" \
        -f target_url="$target"
    echo "record-shards: recorded $context on $head."
done
exit "$status"
