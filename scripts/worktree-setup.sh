#!/bin/sh
# CONTRIBUTING.md#development-checks
#
# Give a linked worktree the controller-local files the main checkout already has:
# the untracked .env and the locked dependencies. Run it from inside the worktree.
set -eu

worktree=$(git rev-parse --show-toplevel)
main=$(git worktree list --porcelain | sed -n 's/^worktree //p' | head -n 1)

if [ "$worktree" = "$main" ]; then
    printf 'worktree-setup: %s is the main checkout; nothing to copy.\n' "$worktree"
    exit 0
fi

if [ -f "$worktree/.env" ]; then
    printf 'worktree-setup: .env is already present.\n'
elif [ -f "$main/.env" ]; then
    cp "$main/.env" "$worktree/.env"
    printf 'worktree-setup: copied .env from %s.\n' "$main"
else
    printf 'worktree-setup: %s/.env is missing; configure it as the README describes.\n' "$main" >&2
    exit 1
fi

cd "$worktree"
uv sync --locked
if [ -d node_modules ]; then
    printf 'worktree-setup: node_modules is already present.\n'
else
    npm ci
fi
printf 'worktree-setup: ready.\n'
