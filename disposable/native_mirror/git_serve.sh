#!/bin/sh
# The lane's fixture Git host (docs/quality.md#native-layer). It serves the fixture
# repository over SSH (an OpenSSH server whose only account is limited to git-shell) and
# over HTTPS (git_http.py), so a scenario server clones the same repository both ways
# without the internet.
set -eu

root=${GIT_ROOT:-/home/git}
[ -d "$root" ] || { echo "git fixture: no repository root $root" >&2; exit 2; }

# The lane mounts the fixture public keys; the only SSH account is git-shell-limited.
if [ -f /keys/authorized_keys ]; then
    install -d -m 700 -o git -g git /home/git/.ssh
    install -m 600 -o git -g git /keys/authorized_keys /home/git/.ssh/authorized_keys
fi
mkdir -p /run/sshd
ssh-keygen -A >/dev/null
/usr/sbin/sshd -e

# git_http.py serves smart HTTP on the same port the managed server expects (443).
exec python3 /native/native_mirror/git_http.py \
    --root "$root" --certificate /tls/git.crt --key /tls/git.key
