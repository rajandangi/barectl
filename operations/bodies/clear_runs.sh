# shellcheck shell=sh
# Barectl change engine: clear reviewed finished barectl runs.
#
# The engine runs this file as the staged, digest-bound body of a transient unit that
# already holds the mutation lock and has admitted the review (boot, deadline, other
# runs, capacity and, for a Shared change, the affected-sites digest). It receives one
# parameter:
#
#   TARGETS  reviewed pipe-delimited unit evidence records separated by spaces
#
# Every exit path reports one structured line, "barectl-result {json}", to the journal
# (docs/adr/0035-one-change-engine-with-effect-derived-consent.md).
# $0 is the private, temporary copy staged by the worker over standard input.
result_reported=0
result() {
  result_reported=1
  printf 'barectl-result %s\n' "$1"
}
refused() { result "{\"class\":\"refused\",\"reason\":\"$1\"}"; exit 1; }
partial() { result "{\"class\":\"partial\",\"reason\":\"$1\"}"; exit 2; }
finish() {
  status=$?
  if [ "$result_reported" -eq 0 ] && [ "$status" -ne 0 ]; then
    result '{"class":"failed"}'
  fi
  rm -f -- "$0"
}
# shellcheck disable=SC2154
trap 'finish' EXIT
trap 'result "{\"class\":\"timed_out\"}"; exit 3' TERM
TARGETS=${1:?reviewed targets are required}
show='systemctl show --value -p'

read_target() {
  IFS='|' read -r name invocation reviewed_active reviewed_sub reviewed_result \
    reviewed_code reviewed_status reviewed_populated extra <<EOF
$1
EOF
  [ -n "$name" ] && [ -n "$invocation" ] && [ -n "$reviewed_active" ] &&
    [ -n "$reviewed_sub" ] && [ -n "$reviewed_result" ] && [ -n "$reviewed_code" ] &&
    [ -n "$reviewed_status" ] && [ -n "$reviewed_populated" ] && [ -z "$extra" ] ||
    refused evidence
}

for entry in $TARGETS; do
  read_target "$entry"
  if [ "$($show LoadState "$name")" = not-found ]; then continue; fi
  [ "$($show InvocationID "$name")" = "$invocation" ] || refused evidence
  [ "$($show ActiveState "$name")" = "$reviewed_active" ] || refused evidence
  [ "$($show SubState "$name")" = "$reviewed_sub" ] || refused evidence
  [ "$($show Result "$name")" = "$reviewed_result" ] || refused evidence
  [ "$($show ExecMainCode "$name")" = "$reviewed_code" ] || refused evidence
  [ "$($show ExecMainStatus "$name")" = "$reviewed_status" ] || refused evidence
  control_group=$($show ControlGroup "$name")
  events="/sys/fs/cgroup$control_group/cgroup.events"
  populated=0
  if [ -n "$control_group" ] && [ -e "$events" ]; then
    if grep -qx 'populated 1' "$events" 2>/dev/null; then
      populated=1
    elif ! grep -qx 'populated 0' "$events" 2>/dev/null; then
      refused evidence
    fi
  fi
  [ "$populated" = "$reviewed_populated" ] || refused evidence
done

for entry in $TARGETS; do
  read_target "$entry"
  if [ "$($show LoadState "$name")" = not-found ]; then continue; fi
  if [ "$reviewed_active" = active ]; then
    systemctl stop "$name" || partial cleanup
  else
    systemctl reset-failed "$name" || partial cleanup
  fi
done

result '{"class":"succeeded"}'
