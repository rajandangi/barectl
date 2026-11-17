# Local CLI: Refresh server

The first CLI workflow submits the same Refresh server operation as the dashboard. Run it on the controller with its `.env`, application database and a separate `db_worker` process. SSH reads run in that worker. The CLI itself reads and writes only the local database.

```bash
uv run --env-file .env python manage.py barectl server refresh SERVER_ID --username operator --password-stdin --json
uv run --env-file .env python manage.py barectl server refresh SERVER_ID --username operator --password-stdin --wait --timeout 120 --json
uv run --env-file .env python manage.py barectl server refresh-status OPERATION_ID --username operator --password-stdin --wait --timeout 120 --json
```

`--password-stdin` reads one password line. Omit it only at a terminal, where Barectl prompts without echo. A username alone does not authenticate. The active account needs `servers.view_server` and `discovery.add_discoveryattempt` for every request and status read. The worker checks permissions and the captured connection again before publication.

Both commands print the operation ID before waiting in text mode. A status read without `--wait` prints the ID before the current state too. Repeated requests share an active discovery attempt. An active operation of another kind is a blocker. `--wait` polls the local database; `--timeout` requires `--wait` and accepts 1 to 600 seconds (default 120). A timeout or Ctrl-C stops waiting, never the operation. Resume with `refresh-status`; status reads do not submit work. Without a worker, the operation remains queued.

JSON output is one version-1 object. The `code` is `accepted`, `shared_active`, `in_progress`, `succeeded`, `failed`, `stale_connection`, `busy` or `client_timeout` for an operation. Authentication and input failures use `authentication_failed`, `credentials_required`, `permission_denied`, `not_found`, `invalid_input` or `interrupted`. The object includes the server ID/name, operation ID/kind/status/timestamps, progress stage/read count/timestamps/elapsed seconds and worker-wait flag. Elapsed seconds count from the start, or from queueing if work never started, to completion when recorded; active work counts to the status read, with negative durations shown as zero. A successful attempt can include a `snapshot` with only OS, architecture, CPU, memory and root filesystem values, each with its observation outcome. `snapshot_availability` is `not_applicable` before success or after failure, `retained` for a successful result still held locally, and `replaced` for an older successful result whose snapshot was replaced. `connection_current: false` marks a result captured on an earlier connection revision. These values are historical status only; run a fresh refresh before acting on current server state.

Exit status 0 means the request was accepted or the read succeeded, including queued work without `--wait`. Status 2 means invalid input or missing safe password input; 3 means authentication or authorization failure; 4 means missing server/operation; 5 means another operation blocks refresh; 6 means a failed refresh; 7 means the client wait timed out. Ctrl-C returns 130. Diagnostic text goes to stderr. The operation can continue after a nonzero wait exit. Django imports the project and parses command options before the JSON handler runs. Import or settings failures can therefore stop startup without a JSON envelope. This command skips Django's optional system and migration checks so their notices cannot appear on JSON stdout; run `manage.py check` and migrations separately during deployment.

The CLI currently covers this single read-only refresh workflow. Fleet overview, change commands, remote HTTP authentication and standalone binary distribution remain planned.
