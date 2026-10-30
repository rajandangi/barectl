# Reading GitHub checks

Commands that behave the way you expect on the first call. `gh` needs the repository; run them
from the clone.

## Watch a pull request's checks

```bash
gh pr checks <n> --watch
```

A call made within a few seconds of a push prints `no checks reported on the '<branch>' branch`
because GitHub has not created the run yet. Call it again; the second call watches the new head.

## Read the assertion a job failed on

```bash
gh run view <run> --job <job-id> --log | grep -E "FAIL: |AssertionError|Error:"
```

`gh run view <run> --log-failed` stops at the first lines of a failed step and usually omits the
assertion. `gh run view <run>` lists each job with its status; take the failed job's id from the
`details_url` in `gh pr checks <n>`, or from the run page.

## Re-run a flaky shard after reading its failure

```bash
gh run rerun <run> --failed
gh pr checks <n> --watch
```

Read the failure first: a re-run hides nothing, and the aggregate `native` job follows the shard
results of the new attempt.

## Close an issue with multiline evidence

```bash
gh issue comment <n> --body-file <file>
gh issue close <n> --reason completed
```

`gh issue close` takes `--comment` as a single string and has no `--comment-file`; write the
evidence to a file and post it first.
