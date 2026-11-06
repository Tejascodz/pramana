# Support

## Getting help

| You want to | Do this |
|---|---|
| Report a bug or a crash | Open an issue with the **Bug report** form |
| Report a wrong verdict (a pass that should fail, or a failure that should not) | Open an issue with the **Scoring error** form. These are the most valuable reports: every confirmed one becomes a regression test |
| Ask for a feature or a new check | Open an issue with the **Feature request** form |
| Report a security vulnerability | Do **not** open an issue: follow [SECURITY.md](SECURITY.md) |

Before sending an excerpt from an audit pack, remove secrets, keys and personal data.
The forms ask for the Pramana version (`pramana --version`), the command you ran and
the check id, which is usually enough to reproduce a problem.

## What is supported

Pramana is pre-1.0. Fixes go into the latest release; older versions are not patched.
Pin a release tag in production and read [CHANGELOG.md](CHANGELOG.md) before upgrading.

Within a 0.x series, these are kept stable and any change to them is called out in the
changelog:

- the command-line commands and their exit codes (0 success, 1 gate blocked,
  2 verification failed, 3 bad input, 4 endpoint unreachable);
- the audit spec keys documented in the README and `docs/methodology.md`;
- the `gate` object and the per-check `check_id`, `status`, `severity` and `metrics`
  fields of `results.json`;
- the evidence-pack layout that `pramana verify` checks.

Scoring rules do change between releases when a blind spot is found, so the same inputs
can produce a different verdict after an upgrade. The changelog says which checks changed
and why; re-run the previous version on the same pack's replay to compare.

## Response times

Community support through GitHub issues is best effort, with no guaranteed response
time. Commercial support, onboarding, supervised pilots and audit reviews are offered
separately under a written agreement; open an issue titled "Commercial support" or
contact the maintainer through their GitHub profile.
