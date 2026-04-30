<!-- Thanks for the PR. A few quick prompts: -->

## What this changes

<!-- One or two sentences. The "why", not just the "what" — the diff already shows the what. -->

## Linked issue

<!-- Closes #123 / Refs #456. If this is a one-line typo fix or similar, "n/a" is fine. -->

## Pre-submit checklist

- [ ] `make lint && make test` pass locally.
- [ ] Conventional Commits subject (e.g. `feat(privesc): …`, `fix(report): …`). The PR title is the merge-commit subject — keep it ≤ 72 chars, no trailing period.
- [ ] If this PR adds or renames a rule ID, [`docs/findings.md`](../blob/main/docs/findings.md) is updated and (if appropriate) the e2e assertions in [`scripts/kind-e2e.sh`](../blob/main/scripts/kind-e2e.sh) and the fixture in [`testdata/e2e/vulnerable.yaml`](../blob/main/testdata/e2e/vulnerable.yaml) are updated.
- [ ] If this PR introduces a new resource/subject Kind or privesc Action slug, the matching `Glossary` / `Techniques` entry in [`internal/report/glossary.go`](../blob/main/internal/report/glossary.go) is added.
- [ ] If this PR is user-visible, `CHANGELOG.md` is updated (under `## [Unreleased]`).

<!-- Delete checklist items that don't apply. -->
