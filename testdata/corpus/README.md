# Calibration / regression corpus

This directory is the deterministic, Docker-free counterpart to the live-kind
e2e (`scripts/kind-e2e.sh`). Each case pins a snapshot and a labeled set of
findings, and `internal/corpus` runs the analyzer engine in-process against it
and computes **precision and recall**, which the shell harness cannot measure.

The engine never touches the network (collector → snapshot → analyzer), so a
committed snapshot JSON always yields the same finding-ID set. That determinism
is what makes precision/recall meaningful here rather than flaky.

## Why this exists

The live e2e asserts "these rule IDs appear" against a whitelist and tolerates
unlimited *extra* findings, so a new false positive is invisible to it. This
corpus closes that gap: it treats each case's `expected` list as the **complete**
correct answer, so any finding the engine emits that is not sanctioned counts as
a false positive, and any sanctioned finding it drops counts as a recall miss.

```
TP = actual ∩ expected     FP = actual \ expected     FN = expected \ actual
precision = TP / (TP + FP)  recall = TP / (TP + FN)   F1 = 2PR / (P + R)
```

Run it:

```bash
make corpus          # scorecard for every case
make test            # runs the same gate as part of `go test ./...`
```

## Case layout

```
testdata/corpus/<case-name>/labels.json
```

`labels.json` schema:

| field | meaning |
|-------|---------|
| `name` | case name (defaults to the directory name) |
| `description` | what the snapshot models and what the deny list guards |
| `snapshot` | repo-root-relative path to the snapshot JSON (cases reference the shared `testdata/snapshots/` fixtures; there is no per-case copy to drift) |
| `options.max_privesc_depth` | privesc BFS depth; `0` → engine default (5) |
| `options.admission_mode` | `off` \| `attenuate` \| `suppress`; empty → engine default (`suppress`) |
| `expected` | the **complete** set of finding IDs that should fire (positive ground truth) |
| `deny` | finding-ID prefixes that must never fire (see matching below) |
| `min_precision` / `min_recall` | per-case gates; omit → `1.0` |

Finding IDs are the deterministic `RULE:subject-or-resource:...` keys the
analyzers emit (`models.Finding.ID`), not bare rule IDs.

### Deny matching

A `deny` entry matches a finding when the finding ID **equals** it or **begins
with it followed by `:`**. So a bare rule ID bans every instance of that rule,
while a `rule:subject` prefix bans one specific instance:

```
"KUBE-RBAC-OVERBROAD-001"                              → bans the rule everywhere
"KUBE-PRIVESC-PATH-CLUSTER-ADMIN:ServiceAccount/legacy/loadtester"
                                                       → bans that one subject's path
```

The deny list is the part that is genuine calibration rather than a golden
snapshot: it encodes assertions authored independently of current output. In
`leastprivilege-demo` the read-only `loadtester`, view-only `old-ci-bot`, and
configmap-only `etl-runner` SAs must **never** be flagged as privilege
escalation — if a graph change ever laundered one of them to `cluster_admin`,
the deny gate fails even if someone regenerated `expected` straight from the new
(wrong) output.

## Adding or updating a case

1. Add or reuse a snapshot under `testdata/snapshots/`.
2. Generate current output to seed `expected`:

   ```bash
   ./bin/kubesplaining scan \
     --input-file testdata/snapshots/<snap>.json \
     --all-findings --exclusions-preset none \
     --output-format json --output-dir /tmp/probe
   jq -r '.[].id' /tmp/probe/findings.json | sort
   ```

3. **Read the resources and confirm each expected ID is actually correct** —
   do not paste output blindly. Where the tool's behavior is debatable, that is
   the discussion the corpus is meant to host, not paper over. Add `deny`
   entries for benign resources that must stay quiet.
4. `make corpus` should print `P=1.000 R=1.000` for a clean case.

## Maintenance note

`expected` sets are seeded from verified current output, so they double as a
regression golden: a deliberate behavior change requires a reviewed edit here.
When you add a rule (e.g. the reserved `KUBE-CONFUSED-DEPUTY-*` /
`KUBE-NODE-*-CVE-*` IDs in `docs/privesc-research.md` §N), extend the affected
cases' `expected`/`deny` in the same PR so the gate keeps measuring the new
surface instead of silently ignoring it.

## Known calibration questions (candidates for review, not settled truth)

- `leastprivilege-demo`: `prometheus` (cluster-wide `create`/`delete` on
  pods+nodes) is currently labeled `KUBE-PRIVESC-PATH-CLUSTER-ADMIN`
  (`cluster_admin_equivalent`). That is an aggressive modeling choice; it is in
  `expected` because it reflects current behavior, flagged here so the question
  is visible rather than buried.
