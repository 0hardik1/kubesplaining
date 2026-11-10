package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/0hardik1/kubesplaining/internal/analyzer/privesc"
	"github.com/0hardik1/kubesplaining/internal/exclusions"
	"github.com/0hardik1/kubesplaining/internal/models"
	"github.com/0hardik1/kubesplaining/internal/usage"
	"github.com/spf13/cobra"
)

const pathsLong = `List the attack paths in a cluster.

An attack path is a chain of permissions that takes one identity (the source)
to a dangerous position (the target). An example is a ServiceAccount that can
open a shell in a pod, take the token of a second ServiceAccount there, and use
that token to become cluster-admin.

With no filter, paths lists the same attack paths that scan reports.

  --to    keeps the paths that end at one target. It answers "who can reach
          cluster-admin?".
  --from  starts the search at one identity. It answers "what can this
          ServiceAccount reach?". The exclusions do not apply, and you can name
          an identity that scan does not use as a source: a built-in system
          identity, a control-plane ServiceAccount, or a group such as
          system:authenticated.

Identities for --from:
  ServiceAccount/<namespace>/<name>   (short form: sa/<namespace>/<name>)
  User/<name>
  Group/<name>
  system:serviceaccount:<namespace>:<name>

Targets for --to:
  cluster-admin                  all permissions in the cluster
  system-masters                 a credential for the system:masters group
  kube-system-secrets            read the Secrets of kube-system
  node-escape                    root on a node
  namespace-admin[:<namespace>]  all permissions in one namespace
  token-mint                     create a token for a ServiceAccount of your choice
  aws-iam-role[:<arn>]           assume an AWS IAM role
  traffic-intercept              redirect the traffic of a Service
  node-identity                  the client identity of a kubelet

The command reads a snapshot file (--input-file) or the live cluster. It does
not change the cluster. For more than one question, capture the cluster one
time with "kubesplaining download" and use --input-file: each answer then
takes less than a second and needs no cluster access.`

const pathsExample = `  # Who can reach cluster-admin?
  kubesplaining paths --to cluster-admin

  # What can one ServiceAccount reach?
  kubesplaining paths --from ServiceAccount/dev/ci

  # One chain, hop by hop, with the binding behind each hop and the fix
  kubesplaining paths --from ServiceAccount/dev/ci --to cluster-admin --verbose

  # Capture the cluster one time, then ask offline and get JSON
  kubesplaining download --output-file snapshot.json
  kubesplaining paths --input-file snapshot.json --to node-escape --output-format json --limit 10

  # Does this manifest open a path? Nothing is applied to the cluster.
  kubesplaining paths --input-file snapshot.json --overlay new-binding.yaml --diff

  # Does this fix close the path?
  kubesplaining paths --input-file snapshot.json --overlay-delete ClusterRoleBinding/ci-admin --diff`

// NewPathsCmd returns the "paths" subcommand. It answers one question about the
// privilege-escalation graph in the terminal, where `scan` writes a full report.
func NewPathsCmd(build BuildInfo) *cobra.Command {
	var (
		src              = snapshotSource{}
		from             string
		to               string
		id               string
		limit            int
		outputFormat     string
		verbose          bool
		maxPrivescDepth  int
		exclusionsFile   string
		exclusionsPreset string
		diff             bool
	)

	cmd := &cobra.Command{
		Use:     "paths",
		Short:   "List attack paths: who can reach a target, and what an identity can reach",
		Long:    pathsLong,
		Example: pathsExample,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			format := strings.ToLower(strings.TrimSpace(outputFormat))
			if format != "table" && format != "json" {
				return fmt.Errorf("invalid --output-format %q (must be table or json)", outputFormat)
			}
			if limit < 0 {
				return fmt.Errorf("invalid --limit %d (must be 0 or more; 0 lists every path)", limit)
			}

			var target *targetSelector
			if to != "" {
				parsed, err := parseTargetSelector(to)
				if err != nil {
					return err
				}
				target = &parsed
			}

			var source *models.SubjectRef
			if from != "" {
				parsed, err := parseSourceFlag(from)
				if err != nil {
					return err
				}
				source = &parsed
			}

			depth := maxPrivescDepth
			if depth <= 0 {
				depth = privesc.DefaultMaxDepth
			}
			if diff && !src.hasOverlay() {
				return fmt.Errorf("--diff compares the cluster before and after a change, so it needs --overlay or --overlay-delete")
			}
			if diff && limit > 0 {
				return fmt.Errorf("--limit cannot be used with --diff: a diff that is cut can hide an added path")
			}

			query := pathQuery{source: source, target: target, id: id, depth: depth}
			// The exclusions keep the default listing equal to what scan reports. A
			// path that the user asked for by source or by ID is never hidden. A diff
			// hides nothing unless the user asks: paths that do not change cancel out,
			// and a hidden path that the change adds would make the check pass.
			exclusionsChosen := cmd.Flags().Changed("exclusions-preset") || cmd.Flags().Changed("exclusions-file")
			if source == nil && id == "" && (!diff || exclusionsChosen) {
				cfg, err := loadExclusions(exclusionsPreset, exclusionsFile)
				if err != nil {
					return err
				}
				query.exclusions = &cfg
			}

			base, err := src.loadBase(cmd, build)
			if err != nil {
				return err
			}
			snapshot := base
			var notes []string
			if src.hasOverlay() {
				changed, result, err := src.applyOverlay(cmd, base)
				if err != nil {
					return err
				}
				snapshot = changed
				notes = append(notes, overlayNotes(result)...)
			}

			if diff {
				delta, diffNotes, err := query.diff(base, snapshot)
				if err != nil {
					return err
				}
				notes = append(notes, diffNotes...)
				if format == "json" {
					err = writePathsDiffJSON(cmd.OutOrStdout(), delta, notes, verbose)
				} else {
					err = writePathsDiffText(cmd.OutOrStdout(), cmd.ErrOrStderr(), delta, notes, verbose)
				}
				if err != nil {
					return err
				}
				if n := len(delta.added); n > 0 {
					return asGateError(fmt.Errorf("the change adds %d attack %s", n, pluralize(n, "path", "paths")))
				}
				return nil
			}

			answer, err := query.run(snapshot)
			if err != nil {
				return err
			}
			notes = append(notes, answer.notes...)
			if answer.hidden > 0 {
				hint := "add --exclusions-preset none"
				if exclusionsFile != "" {
					hint += " and remove --exclusions-file"
				}
				notes = append(notes, fmt.Sprintf("The exclusions hide %d attack %s that %s this question. To list all, %s.",
					answer.hidden, pluralize(answer.hidden, "path", "paths"), pluralize(answer.hidden, "matches", "match"), hint))
			}
			findings := answer.findings

			if id != "" && len(findings) == 0 {
				return fmt.Errorf("no attack path has the ID %q (list the IDs with --output-format json)", id)
			}

			total := len(findings)
			if limit > 0 && total > limit {
				findings = findings[:limit]
			}

			if format == "json" {
				return writePathsJSON(cmd.OutOrStdout(), findings, total, notes, verbose)
			}
			if verbose {
				err = writePathsVerbose(cmd.OutOrStdout(), findings)
			} else {
				err = writePathsTable(cmd.OutOrStdout(), findings)
			}
			if err != nil {
				return err
			}
			return writePathsFooter(cmd.ErrOrStderr(), len(findings), total, depth, source, target, notes, verbose)
		},
	}

	bindConnectionFlags(cmd, &src.conn)
	cmd.Flags().StringVar(&src.inputFile, "input-file", "", "Path to a snapshot JSON file from the download command. Without it, the command reads the live cluster.")
	cmd.Flags().StringVar(&from, "from", "", "Start at one identity: ServiceAccount/<namespace>/<name>, User/<name>, or Group/<name>")
	cmd.Flags().StringVar(&to, "to", "", "Keep the paths that end at one target, for example cluster-admin or namespace-admin:<namespace> (see the list above)")
	cmd.Flags().StringVar(&id, "id", "", "Keep the one path that has this finding ID")
	cmd.Flags().IntVar(&limit, "limit", 0, "List only the first N paths, highest severity and score first; 0 lists every path")
	cmd.Flags().StringVar(&outputFormat, "output-format", "table", "Output format: table or json")
	cmd.Flags().BoolVar(&verbose, "verbose", false, "Show each hop with the binding and role behind it, and the fix")
	cmd.Flags().IntVar(&maxPrivescDepth, "max-privesc-depth", privesc.DefaultMaxDepth, "Maximum number of hops in a path")
	cmd.Flags().StringVar(&exclusionsFile, "exclusions-file", "", "Path to a user-supplied exclusions YAML file (merged on top of --exclusions-preset). Not applied with --from or --id.")
	cmd.Flags().StringVar(&exclusionsPreset, "exclusions-preset", "standard", "Built-in exclusions preset: standard|minimal|strict|none. Not applied with --from or --id.")
	cmd.Flags().IntVar(&src.parallelism, "parallelism", 10, "Maximum parallel API requests when the command reads the live cluster")
	cmd.Flags().StringVar(&src.eksAccessEntriesFile, "eks-access-entries", "", "Path to an EKS access-entries export produced by scripts/eks-access-entries.sh")
	cmd.Flags().StringVar(&src.cloudProvider, "cloud-provider", "auto", "Cloud provider hint: auto|eks|gke|aks|none")
	bindOverlayFlags(cmd, &src)
	cmd.Flags().BoolVar(&diff, "diff", false, "With --overlay or --overlay-delete: list the paths that the change adds, removes, and changes. Exits with code 2 when the change adds a path.")

	return cmd
}

// targetSelector is a parsed --to value: a target, and for the two targets that
// have one sink per namespace or per role, optionally which one.
type targetSelector struct {
	target models.EscalationTarget
	detail string
}

// pathTargets lists every target, in the order the help text prints them.
var pathTargets = []models.EscalationTarget{
	models.TargetClusterAdmin,
	models.TargetSystemMasters,
	models.TargetKubeSystemSecrets,
	models.TargetNodeEscape,
	models.TargetNamespaceAdmin,
	models.TargetTokenMint,
	models.TargetAWSIAMRole,
	models.TargetTrafficIntercept,
	models.TargetNodeIdentity,
}

// targetAliases maps the short names a user is likely to type to a target. Keys
// are in the normalized form: lower case, with "_" for "-".
var targetAliases = map[string]models.EscalationTarget{
	"cluster_admin": models.TargetClusterAdmin,
	"node_root":     models.TargetNodeEscape,
}

// targetName returns the name that --to accepts and that the table prints for a
// target: the value in findings.json with "-" for "_", and "cluster-admin" for
// cluster_admin_equivalent.
func targetName(target models.EscalationTarget) string {
	if target == models.TargetClusterAdmin {
		return "cluster-admin"
	}
	return strings.ReplaceAll(string(target), "_", "-")
}

// targetLabel is targetName plus the namespace or the role, in the form that
// --to accepts.
func targetLabel(target models.EscalationTarget, detail string) string {
	if detail == "" {
		return targetName(target)
	}
	return targetName(target) + ":" + detail
}

// parseTargetSelector reads a --to value. The name is not case-sensitive, and
// "-" and "_" are interchangeable, so the value from findings.json
// ("kube_system_secrets") and the value the table prints ("kube-system-secrets")
// both work.
func parseTargetSelector(value string) (targetSelector, error) {
	raw := strings.TrimSpace(value)
	// system:masters is how Kubernetes writes the group, and its colon is not a
	// separator.
	if strings.EqualFold(raw, "system:masters") {
		return targetSelector{target: models.TargetSystemMasters}, nil
	}

	name, detail, _ := strings.Cut(raw, ":")
	key := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(name)), "-", "_")
	detail = strings.TrimSpace(detail)

	target, ok := targetAliases[key]
	if !ok {
		for _, candidate := range pathTargets {
			if string(candidate) == key {
				target, ok = candidate, true
				break
			}
		}
	}
	if !ok {
		names := make([]string, 0, len(pathTargets))
		for _, candidate := range pathTargets {
			names = append(names, targetName(candidate))
		}
		return targetSelector{}, fmt.Errorf("invalid --to %q (must be one of: %s)", value, strings.Join(names, ", "))
	}
	if detail != "" && target != models.TargetNamespaceAdmin && target != models.TargetAWSIAMRole {
		return targetSelector{}, fmt.Errorf("invalid --to %q: only namespace-admin:<namespace> and aws-iam-role:<arn> take a value after the colon", value)
	}
	return targetSelector{target: target, detail: detail}, nil
}

// parseSourceFlag reads a --from value: the username form that the API server
// gives a ServiceAccount, or the Kind/[namespace/]name form that the reports
// print.
func parseSourceFlag(value string) (models.SubjectRef, error) {
	if ref, ok := usage.SubjectFromUsername(strings.TrimSpace(value)); ok {
		return ref, nil
	}
	ref, err := models.ParseSubjectRef(value)
	if err != nil {
		return models.SubjectRef{}, fmt.Errorf("invalid --from: %w", err)
	}
	return ref, nil
}

// resolveSource confirms that the graph can answer a question about ref, and
// returns the notes the answer needs. A subject that is not in the cluster is an
// error and not an empty answer: "0 paths" for a name with a typing mistake
// reads as "this identity is safe".
func resolveSource(graph *models.EscalationGraph, ref models.SubjectRef) ([]string, error) {
	node, ok := privesc.SubjectNode(graph, ref)
	if !ok {
		return nil, unknownSubjectError(graph, ref)
	}

	switch {
	case node.IsSystem:
		return []string{
			ref.Key() + " is a built-in system identity. The list is a lower bound: some checks (Service backends, node identity, traffic interception) skip built-in identities. scan does not report paths that start here.",
		}, nil
	case node.IsControlPlane:
		return []string{
			ref.Key() + " is a control-plane ServiceAccount. scan does not report paths that start here, so these paths are not in findings.json.",
		}, nil
	case node.IsImplicitGroup:
		return []string{
			ref.Key() + " is a group that the API server adds to requests by itself. scan reports these paths one time for each member, not for the group.",
		}, nil
	}
	return nil, nil
}

// unknownSubjectError explains why ref is not known, and lists the subjects that
// have the same name with a different kind or namespace.
func unknownSubjectError(graph *models.EscalationGraph, ref models.SubjectRef) error {
	var msg strings.Builder
	fmt.Fprintf(&msg, "subject %s was not found", ref.Key())
	if ref.Kind == "ServiceAccount" {
		msg.WriteString(": the cluster has no ServiceAccount with this namespace and name, and no binding names it")
	} else {
		fmt.Fprintf(&msg, ": no binding names it (a %s is known only through the bindings that name it)", ref.Kind)
	}

	var similar []string
	for _, node := range graph.Nodes {
		if node.IsSink || node.IsExternal {
			continue
		}
		if strings.EqualFold(node.Subject.Name, ref.Name) {
			similar = append(similar, node.Subject.Key())
		}
	}
	if len(similar) > 0 {
		sort.Strings(similar)
		const maxSuggestions = 5
		if len(similar) > maxSuggestions {
			similar = similar[:maxSuggestions]
		}
		fmt.Fprintf(&msg, ". Subjects with this name: %s", strings.Join(similar, ", "))
	}

	authenticated := models.SubjectRef{Kind: "Group", Name: "system:authenticated"}
	if _, ok := privesc.SubjectNode(graph, authenticated); ok && ref.Kind != "ServiceAccount" {
		fmt.Fprintf(&msg, ". To see what each authenticated identity can reach, use --from %s", authenticated.Key())
	}
	return subjectNotFoundError{message: msg.String()}
}

// subjectNotFoundError says that --from names a subject that the cluster does
// not have. `paths --diff` reads it as "no paths on this side" when the subject
// is in the cluster on the other side of the change.
type subjectNotFoundError struct{ message string }

func (e subjectNotFoundError) Error() string { return e.message }

// pathQuery is one question: the filters and the search depth.
type pathQuery struct {
	source *models.SubjectRef
	target *targetSelector
	id     string
	depth  int
	// exclusions is nil when the exclusions do not apply to this question.
	exclusions *exclusions.Config
}

// pathAnswer is the paths that match a question on one snapshot, ordered for
// output, plus the notes the answer needs and the count of matching paths that
// the exclusions hid.
type pathAnswer struct {
	findings []models.Finding
	notes    []string
	hidden   int
}

// run answers the question on one snapshot.
func (q pathQuery) run(snapshot models.Snapshot) (pathAnswer, error) {
	graph := privesc.BuildGraph(snapshot)

	var (
		answer pathAnswer
		paths  []models.EscalationPath
	)
	if q.source != nil {
		notes, err := resolveSource(graph, *q.source)
		if err != nil {
			return pathAnswer{}, err
		}
		answer.notes = notes
		paths, _ = privesc.PathsFrom(graph, *q.source, q.depth)
	} else {
		paths = privesc.FindPaths(graph, q.depth)
	}

	findings := filterPathFindings(privesc.FindingsFromPaths(paths, snapshot), q.target, q.id)
	if q.exclusions != nil {
		findings, answer.hidden = exclusions.Apply(*q.exclusions, findings)
	}
	sortPathFindings(findings)
	answer.findings = findings
	return answer, nil
}

// pathChange is one path that exists before and after a change, with a
// different chain or a different alternate route.
type pathChange struct {
	before models.Finding
	after  models.Finding
}

// pathsDelta is what a change does to the answer of one question.
type pathsDelta struct {
	added     []models.Finding
	removed   []models.Finding
	changed   []pathChange
	unchanged int
}

// diff answers the question before and after a change and compares the two
// answers by path ID. An ID names the source and the target, so a path whose
// route moves keeps its ID and is reported as changed, not as removed. That is
// the case that matters for a fix: the binding is gone, and a second route to the
// same target is still there.
func (q pathQuery) diff(before, after models.Snapshot) (pathsDelta, []string, error) {
	beforeAnswer, beforeErr := q.run(before)
	afterAnswer, afterErr := q.run(after)
	// A --from subject can be on one side only: the change adds a ServiceAccount,
	// or deletes the last binding that names a user. That side has its paths, and
	// the other side has none. A subject on neither side is an error.
	var notFound subjectNotFoundError
	switch {
	case beforeErr != nil && afterErr != nil:
		return pathsDelta{}, nil, afterErr
	case beforeErr != nil && !errors.As(beforeErr, &notFound):
		return pathsDelta{}, nil, beforeErr
	case afterErr != nil && !errors.As(afterErr, &notFound):
		return pathsDelta{}, nil, afterErr
	}

	beforeByID := map[string]models.Finding{}
	for _, finding := range beforeAnswer.findings {
		beforeByID[finding.ID] = finding
	}
	var delta pathsDelta
	seen := map[string]bool{}
	for _, finding := range afterAnswer.findings {
		seen[finding.ID] = true
		old, existed := beforeByID[finding.ID]
		switch {
		case !existed:
			delta.added = append(delta.added, finding)
		case !reflect.DeepEqual(old.EscalationPath, finding.EscalationPath) ||
			!reflect.DeepEqual(old.AlternateEscalationPath, finding.AlternateEscalationPath):
			delta.changed = append(delta.changed, pathChange{before: old, after: finding})
		default:
			delta.unchanged++
		}
	}
	for _, finding := range beforeAnswer.findings {
		if !seen[finding.ID] {
			delta.removed = append(delta.removed, finding)
		}
	}

	notes := afterAnswer.notes
	if beforeErr != nil {
		notes = append(notes, q.source.Key()+" is not in the cluster before the change.")
	}
	if afterErr != nil {
		notes = append(notes, q.source.Key()+" is not in the cluster after the change.")
	}
	return delta, notes, nil
}

// pathsDiffOutput is the JSON form of a diff.
type pathsDiffOutput struct {
	Added     []pathRecord       `json:"added"`
	Removed   []pathRecord       `json:"removed"`
	Changed   []pathChangeRecord `json:"changed"`
	Unchanged int                `json:"unchanged"`
	Notes     []string           `json:"notes,omitempty"`
}

type pathChangeRecord struct {
	Before pathRecord `json:"before"`
	After  pathRecord `json:"after"`
}

func writePathsDiffJSON(w io.Writer, delta pathsDelta, notes []string, verbose bool) error {
	out := pathsDiffOutput{
		Added:     make([]pathRecord, 0, len(delta.added)),
		Removed:   make([]pathRecord, 0, len(delta.removed)),
		Changed:   make([]pathChangeRecord, 0, len(delta.changed)),
		Unchanged: delta.unchanged,
		Notes:     notes,
	}
	for _, finding := range delta.added {
		out.Added = append(out.Added, newPathRecord(finding, verbose))
	}
	for _, finding := range delta.removed {
		out.Removed = append(out.Removed, newPathRecord(finding, verbose))
	}
	for _, change := range delta.changed {
		out.Changed = append(out.Changed, pathChangeRecord{Before: newPathRecord(change.before, verbose), After: newPathRecord(change.after, verbose)})
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(out)
}

// writePathsDiffText prints one section for each kind of difference on stdout,
// then the counts and the notes on stderr.
func writePathsDiffText(stdout, stderr io.Writer, delta pathsDelta, notes []string, verbose bool) error {
	list := writePathsTable
	if verbose {
		list = writePathsVerbose
	}
	var b strings.Builder
	section := func(title string, findings []models.Finding) error {
		if len(findings) == 0 {
			return nil
		}
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "%s (%d)\n", title, len(findings))
		return list(&b, findings)
	}
	if err := section("ADDED", delta.added); err != nil {
		return err
	}
	if err := section("REMOVED", delta.removed); err != nil {
		return err
	}
	if len(delta.changed) > 0 {
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		// A changed path is the one result that a reader can take for a fix that
		// worked, so each route names the binding behind each hop. Two routes with
		// the same actions differ only in that.
		fmt.Fprintf(&b, "CHANGED (%d): still open, by a different route\n", len(delta.changed))
		for _, change := range delta.changed {
			target, detail, _ := privesc.FindingTarget(change.after)
			fmt.Fprintf(&b, "%s -> %s\n", subjectKey(change.after.Subject), targetLabel(target, detail))
			writeRoutes(&b, "before", change.before)
			writeRoutes(&b, "after", change.after)
		}
	}
	if _, err := io.WriteString(stdout, b.String()); err != nil {
		return err
	}

	var footer strings.Builder
	if b.Len() > 0 {
		footer.WriteString("\n")
	}
	fmt.Fprintf(&footer, "The change adds %d attack %s, removes %d, and changes %d. %d %s the same.\n",
		len(delta.added), pluralize(len(delta.added), "path", "paths"), len(delta.removed), len(delta.changed),
		delta.unchanged, pluralize(delta.unchanged, "stays", "stay"))
	for _, note := range notes {
		fmt.Fprintf(&footer, "note: %s\n", note)
	}
	_, err := io.WriteString(stderr, footer.String())
	return err
}

// writeRoutes prints the chain of a path under label, and its alternate route
// when it has one.
func writeRoutes(b *strings.Builder, label string, finding models.Finding) {
	fmt.Fprintf(b, "  %-7s %s\n", label+":", routeWithGrants(finding.EscalationPath))
	if len(finding.AlternateEscalationPath) > 0 {
		fmt.Fprintf(b, "  %-7s also: %s\n", "", routeWithGrants(finding.AlternateEscalationPath))
	}
}

// routeWithGrants prints a chain as its actions, each with the binding that
// grants it when RBAC grants it.
func routeWithGrants(hops []models.EscalationHop) string {
	parts := make([]string, 0, len(hops))
	for _, hop := range hops {
		part := hop.Action
		if granted := grantedBy(hop); granted != "" {
			part += " [" + granted + "]"
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, " > ")
}

// filterPathFindings keeps the findings that match --to and --id. A nil target
// and an empty id match everything.
func filterPathFindings(findings []models.Finding, target *targetSelector, id string) []models.Finding {
	if target == nil && id == "" {
		return findings
	}
	out := make([]models.Finding, 0, len(findings))
	for _, finding := range findings {
		if id != "" && finding.ID != id {
			continue
		}
		if target != nil {
			got, detail, ok := privesc.FindingTarget(finding)
			if !ok || got != target.target {
				continue
			}
			if target.detail != "" && detail != target.detail {
				continue
			}
		}
		out = append(out, finding)
	}
	return out
}

// sortPathFindings puts the paths to act on first: highest severity, then
// highest score, then fewest hops. The ID makes the order total.
func sortPathFindings(findings []models.Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := &findings[i], &findings[j]
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() > b.Severity.Rank()
		}
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		if len(a.EscalationPath) != len(b.EscalationPath) {
			return len(a.EscalationPath) < len(b.EscalationPath)
		}
		return a.ID < b.ID
	})
}

// pathsOutput is the JSON form of an answer. Total counts the paths that match
// the question, and Returned counts the paths in this output, so a reader can
// tell when --limit cut the list.
type pathsOutput struct {
	Total    int          `json:"total"`
	Returned int          `json:"returned"`
	Notes    []string     `json:"notes,omitempty"`
	Paths    []pathRecord `json:"paths"`
}

// pathRecord is one path without the explanatory prose of a full finding, which
// is most of a finding's size. Field names and values match findings.json where
// both have the field, except that the score is rounded to two decimals.
// Subjects are in the Kind/[namespace/]name form that --from accepts.
type pathRecord struct {
	ID              string  `json:"id"`
	Source          string  `json:"source"`
	Target          string  `json:"target"`
	TargetNamespace string  `json:"target_namespace,omitempty"`
	TargetRole      string  `json:"target_role,omitempty"`
	Severity        string  `json:"severity"`
	Score           float64 `json:"score"`
	// SurvivesFirstFix is true when a second route to the same target stays open
	// after the binding behind hop 1 is removed.
	SurvivesFirstFix bool        `json:"survives_first_fix"`
	Hops             []hopRecord `json:"hops"`

	// The fields below are set only with --verbose.
	Remediation   string      `json:"remediation,omitempty"`
	FixCommand    string      `json:"fix_command,omitempty"`
	RBACDiff      string      `json:"rbac_diff,omitempty"`
	AlternateHops []hopRecord `json:"alternate_hops,omitempty"`
}

// hopRecord is one step of a path.
type hopRecord struct {
	Step             int    `json:"step"`
	Action           string `json:"action"`
	From             string `json:"from"`
	To               string `json:"to,omitempty"`
	Permission       string `json:"permission,omitempty"`
	SourceBinding    string `json:"source_binding,omitempty"`
	BindingNamespace string `json:"binding_namespace,omitempty"`
	SourceRole       string `json:"source_role,omitempty"`
	Difficulty       string `json:"difficulty,omitempty"`
	// Gains is set only with --verbose.
	Gains string `json:"gains,omitempty"`
}

func newPathRecord(finding models.Finding, verbose bool) pathRecord {
	target, detail, _ := privesc.FindingTarget(finding)
	record := pathRecord{
		ID:               finding.ID,
		Source:           subjectKey(finding.Subject),
		Target:           string(target),
		Severity:         string(finding.Severity),
		Score:            roundScore(finding.Score),
		SurvivesFirstFix: len(finding.AlternateEscalationPath) > 0,
		Hops:             newHopRecords(finding.EscalationPath, verbose),
	}
	switch target {
	case models.TargetNamespaceAdmin:
		record.TargetNamespace = detail
	case models.TargetAWSIAMRole:
		record.TargetRole = detail
	}
	if verbose {
		record.Remediation = finding.Remediation
		record.AlternateHops = newHopRecords(finding.AlternateEscalationPath, verbose)
		if hint := finding.RemediationHint; hint != nil {
			record.RBACDiff = hint.RBACDiff
			if hint.Patch != nil {
				record.FixCommand = hint.Patch.Command
			}
		}
	}
	return record
}

func newHopRecords(hops []models.EscalationHop, verbose bool) []hopRecord {
	if len(hops) == 0 {
		return nil
	}
	records := make([]hopRecord, 0, len(hops))
	for _, hop := range hops {
		record := hopRecord{
			Step:             hop.Step,
			Action:           hop.Action,
			From:             hop.FromSubject.Key(),
			Permission:       hop.Permission,
			SourceBinding:    hop.SourceBinding,
			BindingNamespace: hop.BindingNamespace,
			SourceRole:       hop.SourceRole,
			Difficulty:       hop.Difficulty,
		}
		if hop.ToSubject.Name != "" {
			record.To = hop.ToSubject.Key()
		}
		if verbose {
			record.Gains = hop.Gains
		}
		records = append(records, record)
	}
	return records
}

// roundScore drops the float noise that the per-hop arithmetic leaves in a
// score (8.149999999999999), so the JSON and the table show the same number.
func roundScore(score float64) float64 {
	return math.Round(score*100) / 100
}

// formatScore prints one or two decimals: "9.0", "8.5", "9.65".
func formatScore(score float64) string {
	text := strconv.FormatFloat(roundScore(score), 'f', 2, 64)
	return strings.TrimSuffix(text, "0")
}

func subjectKey(ref *models.SubjectRef) string {
	if ref == nil {
		return ""
	}
	return ref.Key()
}

func writePathsJSON(w io.Writer, findings []models.Finding, total int, notes []string, verbose bool) error {
	out := pathsOutput{
		Total:    total,
		Returned: len(findings),
		Notes:    notes,
		Paths:    make([]pathRecord, 0, len(findings)),
	}
	for _, finding := range findings {
		out.Paths = append(out.Paths, newPathRecord(finding, verbose))
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(out)
}

// writePathsTable prints one line for each path.
func writePathsTable(w io.Writer, findings []models.Finding) error {
	if len(findings) == 0 {
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "SEVERITY\tSCORE\tSOURCE\tTARGET\tHOPS\tCHAIN"); err != nil {
		return err
	}
	for _, finding := range findings {
		target, detail, _ := privesc.FindingTarget(finding)
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%s\n",
			finding.Severity,
			formatScore(finding.Score),
			subjectKey(finding.Subject),
			targetLabel(target, detail),
			len(finding.EscalationPath),
			chainOf(finding.EscalationPath),
		); err != nil {
			return err
		}
	}
	return tw.Flush()
}

// chainOf joins the action of each hop: "pod_exec > token_theft > bind_role".
func chainOf(hops []models.EscalationHop) string {
	actions := make([]string, 0, len(hops))
	for _, hop := range hops {
		actions = append(actions, hop.Action)
	}
	return strings.Join(actions, " > ")
}

// writePathsVerbose prints each path hop by hop, with the binding and role that
// grant each hop, then the fix.
func writePathsVerbose(w io.Writer, findings []models.Finding) error {
	var b strings.Builder
	for i, finding := range findings {
		if i > 0 {
			b.WriteString("\n")
		}
		target, detail, _ := privesc.FindingTarget(finding)
		label := targetLabel(target, detail)
		hops := finding.EscalationPath
		fmt.Fprintf(&b, "%s -> %s\n", subjectKey(finding.Subject), label)
		fmt.Fprintf(&b, "  severity: %s (score %s)   hops: %d\n", finding.Severity, formatScore(finding.Score), len(hops))
		fmt.Fprintf(&b, "  id: %s\n\n", finding.ID)

		for n, hop := range hops {
			fmt.Fprintf(&b, "  %d. %s", hop.Step, hop.Action)
			if hop.Difficulty != "" {
				fmt.Fprintf(&b, " (%s)", hop.Difficulty)
			}
			b.WriteString("\n")
			fmt.Fprintf(&b, "     from:       %s\n", hop.FromSubject.Key())
			switch {
			case n == len(hops)-1:
				fmt.Fprintf(&b, "     to:         %s\n", label)
			case hop.ToSubject.Name != "":
				fmt.Fprintf(&b, "     to:         %s\n", hop.ToSubject.Key())
			}
			if hop.Permission != "" {
				fmt.Fprintf(&b, "     permission: %s\n", hop.Permission)
			}
			if granted := grantedBy(hop); granted != "" {
				fmt.Fprintf(&b, "     granted by: %s\n", granted)
			}
			if hop.Gains != "" {
				fmt.Fprintf(&b, "     result:     %s\n", hop.Gains)
			}
		}

		if finding.Remediation != "" {
			fmt.Fprintf(&b, "\n  fix: %s\n", plainText(finding.Remediation))
		}
		if hint := finding.RemediationHint; hint != nil {
			if hint.Patch != nil && hint.Patch.Command != "" {
				writeIndented(&b, plainText(hint.Patch.Command), "    ")
			}
			if hint.RBACDiff != "" {
				b.WriteString("\n")
				writeIndented(&b, hint.RBACDiff, "    ")
			}
		}
		if len(finding.AlternateEscalationPath) > 0 {
			fmt.Fprintf(&b, "\n  a second route to this target stays open after that fix: %s\n", chainOf(finding.AlternateEscalationPath))
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// grantedBy names the binding and role behind a hop. It is empty for a hop that
// no one binding grants, such as an escape from a privileged pod.
func grantedBy(hop models.EscalationHop) string {
	if hop.SourceBinding == "" {
		return ""
	}
	binding := "ClusterRoleBinding " + hop.SourceBinding
	if hop.BindingNamespace != "" {
		binding = "RoleBinding " + hop.BindingNamespace + "/" + hop.SourceBinding
	}
	if hop.SourceRole == "" {
		return binding
	}
	return binding + " (role " + hop.SourceRole + ")"
}

// plainText removes the Markdown emphasis and code marks that finding prose
// carries for the HTML report.
func plainText(value string) string {
	return strings.NewReplacer("**", "", "`", "").Replace(value)
}

func writeIndented(b *strings.Builder, text, indent string) {
	for _, line := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
		b.WriteString(indent)
		b.WriteString(line)
		b.WriteString("\n")
	}
}

// writePathsFooter prints the count, the notes, and one hint after a table or a
// verbose listing. It goes to stderr, so stdout holds only the paths.
func writePathsFooter(w io.Writer, returned, total, depth int, source *models.SubjectRef, target *targetSelector, notes []string, verbose bool) error {
	var b strings.Builder
	switch {
	case total == 0:
		b.WriteString("No attack paths")
		if source != nil {
			fmt.Fprintf(&b, " from %s", source.Key())
		}
		if target != nil {
			fmt.Fprintf(&b, " to %s", targetLabel(target.target, target.detail))
		}
		fmt.Fprintf(&b, " within %d %s.\n", depth, pluralize(depth, "hop", "hops"))
	case returned < total:
		fmt.Fprintf(&b, "\nShowing %d of %d attack paths.\n", returned, total)
	default:
		fmt.Fprintf(&b, "\n%d attack %s.\n", total, pluralize(total, "path", "paths"))
	}
	for _, note := range notes {
		fmt.Fprintf(&b, "note: %s\n", note)
	}
	if total > 0 && !verbose {
		b.WriteString("Add --verbose to see each hop, the binding behind it, and the fix.\n")
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func pluralize(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
