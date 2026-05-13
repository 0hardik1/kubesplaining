// Package usage builds and queries an in-memory index of "what RBAC verbs has each subject
// actually exercised within an observation window?" It is the data layer behind the
// least-privilege analyzer: granted permissions come from the snapshot (point-in-time),
// observed permissions come from the kube-apiserver audit log (history), and the analyzer
// diffs them to surface narrowing opportunities.
//
// The index never persists. Audit logs are large, snapshots are small and shareable; the
// loader streams the log once at scan time, builds the index, and the analyzer queries it
// before it is dropped at process exit. The window metadata travels on each finding so the
// HTML report can show reviewers what data fed the verdict.
package usage

import (
	"strings"
	"time"

	"github.com/0hardik1/kubesplaining/internal/models"
)

// UsageIndex is the in-memory aggregate of audit-log observations keyed by subject and
// (apiGroup, resource[/subresource]). Construct one via LoadAuditLog. Queries are read-only
// and safe to call from multiple goroutines.
type UsageIndex struct {
	WindowStart     time.Time
	WindowEnd       time.Time
	EventsProcessed int
	// EventsSkipped counts events dropped during ingestion: denied responses, parse errors,
	// out-of-window timestamps, non-ServiceAccount users. The total is surfaced in the HTML
	// report so reviewers can sanity-check ingest health.
	EventsSkipped  int
	NonSAUsernames int // events from human/group users; ignored by v1 but counted for transparency

	perSubject map[string]*subjectUsage // key = models.SubjectRef.Key()
}

type subjectUsage struct {
	byGVR map[gvrKey]verbSet
}

// gvrKey is the (apiGroup, resource[/subresource]) coordinate. "" is the core group; the
// subresource is folded into Resource as "pods/exec" to keep one map per coordinate.
type gvrKey struct {
	APIGroup string
	Resource string
}

// verbSet is a set of observed verbs. Stored as map[string]struct{} so contains/insert are O(1).
type verbSet map[string]struct{}

func newVerbSet() verbSet { return verbSet{} }

func (s verbSet) add(v string) {
	if v == "" {
		return
	}
	s[v] = struct{}{}
}

// Contains reports whether verb v has been observed. Empty input returns false.
func (s verbSet) Contains(v string) bool {
	if s == nil {
		return false
	}
	_, ok := s[v]
	return ok
}

// Sorted returns the verbs in stable order - for deterministic finding evidence and tests.
func (s verbSet) Sorted() []string {
	out := make([]string, 0, len(s))
	for v := range s {
		out = append(out, v)
	}
	// stdlib sort is enough; tiny slices, no need for slices.Sort here either way.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

// Observed returns the verbs observed for subject on (apiGroup, resource). Subresources
// are tracked separately: a query for "pods" will NOT return verbs observed against
// "pods/exec". This matches Kubernetes RBAC semantics - pods and pods/exec are distinct
// grants and need distinct usage signals.
//
// Returns an empty (non-nil) verbSet when nothing has been observed; callers can iterate
// freely without nil checks.
func (i *UsageIndex) Observed(subj models.SubjectRef, apiGroup, resource string) verbSet {
	if i == nil {
		return verbSet{}
	}
	su, ok := i.perSubject[subj.Key()]
	if !ok {
		return verbSet{}
	}
	v, ok := su.byGVR[gvrKey{APIGroup: apiGroup, Resource: resource}]
	if !ok {
		return verbSet{}
	}
	return v
}

// HasAnyEventsFor reports whether the index contains any event attributed to subj within
// the observation window. Used by the analyzer to distinguish "subject is silent on
// resource X but active elsewhere" (narrow finding) from "subject is silent everywhere"
// (whole-Role candidate for removal).
func (i *UsageIndex) HasAnyEventsFor(subj models.SubjectRef) bool {
	if i == nil {
		return false
	}
	_, ok := i.perSubject[subj.Key()]
	return ok
}

// ObservedGVRs returns every (apiGroup, resource) coordinate that subj has touched. Used
// by the wildcard-expansion path: when a Role grants `verbs: ["*"]` on `apiGroups: ["*"]`,
// we don't enumerate every possible cluster verb - we only consider what the subject has
// actually exercised, which is the only signal we have for "narrower than the wildcard."
func (i *UsageIndex) ObservedGVRs(subj models.SubjectRef) []gvrKey {
	if i == nil {
		return nil
	}
	su, ok := i.perSubject[subj.Key()]
	if !ok {
		return nil
	}
	out := make([]gvrKey, 0, len(su.byGVR))
	for k := range su.byGVR {
		out = append(out, k)
	}
	return out
}

// record inserts a single (subj, group, resource, verb) tuple into the index. The parser
// adapters call this once per kept event. Idempotent - re-inserting an existing tuple is a
// no-op.
func (i *UsageIndex) record(subj models.SubjectRef, apiGroup, resource, verb string) {
	if i.perSubject == nil {
		i.perSubject = map[string]*subjectUsage{}
	}
	key := subj.Key()
	su := i.perSubject[key]
	if su == nil {
		su = &subjectUsage{byGVR: map[gvrKey]verbSet{}}
		i.perSubject[key] = su
	}
	gk := gvrKey{APIGroup: apiGroup, Resource: resource}
	vs := su.byGVR[gk]
	if vs == nil {
		vs = newVerbSet()
		su.byGVR[gk] = vs
	}
	vs.add(verb)
}

// SubjectFromUsername parses a username string into a models.SubjectRef. ServiceAccount
// users are emitted by the API server as `system:serviceaccount:<namespace>:<name>` -
// we map that into the canonical SubjectRef shape so it aligns with snapshot-derived
// subjects. Any other shape (humans authenticated via OIDC/cert, internal system users,
// `system:anonymous`, etc.) returns ok=false; v1 of the least-privilege analyzer only
// considers ServiceAccount workloads.
func SubjectFromUsername(username string) (models.SubjectRef, bool) {
	const prefix = "system:serviceaccount:"
	if !strings.HasPrefix(username, prefix) {
		return models.SubjectRef{}, false
	}
	rest := username[len(prefix):]
	slash := strings.IndexByte(rest, ':')
	if slash <= 0 || slash >= len(rest)-1 {
		return models.SubjectRef{}, false
	}
	return models.SubjectRef{
		Kind:      "ServiceAccount",
		Namespace: rest[:slash],
		Name:      rest[slash+1:],
	}, true
}

// EmptyIndex returns a usable empty index. Callers in pre-flight error paths use it so
// downstream code can dereference the pointer without nil-checks.
func EmptyIndex() *UsageIndex {
	return &UsageIndex{perSubject: map[string]*subjectUsage{}}
}
