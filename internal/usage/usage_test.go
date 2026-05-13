package usage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/0hardik1/kubesplaining/internal/models"
)

// TestSubjectFromUsername verifies the audit-username → SubjectRef mapping for the only
// shape v1 cares about (ServiceAccount). Non-SA usernames must return ok=false so the
// loader knows to bump NonSAUsernames rather than silently dropping events with no
// signal.
func TestSubjectFromUsername(t *testing.T) {
	tests := []struct {
		name      string
		username  string
		wantOK    bool
		wantNs    string
		wantSAVal string
	}{
		{"plain SA", "system:serviceaccount:default:builder", true, "default", "builder"},
		{"kube-system SA", "system:serviceaccount:kube-system:coredns", true, "kube-system", "coredns"},
		{"system:anonymous", "system:anonymous", false, "", ""},
		{"human OIDC sub", "user@example.com", false, "", ""},
		{"system:kube-controller-manager", "system:kube-controller-manager", false, "", ""},
		{"malformed missing name", "system:serviceaccount:default:", false, "", ""},
		{"malformed missing ns", "system:serviceaccount::name", false, "", ""},
		{"empty", "", false, "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			subj, ok := SubjectFromUsername(tc.username)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if subj.Namespace != tc.wantNs || subj.Name != tc.wantSAVal || subj.Kind != "ServiceAccount" {
				t.Errorf("got %+v, want ns=%q name=%q", subj, tc.wantNs, tc.wantSAVal)
			}
		})
	}
}

// TestNativeParser_Basic walks the native JSON-lines parser end-to-end: feeds a small
// batch of events, asserts the kept set lands in the index against the right (group,
// resource, verb) coordinates, and confirms denied/out-of-window events are skipped.
func TestNativeParser_Basic(t *testing.T) {
	dir := t.TempDir()
	now := mustParseTime("2026-05-13T12:00:00Z")
	// 30-day window ends at `now`; "old" event sits 60 days earlier and must be filtered.
	old := now.Add(-60 * 24 * time.Hour).Format(time.RFC3339)
	recent := now.Add(-1 * time.Hour).Format(time.RFC3339)

	lines := []string{
		// 1) recent + kept: get pods by builder SA
		`{"verb":"get","user":{"username":"system:serviceaccount:default:builder"},"objectRef":{"apiGroup":"","resource":"pods"},"responseStatus":{"code":200},"requestReceivedTimestamp":"` + recent + `"}`,
		// 2) recent + kept: list secrets, subresource appended in normalized form
		`{"verb":"list","user":{"username":"system:serviceaccount:default:builder"},"objectRef":{"apiGroup":"","resource":"pods","subresource":"exec"},"responseStatus":{"code":200},"requestReceivedTimestamp":"` + recent + `"}`,
		// 3) denied - must be skipped even though username + verb are clean
		`{"verb":"delete","user":{"username":"system:serviceaccount:default:builder"},"objectRef":{"apiGroup":"","resource":"pods"},"responseStatus":{"code":403},"requestReceivedTimestamp":"` + recent + `"}`,
		// 4) out-of-window - must be skipped
		`{"verb":"create","user":{"username":"system:serviceaccount:default:builder"},"objectRef":{"apiGroup":"","resource":"pods"},"responseStatus":{"code":201},"requestReceivedTimestamp":"` + old + `"}`,
		// 5) non-SA user - must be skipped, increments NonSAUsernames
		`{"verb":"get","user":{"username":"alice@example.com"},"objectRef":{"apiGroup":"","resource":"pods"},"responseStatus":{"code":200},"requestReceivedTimestamp":"` + recent + `"}`,
		// 6) garbage line - must be skipped without aborting
		`{"verb":"`,
		// 7) recent + kept: apps/Deployment get
		`{"verb":"get","user":{"username":"system:serviceaccount:default:builder"},"objectRef":{"apiGroup":"apps","resource":"deployments"},"responseStatus":{"code":200},"requestReceivedTimestamp":"` + recent + `"}`,
	}

	path := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	idx, warns, err := LoadAuditLog([]string{path}, SourceNative, 30*24*time.Hour, now)
	if err != nil {
		t.Fatalf("LoadAuditLog: %v", err)
	}
	if len(warns) != 0 {
		t.Fatalf("unexpected warnings: %v", warns)
	}
	if idx.EventsProcessed != 3 {
		t.Errorf("EventsProcessed = %d, want 3", idx.EventsProcessed)
	}
	if idx.NonSAUsernames != 1 {
		t.Errorf("NonSAUsernames = %d, want 1", idx.NonSAUsernames)
	}
	// EventsSkipped should cover at least the 1 garbage line, 1 denied, 1 out-of-window =
	// 3 (exact count). Non-SA users count separately in NonSAUsernames, not Skipped.
	if idx.EventsSkipped != 3 {
		t.Errorf("EventsSkipped = %d, want 3", idx.EventsSkipped)
	}

	subj := mustParseSubject(t, "system:serviceaccount:default:builder")

	if !idx.HasAnyEventsFor(subj) {
		t.Fatal("expected HasAnyEventsFor(builder) = true")
	}
	if !idx.Observed(subj, "", "pods").Contains("get") {
		t.Errorf("expected `get pods` observed for builder")
	}
	if idx.Observed(subj, "", "pods").Contains("delete") {
		t.Errorf("denied `delete pods` should NOT be observed")
	}
	// Subresource is kept distinct: list pods/exec recorded, list pods NOT.
	if !idx.Observed(subj, "", "pods/exec").Contains("list") {
		t.Errorf("expected `list pods/exec` observed")
	}
	if idx.Observed(subj, "", "pods").Contains("list") {
		t.Errorf("list pods (parent) should NOT be observed via subresource event")
	}
	if !idx.Observed(subj, "apps", "deployments").Contains("get") {
		t.Errorf("expected `get apps/deployments` observed")
	}
}

// TestEKSParser_WrappedShape feeds an EKS-shaped export and confirms the envelope is
// stripped and the underlying audit event lands in the index. The native parser is the
// shared backend, so we only need to verify the unwrap path.
func TestEKSParser_WrappedShape(t *testing.T) {
	dir := t.TempDir()
	now := mustParseTime("2026-05-13T12:00:00Z")
	recent := now.Add(-2 * time.Hour).Format(time.RFC3339)

	// Inner audit event, exactly as kube-apiserver writes it. We embed it as a JSON
	// string inside the CloudWatch envelope below.
	inner := `{"verb":"get","user":{"username":"system:serviceaccount:default:builder"},"objectRef":{"apiGroup":"","resource":"configmaps"},"responseStatus":{"code":200},"requestReceivedTimestamp":"` + recent + `"}`
	innerEscaped := strings.ReplaceAll(inner, `"`, `\"`)
	export := `{"events":[{"message":"` + innerEscaped + `"}]}`

	path := filepath.Join(dir, "eks.json")
	if err := os.WriteFile(path, []byte(export), 0o644); err != nil {
		t.Fatal(err)
	}

	idx, _, err := LoadAuditLog([]string{path}, SourceEKS, 30*24*time.Hour, now)
	if err != nil {
		t.Fatalf("LoadAuditLog: %v", err)
	}
	if idx.EventsProcessed != 1 {
		t.Fatalf("EventsProcessed = %d, want 1", idx.EventsProcessed)
	}
	subj := mustParseSubject(t, "system:serviceaccount:default:builder")
	if !idx.Observed(subj, "", "configmaps").Contains("get") {
		t.Errorf("expected `get configmaps` observed after EKS unwrap")
	}
}

// TestParseSource sanity-checks the CLI flag mapping. Unknown values must return ok=false
// so scan.go can surface a clean error to the operator.
func TestParseSource(t *testing.T) {
	tests := []struct {
		in     string
		want   Source
		wantOK bool
	}{
		{"", SourceNative, true},
		{"native", SourceNative, true},
		{"NATIVE", SourceNative, true},
		{"eks", SourceEKS, true},
		{"gke", "", false},
		{"junk", "", false},
	}
	for _, tc := range tests {
		got, ok := ParseSource(tc.in)
		if ok != tc.wantOK || got != tc.want {
			t.Errorf("ParseSource(%q) = (%q, %v), want (%q, %v)", tc.in, got, ok, tc.want, tc.wantOK)
		}
	}
}

func mustParseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func mustParseSubject(t *testing.T, username string) models.SubjectRef {
	t.Helper()
	s, ok := SubjectFromUsername(username)
	if !ok {
		t.Fatalf("SubjectFromUsername(%q): ok=false", username)
	}
	return s
}
