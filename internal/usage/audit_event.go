package usage

import "time"

// AuditEvent is the normalized intermediate shape the parsers produce. Both the native
// kube-apiserver JSON-lines parser and the EKS CloudWatch envelope parser emit AuditEvents
// that the indexer consumes. Keeping a single internal shape means new audit-log sources
// only need a new parser, never analyzer-side changes.
type AuditEvent struct {
	Username    string
	Verb        string
	APIGroup    string
	Resource    string // including any subresource appended as "resource/subresource"
	StatusCode  int
	RequestedAt time.Time
}

// keep reports whether an event should be counted into the index. The window check uses
// [windowStart, now] inclusive on both ends; events outside the window are dropped along
// with denied responses (>= 400, where the server refused the request) and events whose
// username doesn't parse to a ServiceAccount subject.
//
// We treat any 4xx/5xx as "denied or failed" - counting failed writes as usage would
// invert the test: an attacker probing for permissions would dilute the unused signal.
// Read-only callers occasionally produce 404 (object not found) but we don't fold those
// back in; if a Role grants `get pods` and the subject only ever 404s on missing pods,
// the analyzer flagging it as unused is still the right call.
func (e AuditEvent) keep(windowStart, windowEnd time.Time) bool {
	if e.StatusCode >= 400 {
		return false
	}
	if e.Verb == "" || e.Resource == "" {
		return false
	}
	if e.RequestedAt.Before(windowStart) || e.RequestedAt.After(windowEnd) {
		return false
	}
	return true
}
