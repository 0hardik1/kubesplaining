package usage

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

// nativeEvent mirrors the subset of github.com/k8s.io/apiserver/pkg/apis/audit.Event we
// consume. Using a hand-rolled type instead of the upstream package avoids a heavy
// transitive dep - we only need a handful of fields and the JSON shape is stable.
type nativeEvent struct {
	Verb                     string             `json:"verb"`
	User                     nativeUser         `json:"user"`
	ObjectRef                nativeObjectRef    `json:"objectRef"`
	ResponseStatus           nativeResponseStat `json:"responseStatus"`
	RequestReceivedTimestamp time.Time          `json:"requestReceivedTimestamp"`
}

type nativeUser struct {
	Username string `json:"username"`
}

type nativeObjectRef struct {
	APIGroup    string `json:"apiGroup"`
	Resource    string `json:"resource"`
	Subresource string `json:"subresource"`
	Namespace   string `json:"namespace"`
	Name        string `json:"name"`
}

type nativeResponseStat struct {
	Code int `json:"code"`
}

func (e nativeEvent) toAuditEvent() AuditEvent {
	resource := e.ObjectRef.Resource
	if resource != "" && e.ObjectRef.Subresource != "" {
		resource = resource + "/" + e.ObjectRef.Subresource
	}
	return AuditEvent{
		Username:    e.User.Username,
		Verb:        strings.ToLower(e.Verb),
		APIGroup:    e.ObjectRef.APIGroup,
		Resource:    resource,
		StatusCode:  e.ResponseStatus.Code,
		RequestedAt: e.RequestReceivedTimestamp,
	}
}

// parseNativeReader streams r line-by-line, emitting one AuditEvent per parseable JSON
// object. Malformed lines (blank, half-written during log rotation, garbage) are skipped
// and counted in skipped - they never abort ingestion. This mirrors the collector's
// "downgrade to warning" posture from `internal/collector/collector.go`: a partial audit
// log is more useful than no audit log.
//
// The default bufio.Scanner line cap (64 KiB) is too small for `RequestResponse`-level
// audit logs that include serialized object bodies. We bump to 4 MiB which comfortably
// fits the largest objects the apiserver writes (PSP, big ConfigMaps). Anything larger
// is almost certainly a malformed line and worth skipping.
func parseNativeReader(r io.Reader, emit func(AuditEvent), onSkip func()) error {
	const maxLine = 4 * 1024 * 1024
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), maxLine)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		// Some emitters wrap the audit Event in {"kind":"Event", ...}; the field set we
		// read is unchanged, so a single json.Unmarshal covers both shapes.
		var ev nativeEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			if onSkip != nil {
				onSkip()
			}
			continue
		}
		emit(ev.toAuditEvent())
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan audit log: %w", err)
	}
	return nil
}
