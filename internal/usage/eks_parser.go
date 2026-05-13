package usage

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// eksFilterLogEventsOutput matches the shape returned by `aws logs filter-log-events
// --output json` for an EKS cluster's `/aws/eks/<cluster>/cluster` log group with stream
// prefix `kube-apiserver-audit-`. The CloudWatch envelope (timestamp/logStreamName/etc.)
// wraps the same kube-apiserver audit JSON the native parser already understands, so the
// EKS parser is "unwrap envelope, delegate to the native unmarshal."
type eksFilterLogEventsOutput struct {
	Events []eksLogEvent `json:"events"`
}

type eksLogEvent struct {
	// Message is the raw kube-apiserver audit JSON, escaped as a string by CloudWatch.
	Message string `json:"message"`
}

// parseEKSReader handles two on-disk shapes the EKS CLI can produce:
//
//  1. A single JSON object {"events":[{"message":"..."},...]} written by the default
//     `aws logs filter-log-events --output json` call.
//  2. A JSON-lines stream where each line is one `{"message":"..."}` object, written by
//     `aws logs tail` or post-processed exports.
//
// We detect (2) by sniffing the first non-whitespace byte: `{` followed by `"events"` is
// (1); anything else is (2). Both paths funnel each inner message through the native
// parser via parseNativeBytes.
func parseEKSReader(r io.Reader, emit func(AuditEvent), onSkip func()) error {
	buf, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("read eks audit export: %w", err)
	}
	trimmed := strings.TrimSpace(string(buf))
	if trimmed == "" {
		return nil
	}

	// Shape (1): single object containing "events":[...] array.
	if strings.HasPrefix(trimmed, "{") && strings.Contains(trimmed[:min(256, len(trimmed))], `"events"`) { //nolint:staticcheck // builtin min, Go 1.21+
		var out eksFilterLogEventsOutput
		if err := json.Unmarshal([]byte(trimmed), &out); err != nil {
			return fmt.Errorf("decode eks filter-log-events output: %w", err)
		}
		for _, ev := range out.Events {
			if ev.Message == "" {
				if onSkip != nil {
					onSkip()
				}
				continue
			}
			var inner nativeEvent
			if err := json.Unmarshal([]byte(ev.Message), &inner); err != nil {
				if onSkip != nil {
					onSkip()
				}
				continue
			}
			emit(inner.toAuditEvent())
		}
		return nil
	}

	// Shape (2): JSON-lines, each line wraps {"message":"<audit-json>"}.
	for _, line := range strings.Split(trimmed, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var wrap eksLogEvent
		if err := json.Unmarshal([]byte(line), &wrap); err != nil || wrap.Message == "" {
			if onSkip != nil {
				onSkip()
			}
			continue
		}
		var inner nativeEvent
		if err := json.Unmarshal([]byte(wrap.Message), &inner); err != nil {
			if onSkip != nil {
				onSkip()
			}
			continue
		}
		emit(inner.toAuditEvent())
	}
	return nil
}
