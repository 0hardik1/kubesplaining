package cli

import "errors"

// Exit codes. A script or an agent must be able to tell "the scan ran and the
// findings are over budget" from "the tool could not do its work", because the
// first is a result and the second is a fault.
const (
	// ExitFailure is any error that is not a gate result: bad flags, an
	// unreachable cluster, an unreadable file.
	ExitFailure = 1
	// ExitGateExceeded means the command completed and a pass/fail gate
	// (--ci-mode) reported that the findings are over the configured budget.
	ExitGateExceeded = 2
)

// gateError marks an error as a gate result. The wrapped error keeps its text,
// so the message on stderr does not change.
type gateError struct{ err error }

func (e gateError) Error() string { return e.err.Error() }
func (e gateError) Unwrap() error { return e.err }

// asGateError wraps err so ExitCode maps it to ExitGateExceeded.
func asGateError(err error) error {
	if err == nil {
		return nil
	}
	return gateError{err: err}
}

// ExitCode maps an error returned by the root command to a process exit code.
func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	var gate gateError
	if errors.As(err, &gate) {
		return ExitGateExceeded
	}
	return ExitFailure
}
