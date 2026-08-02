// Package approve provides a nono-specific ResultAccessor that handles
// nono.CheckResponse so it can participate in the kyverno-authz events fan-out
// without triggering the upstream type-switch panic.
package approve

import (
	"github.com/kyverno/kyverno-authz/pkg/events"
	nonotype "github.com/kyverno/kyverno/pkg/cel/libs/authz/nono"
)

// NewResultAccessor creates a ResultAccessor compatible with the kyverno-authz
// events infrastructure from a nono CheckResponse and optional error.
func NewResultAccessor(res *nonotype.CheckResponse, err error) events.ResultAccessor {
	return &nonoResultAccessor{res: res, err: err}
}

type nonoResultAccessor struct {
	res *nonotype.CheckResponse
	err error
}

func (r *nonoResultAccessor) MustGet() (string, error) {
	if r.err != nil {
		return events.RequestErrored, r.err
	}
	if r.res == nil || r.res.Denied != nil {
		return events.RequestDenied, nil
	}
	return events.RequestAllowed, nil
}
