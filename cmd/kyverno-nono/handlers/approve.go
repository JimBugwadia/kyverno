// Package approve implements the nono approval webhook handler.
// It decodes the nono wire protocol, evaluates ValidatingPolicies with
// evaluation mode "Nono", and returns {"decision":"granted"} or
// {"decision":"denied","reason":"..."}.
//
// Key behavioral difference from kyverno-authz HTTP mode:
// when no policy produces a result the response is DENIED (fail-closed),
// not allowed. This matches nono's own fail-closed semantics.
package approve

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-logr/logr"
	"github.com/kyverno/kyverno-authz/pkg/events"
	authzmetics "github.com/kyverno/kyverno-authz/pkg/metrics"
	nonotype "github.com/kyverno/kyverno/pkg/cel/libs/authz/nono"
	"github.com/kyverno/sdk/core"
	"github.com/kyverno/sdk/extensions/policy"
	"k8s.io/client-go/dynamic"
	ctrl "sigs.k8s.io/controller-runtime"
)

const modeNono = "nono"

// NonoPolicy is the type alias for a compiled nono policy.
type NonoPolicy = policy.Policy[dynamic.Interface, *nonotype.CheckRequest, *nonotype.CheckResponse]

// decisionResponse is the wire JSON response nono expects.
type decisionResponse struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason,omitempty"`
}

// Authorizer is the http.Handler for POST /approve.
type Authorizer struct {
	engine       core.Engine[dynamic.Interface, *nonotype.CheckRequest, policy.Evaluation[*nonotype.CheckResponse]]
	dyn          dynamic.Interface
	eventHandler events.EventIface[nonotype.CheckRequest]
}

// NewAuthorizer constructs an Authorizer.
func NewAuthorizer(
	eng core.Engine[dynamic.Interface, *nonotype.CheckRequest, policy.Evaluation[*nonotype.CheckResponse]],
	dyn dynamic.Interface,
	eventIface events.EventIface[nonotype.CheckRequest],
) *Authorizer {
	return &Authorizer{
		engine:       eng,
		dyn:          dyn,
		eventHandler: eventIface,
	}
}

func (a *Authorizer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	decision := authzmetics.DecisionError
	source := authzmetics.SourceServer
	defer func() {
		authzmetics.RecordAuthzDecision(modeNono, decision, source, start)
	}()

	logger := ctrl.LoggerFrom(r.Context()).WithValues("from", r.RemoteAddr)
	logger.Info("received nono approval request")

	// Decode the nono request body.
	req, err := nonotype.NewRequest(r)
	if err != nil {
		logger.Error(err, "failed to decode nono request body")
		writeDenied(w, http.StatusBadRequest, "malformed request: "+err.Error())
		return
	}

	// Run the policy engine.
	response := a.engine.Handle(r.Context(), a.dyn, &req)
	if response.Error != nil {
		source = authzmetics.SourceEngine
		logger.Error(response.Error, "policy engine error")
		a.eventHandler.Push(context.Background(), time.Now(), req, NewResultAccessor(nil, response.Error))
		// Fail-closed: engine errors → deny with reason.
		writeGrantedOrDenied(w, logger, nil, response.Error)
		return
	}

	result := response.Result
	if result == nil {
		// Fail-closed: no policy matched → deny.
		decision = authzmetics.DecisionNoMatch
		source = authzmetics.SourceDefault
		noMatch := &nonotype.CheckResponse{
			Denied: &nonotype.CheckResponseDenied{Reason: "no policy granted this request"},
		}
		a.eventHandler.Push(context.Background(), time.Now(), req, NewResultAccessor(noMatch, nil))
		writeGrantedOrDenied(w, logger, noMatch, nil)
		return
	}

	if result.Denied != nil {
		decision = authzmetics.DecisionDeny
	} else {
		decision = authzmetics.DecisionAllow
	}
	source = authzmetics.SourcePolicy
	a.eventHandler.Push(context.Background(), time.Now(), req, NewResultAccessor(result, nil))
	writeGrantedOrDenied(w, logger, result, nil)
}

func writeGrantedOrDenied(
	w http.ResponseWriter,
	logger logr.Logger,
	result *nonotype.CheckResponse,
	err error,
) {
	w.Header().Set("Content-Type", "application/json")
	var resp decisionResponse
	if err != nil {
		resp = decisionResponse{
			Decision: "denied",
			Reason:   fmt.Sprintf("engine error: %v", err),
		}
	} else if result == nil || result.Denied != nil {
		reason := "no policy granted this request"
		if result != nil && result.Denied != nil {
			reason = result.Denied.Reason
		}
		resp = decisionResponse{Decision: "denied", Reason: reason}
	} else {
		resp = decisionResponse{Decision: "granted"}
	}
	w.WriteHeader(http.StatusOK)
	if encErr := json.NewEncoder(w).Encode(resp); encErr != nil {
		logger.Error(encErr, "failed to write response")
	}
}

func writeDenied(w http.ResponseWriter, status int, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(decisionResponse{Decision: "denied", Reason: reason}) //nolint:errcheck
}
