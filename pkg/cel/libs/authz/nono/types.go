package nono

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/google/cel-go/common/types"
)

var (
	RequestEnvelopeType = types.NewObjectType("nono.CheckRequest")
	RequestDataType     = types.NewObjectType("nono.RequestData")
	ResponseType        = types.NewObjectType("nono.CheckResponse")
	ResponseGrantedType = types.NewObjectType("nono.CheckResponseGranted")
	ResponseDeniedType  = types.NewObjectType("nono.CheckResponseDenied")
)

// CheckRequest is the outer nono envelope, bound as the CEL `object` variable.
// Policy expressions access nono-specific data via object.request.*.
type CheckRequest struct {
	Backend string      `json:"backend" cel:"backend"`
	Request RequestData `json:"request" cel:"request"`
}

// RequestData mirrors the nono wire format `request` object exactly.
// All fields are zero-valued when not applicable to the current capability_type,
// so CEL access is always safe without nil checks.
type RequestData struct {
	// Common fields
	CapabilityType string `json:"capability_type" cel:"capability_type"`
	RequestID      string `json:"request_id"      cel:"request_id"`
	SessionID      string `json:"session_id"      cel:"session_id"`
	ChildPid       int64  `json:"child_pid"       cel:"child_pid"`

	// Command fields (populated when capability_type == "command")
	Command       string   `json:"command"        cel:"command"`
	Caller        string   `json:"caller"         cel:"caller"`
	Args          []string `json:"args"           cel:"args"`
	InterceptRule string   `json:"intercept_rule" cel:"intercept_rule"`

	// Endpoint fields (populated when capability_type == "endpoint")
	Method    string `json:"method"     cel:"method"`
	Path      string `json:"path"       cel:"path"`
	RouteID   string `json:"route_id"   cel:"route_id"`
	Upstream  string `json:"upstream"   cel:"upstream"`
	RuleLabel string `json:"rule_label" cel:"rule_label"`
}

// CheckResponse is what a policy validation expression must return.
type CheckResponse struct {
	Granted *CheckResponseGranted `json:"granted,omitempty" cel:"granted"`
	Denied  *CheckResponseDenied  `json:"denied,omitempty"  cel:"denied"`
}

type CheckResponseGranted struct{}

type CheckResponseDenied struct {
	Reason string `json:"reason" cel:"reason"`
}

// nonoRequestBody is the raw JSON shape nono sends to POST /approve.
type nonoRequestBody struct {
	Backend string         `json:"backend"`
	Request map[string]any `json:"request"`
}

// NewRequest parses a nono POST /approve HTTP request body into a CheckRequest.
func NewRequest(r *http.Request) (CheckRequest, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return CheckRequest{}, err
	}
	return ParseRequest(body)
}

// ParseRequest parses a raw nono approval body.
// Missing fields are silently zero-valued so fail-closed policy evaluation can still run.
func ParseRequest(body []byte) (CheckRequest, error) {
	var raw nonoRequestBody
	if err := json.Unmarshal(body, &raw); err != nil {
		return CheckRequest{}, err
	}

	req := raw.Request
	if req == nil {
		req = map[string]any{}
	}

	rd := RequestData{
		CapabilityType: stringField(req, "capability_type"),
		RequestID:      stringField(req, "request_id"),
		SessionID:      stringField(req, "session_id"),
		ChildPid:       int64Field(req, "child_pid"),
		Command:        stringField(req, "command"),
		Caller:         stringField(req, "caller"),
		Args:           stringSliceField(req, "args"),
		InterceptRule:  stringField(req, "intercept_rule"),
		Method:         stringField(req, "method"),
		Path:           stringField(req, "path"),
		RouteID:        stringField(req, "route_id"),
		Upstream:       stringField(req, "upstream"),
		RuleLabel:      stringField(req, "rule_label"),
	}

	return CheckRequest{
		Backend: raw.Backend,
		Request: rd,
	}, nil
}

func stringField(m map[string]any, key string) string {
	v, _ := m[key].(string)
	return v
}

func int64Field(m map[string]any, key string) int64 {
	switch v := m[key].(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	case int:
		return int64(v)
	}
	return 0
}

func stringSliceField(m map[string]any, key string) []string {
	raw, ok := m[key].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
