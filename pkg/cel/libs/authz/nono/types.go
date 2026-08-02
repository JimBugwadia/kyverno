package nono

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/google/cel-go/common/types"
)

var (
	RequestType         = types.NewObjectType("nono.CheckRequest")
	ResponseType        = types.NewObjectType("nono.CheckResponse")
	ResponseGrantedType = types.NewObjectType("nono.CheckResponseGranted")
	ResponseDeniedType  = types.NewObjectType("nono.CheckResponseDenied")
	CapabilityType      = types.NewObjectType("nono.CapabilityData")
	CommandDataType     = types.NewObjectType("nono.CommandData")
	EndpointDataType    = types.NewObjectType("nono.EndpointData")
)

// CheckRequest is the nono approval envelope, registered as the CEL `object` variable.
// Both Command and Endpoint are value types (never nil) so CEL access is always safe.
type CheckRequest struct {
	Backend    string         `json:"backend"    cel:"backend"`
	Capability CapabilityData `json:"capability" cel:"capability"`
	// Raw holds the full unstructured request map for forward-compatibility with
	// future capability types not yet modeled in CapabilityData.
	Raw map[string]any `json:"raw" cel:"raw"`
}

// CapabilityData is the union of command and endpoint fields.
// Fields are zero-valued when not applicable to the capability type.
type CapabilityData struct {
	Type     string       `json:"type"     cel:"type"`     // "command" | "endpoint"
	ID       string       `json:"id"       cel:"id"`       // request_id
	Session  string       `json:"session"  cel:"session"`  // session_id
	Pid      int64        `json:"pid"      cel:"pid"`      // child_pid
	Command  CommandData  `json:"command"  cel:"command"`  // populated when type=="command"
	Endpoint EndpointData `json:"endpoint" cel:"endpoint"` // populated when type=="endpoint"
}

// CommandData holds fields present when capability_type == "command".
type CommandData struct {
	Name          string   `json:"name"           cel:"name"`
	Caller        string   `json:"caller"         cel:"caller"`
	Args          []string `json:"args"           cel:"args"`
	InterceptRule string   `json:"intercept_rule" cel:"intercept_rule"`
}

// EndpointData holds fields present when capability_type == "endpoint".
type EndpointData struct {
	Method    string `json:"method"     cel:"method"`
	Path      string `json:"path"       cel:"path"`
	RouteID   string `json:"route_id"   cel:"route_id"`
	Upstream  string `json:"upstream"   cel:"upstream"`
	RuleLabel string `json:"rule_label" cel:"rule_label"`
}

// CheckResponse is what a policy validation expression must return (or null).
type CheckResponse struct {
	Granted *CheckResponseGranted `json:"granted,omitempty" cel:"granted"`
	Denied  *CheckResponseDenied  `json:"denied,omitempty"  cel:"denied"`
}

type CheckResponseGranted struct{}

type CheckResponseDenied struct {
	Reason string `json:"reason" cel:"reason"`
}

// nonoRequestBody is the raw JSON shape nono sends.
type nonoRequestBody struct {
	Backend string         `json:"backend"`
	Request map[string]any `json:"request"`
}

// NewRequest parses a nono POST /approve request body into a CheckRequest.
// Returns an error only for I/O or JSON decode failures; missing fields are
// silently zero-valued so that fail-closed policy evaluation can still run.
func NewRequest(r *http.Request) (CheckRequest, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return CheckRequest{}, err
	}
	return ParseRequest(body)
}

// ParseRequest parses a raw nono approval body.
func ParseRequest(body []byte) (CheckRequest, error) {
	var raw nonoRequestBody
	if err := json.Unmarshal(body, &raw); err != nil {
		return CheckRequest{}, err
	}

	req := raw.Request
	if req == nil {
		req = map[string]any{}
	}

	cap := CapabilityData{
		Type:    stringField(req, "capability_type"),
		ID:      stringField(req, "request_id"),
		Session: stringField(req, "session_id"),
		Pid:     int64Field(req, "child_pid"),
	}

	switch cap.Type {
	case "command":
		cap.Command = CommandData{
			Name:          stringField(req, "command"),
			Caller:        stringField(req, "caller"),
			Args:          stringSliceField(req, "args"),
			InterceptRule: stringField(req, "intercept_rule"),
		}
	case "endpoint":
		cap.Endpoint = EndpointData{
			Method:    stringField(req, "method"),
			Path:      stringField(req, "path"),
			RouteID:   stringField(req, "route_id"),
			Upstream:  stringField(req, "upstream"),
			RuleLabel: stringField(req, "rule_label"),
		}
	}

	// Store raw for forward-compat access via object.raw
	rawMap := map[string]any{
		"backend": raw.Backend,
	}
	for k, v := range req {
		rawMap[k] = v
	}

	return CheckRequest{
		Backend:    raw.Backend,
		Capability: cap,
		Raw:        rawMap,
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
