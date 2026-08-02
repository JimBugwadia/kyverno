# kyverno-nono: Design Document

> **Status: PROPOSED — awaiting review and approval before implementation**
>
> Worktree: `kyverno-nono-worktree` · Branch: `kyverno-nono-design`

---

## 1. Problem Statement

[nono.sh](https://github.com/nolabs-ai/tool-sandbox-examples/tree/main/kubernetes) is a kernel-enforced sandbox for AI agents (e.g. Claude Code). When an agent tries to execute a command (`kubectl scale ...`) or make an HTTP endpoint call, nono can be configured to seek approval from an external webhook backend before allowing the action. The demo ships a trivial Python webhook at `localhost:8765/approve`.

**Goal:** replace that demo webhook with a production-quality **central approval server** that:
- Implements the nono approval wire contract
- Evaluates approval decisions using **Kyverno CEL policies** (the same `ValidatingPolicy` CRD used by kyverno-authz)
- Supports **PolicyExceptions** for trusted sessions or break-glass scenarios
- Emits **audit logs, PolicyReports, and Prometheus metrics**
- Is **fail-closed** (no policy match → deny)
- Can run in-cluster or standalone (dev laptop with no K8s)

The model follows [kyverno-authz](https://github.com/kyverno/kyverno-authz) exactly: it is a new **evaluation mode** (`Nono`) on the same `ValidatingPolicy` CRD, backed by a new CEL type library for the nono wire protocol.

---

## 2. How nono.sh External Approvals Work

```
 agent (Claude Code) inside nono sandbox
        │
        └─ executes: kubectl scale deployment/web --replicas=3
                         │
                [invocation_policy → approve tier]
                         │
                         ▼
        POST http://127.0.0.1:8765/approve
        Content-Type: application/json

        {
          "backend": "kyverno-nono",
          "request": {
            "capability_type": "command",
            "request_id":      "tool-sandbox-approve-kubectl-17849...",
            "session_id":      "35abc089...",
            "child_pid":       13820,
            "command":         "kubectl",
            "caller":          "claude",
            "args":            ["kubectl","scale","deployment/web","--replicas=3"],
            "intercept_rule":  "scale"
          }
        }

        ←  HTTP 200
           {"decision": "granted"}      # or
           {"decision": "denied", "reason": "scale blocked by policy"}
```

For HTTP endpoint interception (`endpoint_policy`), the same endpoint is called with `capability_type: "endpoint"`:

```json
{
  "backend": "kyverno-nono",
  "request": {
    "capability_type": "endpoint",
    "request_id":      "proxy-endpoint-approval-...",
    "session_id":      "35abc089...",
    "child_pid":       0,
    "method":          "PATCH",
    "path":            "/apis/apps/v1/namespaces/staging/deployments/web/scale",
    "route_id":        "kubernetes-api-staging",
    "upstream":        "https://127.0.0.1:6443",
    "rule_label":      "endpoint_policy.approve[PATCH /apis/**]"
  }
}
```

> **Wire contract note (verified):** nono's decision values are `"granted"` / `"denied"` (not `"allow"`/`"deny"`).
> Timeout in the nono profile (`timeout_secs`) causes nono itself to deny if the backend doesn't answer — the server never needs to model a "pending" state.

---

## 3. Architecture

```
 Developer workstation / CI agent (macOS or Linux)
 ┌──────────────────────────────────────────┐
 │  nono sandbox                            │
 │   agent (Claude Code)                    │
 │        │ exec kubectl / outbound HTTP     │
 │        ▼                                 │
 │  nono enforcement (PEP)                  │
 │        │ POST /approve (approval tier)   │
 └────────┼─────────────────────────────────┘
          │  HTTP or HTTPS
          │  (localhost:8765 port-forward,
          │   or direct in-cluster Service)
          ▼
 ┌────────────────────────────────────────────────────────────────────┐
 │                    kyverno-nono server                             │
 │                                                                    │
 │  POST /approve                                                     │
 │   ┌───────────────────────────────────────────────────────────┐   │
 │   │  nonoAuthorizer.ServeHTTP                                 │   │
 │   │   1. decode nono envelope → nono.CheckRequest             │   │
 │   │   2. apply inputProgram (optional CEL transform)          │   │
 │   │   3. engine.Handle(ctx, dynClient, &req)                  │   │
 │   │                                                           │   │
 │   │  core.Engine (kyverno/sdk):                               │   │
 │   │   Sequential dispatcher → first non-nil result wins       │   │
 │   │   For each ValidatingPolicy (mode=Nono):                  │   │
 │   │    a. matchConditions: all must be true or skip policy    │   │
 │   │    b. exceptions: any matching exception → skip policy    │   │
 │   │    c. validations: first non-null CheckResponse wins      │   │
 │   │    d. failurePolicy=Fail (default) → error = deny         │   │
 │   │                                                           │   │
 │   │  result == nil → DENY "no policy granted this request"    │   │  ← fail-closed
 │   │  result.Granted  → ALLOW                                  │   │
 │   │  result.Denied   → DENY + reason                          │   │
 │   │                                                           │   │
 │   │   4. apply outputProgram → {"decision":"granted"|"denied"}│   │
 │   └───────────────────────────────────────────────────────────┘   │
 │                                                                    │
 │  GET /livez, GET /readyz                                           │
 │  :9082/metrics  (Prometheus)                                       │
 │                                                                    │
 │  Sources:              Events (fan-out):                           │
 │   kube CRD watch        stdout writer (always on)                  │
 │   (ValidatingPolicy +   k8s Events (--events-enabled)             │
 │    PolicyException,     OpenReports CR (--openreports-enabled)    │
 │    mode=Nono)           Prometheus metrics                        │
 │   OCI/filesystem                                                   │
 │   bundle (no cluster)                                              │
 └────────────────────────────────────────────────────────────────────┘
          │ watch CRDs
          ▼
 Kubernetes cluster
  ValidatingPolicy (mode=Nono)   ← policy authors write these
  PolicyException (mode=Nono)    ← break-glass / trusted sessions
  Report CR (openreports)        ← audit trail per-pod
```

---

## 4. CEL Type Library: `nono`

The nono request is parsed into a Go struct and registered as a CEL native type — identical pattern to `pkg/cel/libs/authz/http/types.go` in kyverno-authz.

### 4.1 Go types (new: `pkg/cel/libs/authz/nono/types.go`)

```go
// CheckRequest is the nono approval envelope, exposed as `object` in CEL.
type CheckRequest struct {
    Backend    string          `json:"backend"    cel:"backend"`
    Capability CapabilityType  `json:"capability" cel:"capability"` // pre-parsed union
    Raw        map[string]any  `json:"raw"        cel:"raw"`        // forward-compat
}

// CapabilityType is always safe to access (value, not pointer).
// Command fields are zero-valued for endpoint requests and vice-versa.
type CapabilityType struct {
    Type    string          `cel:"type"`     // "command" | "endpoint"
    ID      string          `cel:"id"`       // request_id
    Session string          `cel:"session"`  // session_id
    Pid     int64           `cel:"pid"`      // child_pid
    Command CommandData     `cel:"command"`  // populated when type=="command"
    Endpoint EndpointData   `cel:"endpoint"` // populated when type=="endpoint"
}

type CommandData struct {
    Name          string   `cel:"name"`           // "kubectl"
    Caller        string   `cel:"caller"`          // "claude"
    Args          []string `cel:"args"`            // full argv including args[0]
    InterceptRule string   `cel:"intercept_rule"`
}

type EndpointData struct {
    Method    string `cel:"method"`
    Path      string `cel:"path"`
    RouteID   string `cel:"route_id"`
    Upstream  string `cel:"upstream"`
    RuleLabel string `cel:"rule_label"`
}

// CheckResponse is what a policy validation expression must return (or null).
type CheckResponse struct {
    Granted *CheckResponseGranted `cel:"granted,omitempty"`
    Denied  *CheckResponseDenied  `cel:"denied,omitempty"`
}
type CheckResponseGranted struct{}
type CheckResponseDenied struct{ Reason string `cel:"reason"` }
```

### 4.2 CEL functions (new: `pkg/cel/libs/authz/nono/lib.go`)

```
nono.Grant()             → CheckResponse{Granted: ...}
nono.Deny("reason")      → CheckResponse{Denied: {Reason: "reason"}}
nono.Grant().Response()  → *CheckResponse  (used in validation expressions)
nono.Deny("r").Response()→ *CheckResponse

// Command helpers
object.capability.command.Argv()           → args[1:]  (drops argv[0] shim path)
object.capability.command.HasArg("delete") → bool

// Endpoint helpers  
object.capability.endpoint.PathMatches("/apis/apps/**") → bool  (reuses k8s URL lib)
```

All K8s CEL extension libraries (regex, IP/CIDR, URLs, semver, json, jwt) are available — same base env as kyverno-authz.

### 4.3 New evaluation mode constant (new in kyverno-authz or local override)

```go
// pkg/cel/libs/authz/nono/constants.go
const EvaluationModeNono vpol.EvaluationMode = "Nono"
```

---

## 5. Policy CRD Design

**Reuses `policies.kyverno.io/v1 ValidatingPolicy` exactly** — same CRD, new `spec.evaluation.mode: Nono`. No new CRD schema changes needed.

### 5.1 Example: command approval policy

```yaml
apiVersion: policies.kyverno.io/v1
kind: ValidatingPolicy
metadata:
  name: staging-kubectl-approvals
  namespace: kyverno-nono
spec:
  evaluation:
    mode: Nono
  failurePolicy: Fail          # default; errors → deny
  matchConditions:
  - name: is-command
    expression: "object.capability.type == 'command'"
  variables:
  - name: argv
    expression: "object.capability.command.Argv()"  # drops shim path at args[0]
  validations:
  # Hard deny: namespace deletion blocked outright
  - expression: >
      size(variables.argv) >= 2
        && variables.argv[0] == 'delete'
        && variables.argv[1] in ['namespace', 'namespaces', 'ns']
        ? nono.Deny("namespace deletion is blocked at all times").Response()
        : null
  # Grant: safe read-only commands from claude
  - expression: >
      object.capability.command.name == 'kubectl'
        && object.capability.command.caller == 'claude'
        && size(variables.argv) > 0
        && variables.argv[0] in ['get', 'describe', 'config', 'version']
        ? nono.Grant().Response()
        : null
  # Deny everything else (reached only if no grant above matched)
  - expression: >
      nono.Deny("command not in approved list: " + object.capability.command.name
                + " " + variables.argv.join(" ")).Response()
```

### 5.2 Example: endpoint approval policy

```yaml
apiVersion: policies.kyverno.io/v1
kind: ValidatingPolicy
metadata:
  name: staging-k8s-api-approvals
  namespace: kyverno-nono
spec:
  evaluation:
    mode: Nono
  matchConditions:
  - name: is-endpoint
    expression: "object.capability.type == 'endpoint'"
  validations:
  # Hard deny: any DELETE on namespaces
  - expression: >
      object.capability.endpoint.method == 'DELETE'
        && object.capability.endpoint.path.startsWith('/api/v1/namespaces/')
        ? nono.Deny("namespace deletion denied at API layer").Response()
        : null
  # Grant: reads and targeted scale PATCH
  - expression: >
      object.capability.endpoint.method in ['GET', 'HEAD']
        ? nono.Grant().Response()
        : null
  - expression: >
      object.capability.endpoint.method == 'PATCH'
        && object.capability.endpoint.PathMatches('/apis/apps/v1/namespaces/*/deployments/*/scale')
        ? nono.Grant().Response()
        : null
  - expression: >
      nono.Deny("endpoint not permitted: "
                + object.capability.endpoint.method + " "
                + object.capability.endpoint.path).Response()
```

---

## 6. PolicyException Design

**Reuses `policies.kyverno.io/v1 PolicyException`** — same CRD, new `spec.evaluationMode: Nono`.

### 6.1 Exception semantics

A matching exception causes the associated policy to produce **no result** (same as kyverno-authz). Under fail-closed semantics: an exception to a deny-producing policy only helps if another policy produces a grant. Policy authors should pair exceptions with an explicit grant policy (recommended) or rely on the default-deny producing a clear audit record.

```yaml
apiVersion: policies.kyverno.io/v1
kind: PolicyException
metadata:
  name: break-glass-incident-4711
  namespace: kyverno-nono
spec:
  evaluationMode: Nono
  policyRefs:
  - name: staging-kubectl-approvals
    kind: ValidatingPolicy
  matchConditions:
  - name: incident-session
    expression: "object.capability.session == 'incident-4711'"
```

```yaml
# Exception for a trusted pipeline SA during deployment windows
apiVersion: policies.kyverno.io/v1
kind: PolicyException
metadata:
  name: ci-pipeline-trusted
  namespace: kyverno-nono
spec:
  evaluationMode: Nono
  policyRefs:
  - name: staging-kubectl-approvals
    kind: ValidatingPolicy
  matchConditions:
  - name: ci-caller
    expression: "object.capability.command.caller == 'ci-deploy-bot'"
  - name: scale-only
    expression: "object.capability.command.Argv()[0] == 'scale'"
```

---

## 7. Server Design

### 7.1 New binary: `cmd/kyverno-nono/`

Follows the same structure as `cmd/cleanup-controller/` — the leanest existing binary template.

```
cmd/kyverno-nono/
  main.go          # cobra root → serve subcommand
  server.go        # HTTP mux, TLS, /approve handler wiring
  handlers/
    approve.go     # nonoAuthorizer implements http.Handler
```

### 7.2 HTTP surface

| Route | Behavior |
|---|---|
| `POST /approve` | Parse nono envelope; respond `{"decision":"granted"}` or `{"decision":"denied","reason":"..."}` always as HTTP 200. Malformed JSON → HTTP 400 + denied body (mirrors demo webhook behavior). Engine error + `failurePolicy=Fail` → HTTP 200 + denied with reason (not 500 — keeps nono's timeout/deny semantics clean). |
| `GET /livez` | Always 200 |
| `GET /readyz` | 200 once policy source is ready; 503 if no policies loaded |
| `:9082 GET /metrics` | Prometheus |

### 7.3 Fail-closed rules

1. No policy produces a result → **denied** `"no policy granted this request"` ← **inverts kyverno-authz default-allow**
2. Engine/CEL error with `failurePolicy: Fail` (default) → denied with error message
3. Malformed JSON body → HTTP 400 + denied
4. Unknown `capability_type` → evaluated normally against policies; falls through to deny
5. nono's `timeout_secs` (client side) provides fail-closed on server unavailability

### 7.4 Compile and run flow

```go
// Identical structure to cmd/cli/kubectl-kyverno/processor/authz_processor.go
// but using nono types instead of httpcel types.

compiler := authzcompiler.NewCompiler[dynamic.Interface, *nono.CheckRequest, *nono.CheckResponse](dynClient)
compiled, errs := compiler.Compile(vpol, nil)

eng := core.NewEngine(
    core.MakeSource(compiled),
    handlers.Handler(
        dispatchers.Sequential(
            sdkpolicy.EvaluatorFactory[nonoengine.NonoPolicy](),
            breaker: out.Result != nil,
        ),
        resulters.NewFirst(...),
    ),
)

evaluation := eng.Handle(ctx, dynClient, &req)
// result == nil → deny (fail-closed, unlike authz server)
```

---

## 8. Reporting and Audit

Copied wholesale from kyverno-authz `pkg/events/`:

| Channel | Enabled by | Detail |
|---|---|---|
| **stdout** | always | One JSON line per decision: `{time, request_id, session_id, capability_type, subject, decision, policy, reason, latency_ms}` |
| **K8s Events** | `--events-enabled` | One Event per decision on the server's Pod; `reason: NonoApprovalGranted` / `NonoApprovalDenied` |
| **OpenReports CR** | `--openreports-enabled` | Buffered ring (`--result-buffer-size`, default 500), flushed on `--report-flush-interval` (default 30s) into a `reports.openreports.io/v1alpha1 Report` named `nono-approvals-<xxhash(POD_NAME)>`. Result: granted→`pass`, denied→`fail`, error→`error`. Scope: synthesized `ObjectReference{kind:NonoSession, name:session_id}`. |
| **Prometheus** | always | `nono_approval_decisions_total{decision,source,capability_type}` + `nono_approval_duration_seconds` histogram |

---

## 9. Deployment Model

### 9.1 In-cluster Deployment (primary)

```
Kubernetes cluster
  Namespace: kyverno-nono
    Deployment: kyverno-nono-server
      - mounts TLS cert (cert-manager)
      - watches ValidatingPolicy/PolicyException (mode=Nono)
    Service: kyverno-nono (ClusterIP, port 8765)
    ClusterRole: can list/watch ValidatingPolicy, PolicyException
    ServiceAccount: kyverno-nono

Developer laptop:
  kubectl port-forward svc/kyverno-nono 8765:8765 -n kyverno-nono
  → nono profile: approval_backends.kyverno = {url: "http://127.0.0.1:8765/approve", timeout_secs: 10}
```

### 9.2 Standalone (dev laptop, no cluster)

```
kyverno-nono serve \
  --external-policy-source policies.yaml \
  --port 8765 \
  --fail-closed=true
```
Policies loaded from filesystem or OCI image; audit to stdout only. Identical binary, kube features degrade gracefully.

### 9.3 Helm chart

New chart `charts/kyverno-nono/` modeled on `charts/kyverno-authz-server` (drop Envoy bits).

---

## 10. CLI Integration (bonus — kyverno test)

The existing `kubectl kyverno test` framework already evaluates `ValidatingPolicy` against payloads via `authz_processor.go`. kyverno-nono adds a `--nono-payloads` flag and a `Nono` resource kind in test manifests, enabling offline testing:

```yaml
# test/cli/test-nono-approvals/kyverno-test.yaml
apiVersion: cli.kyverno.io/v1alpha1
kind: Test
metadata:
  name: test-nono-approvals
policies:
- policy.yaml
nono:
- name: scale-deployment
  file: payloads/scale.json    # the nono POST body
  result: granted
- name: delete-namespace
  file: payloads/delete-ns.json
  result: denied
```

---

## 11. Implementation Plan

### Phase 1 — Core server (2–3 weeks)

| Task | Files | Notes |
|---|---|---|
| nono CEL type library | `pkg/cel/libs/authz/nono/types.go`, `lib.go`, `impl.go` | Copy `pkg/cel/libs/authz/http/` structure; new Go types for nono wire protocol |
| nono compiler wrapper | `pkg/engine/compiler/` — add `EvaluationModeNono` branch | Minimal change to existing compiler; add nono type registration to env |
| nono authorizer | `cmd/kyverno-nono/handlers/approve.go` | Fail-closed (invert default-allow) |
| Binary entry point | `cmd/kyverno-nono/main.go`, `server.go` | Cobra CLI; reuse `cmd/internal/` setup |
| Events/metrics | Reuse kyverno-authz `pkg/events/` | Add nono case to `ResultAccessor` type switch |
| Basic unit tests | `pkg/cel/libs/authz/nono/*_test.go` | Table-driven; test grant/deny/fail-closed/malformed |

### Phase 2 — Reporting + policy source (1–2 weeks)

| Task | Files | Notes |
|---|---|---|
| Kube policy source | reuse kyverno-authz `pkg/engine/sources/kube.go` | field-selector `mode=Nono` |
| OpenReports integration | reuse kyverno-authz `pkg/events/openreports.go` | synthetic ObjectReference for session |
| Helm chart | `charts/kyverno-nono/` | Port-forward + Service + RBAC |
| Readyz probe tied to policy load | `cmd/kyverno-nono/server.go` | |

### Phase 3 — CLI integration + conformance tests (1–2 weeks)

| Task | Files | Notes |
|---|---|---|
| `kubectl kyverno test` nono mode | `cmd/cli/kubectl-kyverno/processor/authz_processor.go` | Add `ApplyNonoPolicies` |
| CLI `--nono-payloads` flag | `cmd/cli/kubectl-kyverno/commands/test/` | |
| Conformance test suite | `test/conformance/chainsaw/nono-approvals/` | E2E with mock nono client |
| CLI test fixtures | `test/cli/test-nono-approvals/` | Offline policy test |

### Phase 4 — Hardening (1 week)

| Task | Notes |
|---|---|
| mTLS between nono and server | cert-manager integration; `--ca-cert` flag |
| `failOpen` toggle | `--fail-closed=false` for shadow/audit-only mode |
| OCI policy bundle support | reuse kyverno-authz external source |
| Docs | `docs/dev/kyverno-nono/` |

---

## 12. Key Design Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Reuse `ValidatingPolicy` CRD | Yes | No new CRD; policy authors use familiar structure; CEL tooling works immediately |
| New `EvaluationMode: Nono` | Yes | Field-selectors allow the server to watch only its own policies; no cross-contamination with Envoy/HTTP modes |
| Fail-closed default | Yes | Inverts kyverno-authz default-allow; matches nono's own fail-closed semantics |
| Response wire values | `granted` / `denied` | Matches verified nono wire contract (not `allow`/`deny`) |
| Single `object.capability` union struct | Yes | CEL is always safe (no nil panics); simplifies matchConditions |
| Exceptions via CEL matchConditions | Yes | Reuses existing `PolicyException` machinery from kyverno-authz; break-glass controlled via K8s RBAC |
| Human-in-loop / async approvals | **Out of scope** | K8s admission timeout model doesn't apply; nono's `timeout_secs` is the deadline; Phase 3+ if needed |
| No new CRDs for ApprovalRequest | Yes | Avoids code generation cycle; OpenReports covers audit |

---

## 13. Files to Create / Modify

### New files
```
cmd/kyverno-nono/
  main.go
  server.go
  handlers/approve.go

pkg/cel/libs/authz/nono/
  types.go       # CheckRequest, CheckResponse, CommandData, EndpointData
  lib.go         # nono.Grant(), nono.Deny(), helper funcs
  impl.go        # CEL native type implementations
  constants.go   # EvaluationModeNono

charts/kyverno-nono/
  Chart.yaml, values.yaml, templates/...

test/cli/test-nono-approvals/
  kyverno-test.yaml
  policy.yaml
  payloads/scale.json, delete-ns.json, endpoint-patch.json

test/conformance/chainsaw/nono-approvals/
  (chainsaw E2E test)

docs/dev/kyverno-nono/
  DESIGN.md   ← this file
```

### Modified files
```
cmd/cli/kubectl-kyverno/processor/authz_processor.go  # add ApplyNonoPolicies
cmd/cli/kubectl-kyverno/commands/test/test.go         # --nono-payloads flag
Makefile                                               # build-nono-server target
```

> **No changes to the Kyverno admission controller, engine, or any existing webhook paths.**

---

## 14. Open Questions / Assumptions

| # | Question | Assumption |
|---|---|---|
| 1 | Does nono accept `"allow"` as synonym for `"granted"`? | No — use `"granted"/"denied"` (verified from `approval-webhook-demo.py`) |
| 2 | Is `capability_type: "admission"` a real nono type? | Not found in any public source; design accepts unknown types (fail-closed) |
| 3 | Should `EvaluationModeNono` live in kyverno-authz (upstream) or be local? | Local first (`pkg/cel/libs/authz/nono/constants.go`); propose upstream PR once stable |
| 4 | Authentication between nono and the server? | Phase 4 mTLS; Phase 1 assumes localhost port-forward (same trust model as demo) |
| 5 | Multi-tenant (multiple agent sessions to one server)? | Supported naturally — `session_id` available in CEL for tenant isolation |
| 6 | Human-in-loop approvals? | Out of scope — K8s admission timeout model doesn't apply here; nono's `timeout_secs` is the hard deadline |

---

## 15. References

- [kyverno-authz](https://github.com/kyverno/kyverno-authz) — architecture model
- [kyverno/sdk](https://github.com/kyverno/sdk) — generic policy engine
- [kyverno/api](https://github.com/kyverno/api) — `ValidatingPolicy`, `PolicyException` CRDs
- [nolabs-ai/tool-sandbox-examples](https://github.com/nolabs-ai/tool-sandbox-examples/tree/main/kubernetes) — nono wire contract + deployment model
- [colangelo/nono-cedar-pdp](https://github.com/colangelo/nono-cedar-pdp) — Cedar PDP reference implementation
- [`cmd/cli/kubectl-kyverno/processor/authz_processor.go`](../../cmd/cli/kubectl-kyverno/processor/authz_processor.go) — existing SDK wiring pattern in this repo
- [`pkg/cel/libs/authz/http/types.go`](../../../pkg/cel/libs/authz/http/types.go) — type library pattern to copy (via kyverno-authz module)
