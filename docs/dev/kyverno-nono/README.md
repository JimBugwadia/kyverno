# kyverno-nono

A Kyverno approval server for [nono.sh](https://github.com/nolabs-ai/tool-sandbox-examples/tree/main/kubernetes) — the kernel-enforced AI agent sandbox.

When an agent running inside a nono sandbox attempts to execute a command or make an HTTP request, nono can be configured to forward an approval request to this server. Decisions are evaluated using Kyverno CEL policies (`ValidatingPolicy` with `evaluation.mode: Nono`). The server is **fail-closed**: a request with no matching policy is denied.

---

## Table of Contents

- [How it works](#how-it-works)
- [Quick start](#quick-start)
- [Policy reference](#policy-reference)
- [Sample policies](#sample-policies)
  - [Allow read-only kubectl](#allow-read-only-kubectl)
  - [Block dangerous commands](#block-dangerous-commands)
  - [Allow specific callers](#allow-specific-callers)
  - [Restrict HTTP methods (endpoint)](#restrict-http-methods-endpoint)
  - [Allowlist internal upstreams](#allowlist-internal-upstreams)
  - [Session-scoped exceptions](#session-scoped-exceptions)
  - [Variables and multi-rule policies](#variables-and-multi-rule-policies)
- [Testing with kubectl-kyverno](#testing-with-kubectl-kyverno)
- [Configuring nono](#configuring-nono)
- [Deployment](#deployment)

---

## How it works

```
 AI agent (e.g. Claude Code) inside nono sandbox
        │
        └─ executes: kubectl delete namespace production
                         │
               [nono invocation_policy → approval backend]
                         │
                         ▼
        POST http://localhost:8765/approve
        {
          "backend": "kyverno",
          "request": {
            "capability_type": "command",
            "request_id":      "req-abc123",
            "session_id":      "session-xyz",
            "child_pid":       1234,
            "command":         "kubectl",
            "caller":          "claude",
            "args":            ["kubectl", "delete", "namespace", "production"],
            "intercept_rule":  "kubectl"
          }
        }

        ← {"decision": "denied", "reason": "kubectl delete is not allowed"}
```

HTTP endpoint interception works the same way with `capability_type: "endpoint"`:

```json
{
  "backend": "kyverno",
  "request": {
    "capability_type": "endpoint",
    "request_id":      "req-def456",
    "session_id":      "session-xyz",
    "method":          "DELETE",
    "path":            "/api/v1/namespaces/production",
    "upstream":        "https://kube-apiserver:6443",
    "rule_label":      "endpoint_policy.approve[DELETE /api/**]"
  }
}
```

---

## Quick start

### Run the server (no Kubernetes)

```bash
# Build
make build-nono-server

# Run against local policy files (no cluster needed)
./cmd/kyverno-nono/kyverno-nono serve \
  --address=:8765 \
  --no-kube-policy-source \
  --policy-paths=./my-policies/
```

### Run in-cluster

```bash
# Deploy — watches ValidatingPolicy resources with evaluation.mode=Nono
./cmd/kyverno-nono/kyverno-nono serve --address=:8765
```

### Configure nono to call kyverno-nono

In your nono profile (`.nono/profile.toml` or equivalent):

```toml
[approval_backend]
url         = "http://localhost:8765/approve"
timeout_secs = 5        # nono denies automatically on timeout (fail-closed)
```

---

## Policy reference

### CRD

```yaml
apiVersion: policies.kyverno.io/v1
kind: ValidatingPolicy
metadata:
  name: my-nono-policy
spec:
  evaluation:
    mode: Nono          # required — routes to the nono approval engine
  failurePolicy: Fail   # Fail (deny on compile/eval error) or Ignore (allow on error)
  variables:            # optional — precomputed values available as variables.*
    - name: myVar
      expression: "object.request.command"
  validations:
    - expression: "..."   # must return nono.Grant() or nono.Deny('reason')
      message: "..."      # used in audit logs and PolicyReports
```

### CEL object model

Every policy expression receives a single `object` variable representing the nono approval request.

#### `object` (CheckRequest)

| Field | Type | Description |
|---|---|---|
| `object.backend` | `string` | Backend name configured in the nono profile |
| `object.request` | `RequestData` | The capability-specific request data (see below) |

#### `object.request` (RequestData) — common fields

| Field | Type | Description |
|---|---|---|
| `object.request.capability_type` | `string` | `"command"` or `"endpoint"` |
| `object.request.request_id` | `string` | Unique request identifier |
| `object.request.session_id` | `string` | Agent session identifier |
| `object.request.child_pid` | `int` | Child process PID (command only) |

#### `object.request` — command fields (`capability_type == "command"`)

| Field | Type | Description |
|---|---|---|
| `object.request.command` | `string` | Binary name, e.g. `"kubectl"` |
| `object.request.caller` | `string` | Calling agent name, e.g. `"claude"` |
| `object.request.args` | `list(string)` | Raw args including the shim path at `[0]` |
| `object.request.argv()` | `list(string)` | Args without `[0]` — the actual argv passed to the command |
| `object.request.intercept_rule` | `string` | Name of the nono rule that triggered the request |

#### `object.request` — endpoint fields (`capability_type == "endpoint"`)

| Field | Type | Description |
|---|---|---|
| `object.request.method` | `string` | HTTP method, e.g. `"GET"`, `"DELETE"` |
| `object.request.path` | `string` | Request path, e.g. `"/api/v1/namespaces/prod"` |
| `object.request.route_id` | `string` | nono route identifier |
| `object.request.upstream` | `string` | Upstream base URL, e.g. `"https://kube-apiserver:6443"` |
| `object.request.rule_label` | `string` | Full rule label from the nono profile |

### CEL functions

| Function | Returns | Description |
|---|---|---|
| `nono.Grant()` | `CheckResponseGranted` | Allow the request |
| `nono.Deny("reason")` | `CheckResponseDenied` | Deny with a human-readable reason |
| `object.request.argv()` | `list(string)` | `args[1:]` — strips the nono shim path at index 0 |

> **Note:** A policy `expression` must evaluate to either `nono.Grant()` or `nono.Deny(...)`. Any other return value (including `null`) is treated as "no decision" — the engine moves to the next policy. If no policy produces a decision the server denies (fail-closed).

---

## Sample policies

### Allow read-only kubectl

Permit `kubectl` only with read-only subcommands. Deny everything else.

```yaml
apiVersion: policies.kyverno.io/v1
kind: ValidatingPolicy
metadata:
  name: nono-kubectl-readonly
spec:
  evaluation:
    mode: Nono
  failurePolicy: Fail
  variables:
    - name: readOnlyVerbs
      expression: "['get', 'list', 'describe', 'logs', 'top', 'explain', 'version']"
  validations:
    - expression: >
        object.request.capability_type != "command" ||
        object.request.command != "kubectl"
        ? nono.Grant()
        : variables.readOnlyVerbs.exists(v, object.request.argv().exists(a, a == v))
          ? nono.Grant()
          : nono.Deny(
              "kubectl is restricted to read-only subcommands: " +
              variables.readOnlyVerbs.join(", ")
            )
      message: "kubectl write operations are not allowed"
```

**Allows:**
- `kubectl get pods`
- `kubectl describe deployment/web`
- `kubectl logs my-pod`

**Denies:**
- `kubectl delete namespace production`
- `kubectl scale deployment/web --replicas=0`
- `kubectl apply -f malicious.yaml`

---

### Block dangerous commands

Deny a list of high-risk binaries outright; allow everything else.

```yaml
apiVersion: policies.kyverno.io/v1
kind: ValidatingPolicy
metadata:
  name: nono-block-dangerous-commands
spec:
  evaluation:
    mode: Nono
  failurePolicy: Fail
  variables:
    - name: blocked
      expression: >
        ['rm', 'dd', 'mkfs', 'shred', 'sudo', 'su', 'chmod', 'chown',
         'iptables', 'ip', 'nc', 'ncat', 'socat', 'tcpdump', 'strace']
  validations:
    - expression: >
        object.request.capability_type != "command"
        ? nono.Grant()
        : variables.blocked.exists(b, b == object.request.command)
          ? nono.Deny("'" + object.request.command + "' is not permitted")
          : nono.Grant()
      message: "command blocked by policy"
```

---

### Allow specific callers

Only permit the `claude` agent to run commands. Block other callers (e.g. scripts running inside the sandbox).

```yaml
apiVersion: policies.kyverno.io/v1
kind: ValidatingPolicy
metadata:
  name: nono-trusted-callers-only
spec:
  evaluation:
    mode: Nono
  failurePolicy: Fail
  variables:
    - name: trustedCallers
      expression: "['claude', 'gemini']"
  validations:
    - expression: >
        object.request.capability_type != "command"
        ? nono.Grant()
        : variables.trustedCallers.exists(c, c == object.request.caller)
          ? nono.Grant()
          : nono.Deny(
              "caller '" + object.request.caller + "' is not in the trusted list"
            )
      message: "untrusted caller"
```

---

### Restrict HTTP methods (endpoint)

For endpoint requests, allow GET/HEAD/OPTIONS but deny mutating methods.

```yaml
apiVersion: policies.kyverno.io/v1
kind: ValidatingPolicy
metadata:
  name: nono-endpoint-readonly
spec:
  evaluation:
    mode: Nono
  failurePolicy: Fail
  variables:
    - name: readOnlyMethods
      expression: "['GET', 'HEAD', 'OPTIONS']"
  validations:
    - expression: >
        object.request.capability_type != "endpoint"
        ? nono.Grant()
        : variables.readOnlyMethods.exists(m, m == object.request.method)
          ? nono.Grant()
          : nono.Deny(
              "HTTP " + object.request.method + " is not allowed; " +
              "permitted methods: " + variables.readOnlyMethods.join(", ")
            )
      message: "mutating HTTP methods are not allowed"
```

---

### Allowlist internal upstreams

Only allow endpoint requests to known internal services. Block all external upstreams.

```yaml
apiVersion: policies.kyverno.io/v1
kind: ValidatingPolicy
metadata:
  name: nono-internal-upstreams-only
spec:
  evaluation:
    mode: Nono
  failurePolicy: Fail
  variables:
    - name: allowedUpstreams
      expression: >
        ['https://kube-apiserver:6443',
         'http://metrics.monitoring.svc',
         'http://logging.logging.svc',
         'http://internal-api.default.svc']
  validations:
    - expression: >
        object.request.capability_type != "endpoint"
        ? nono.Grant()
        : variables.allowedUpstreams.exists(u, object.request.upstream.startsWith(u))
          ? nono.Grant()
          : nono.Deny(
              "upstream '" + object.request.upstream +
              "' is not in the allowlist"
            )
      message: "requests to external upstreams are not allowed"
```

---

### Session-scoped exceptions

Grant a specific session (`break-glass` scenario) full access for a limited time window. All other sessions still go through the normal rules.

```yaml
apiVersion: policies.kyverno.io/v1
kind: ValidatingPolicy
metadata:
  name: nono-break-glass
spec:
  evaluation:
    mode: Nono
  failurePolicy: Ignore   # if this policy errors, fall through to other policies
  validations:
    - expression: >
        object.request.session_id == "breakglass-session-2026-08-02"
        ? nono.Grant()
        : nono.Deny("not a break-glass session")
      message: "break-glass exception"
---
# Combine with a separate restrictive policy to form a deny-by-default system:
#
# Policy evaluation order (first match wins — fail-closed if no match):
#   1. nono-break-glass  →  Grant if session matches
#   2. nono-kubectl-readonly  →  Grant read-only kubectl, deny write kubectl
#   3. nono-block-dangerous-commands  →  Deny blocked binaries
#   4. (no match)  →  server denies automatically
```

---

### Variables and multi-rule policies

Use `variables` for reusable sub-expressions, and multiple `validations` to express layered logic.

```yaml
apiVersion: policies.kyverno.io/v1
kind: ValidatingPolicy
metadata:
  name: nono-layered-policy
spec:
  evaluation:
    mode: Nono
  failurePolicy: Fail
  variables:
    - name: isCommand
      expression: "object.request.capability_type == 'command'"
    - name: isEndpoint
      expression: "object.request.capability_type == 'endpoint'"
    - name: argv
      expression: "object.request.argv()"
    - name: isMutatingKubectl
      expression: >
        variables.isCommand &&
        object.request.command == "kubectl" &&
        ['apply', 'delete', 'scale', 'patch', 'edit',
         'create', 'replace', 'rollout'].exists(v,
           variables.argv.exists(a, a == v))
    - name: isProductionPath
      expression: >
        variables.isEndpoint &&
        (object.request.path.contains('/namespaces/production') ||
         object.request.path.contains('/namespaces/prod'))

  validations:
    # Rule 1: block all kubectl mutations targeting production
    - expression: >
        variables.isMutatingKubectl &&
        variables.argv.exists(a, a.contains('production') || a.contains('/prod'))
        ? nono.Deny("kubectl mutations in production are not allowed")
        : nono.Grant()
      message: "production kubectl mutation blocked"

    # Rule 2: block HTTP mutations to production namespace paths
    - expression: >
        variables.isProductionPath &&
        !['GET', 'HEAD', 'OPTIONS'].exists(m, m == object.request.method)
        ? nono.Deny(
            "HTTP " + object.request.method +
            " to production path '" + object.request.path + "' is not allowed"
          )
        : nono.Grant()
      message: "production HTTP mutation blocked"
```

---

## Testing with kubectl-kyverno

Policies can be tested offline without running the server, using `kubectl-kyverno apply` or `kubectl-kyverno test`.

### Apply a policy against a payload

```bash
# Allow: kubectl get pods
kubectl-kyverno apply nono-kubectl-readonly.yaml \
  --nono-payload payloads/kubectl-get-pods.json

# Deny: kubectl delete namespace production
kubectl-kyverno apply nono-kubectl-readonly.yaml \
  --nono-payload payloads/kubectl-delete-ns.json
```

### Write a test suite

**`kyverno-test.yaml`**:
```yaml
name: kubectl-readonly-tests
policies:
  - nono-kubectl-readonly.yaml
tests:
  - name: allow-get-pods
    policy: nono-kubectl-readonly
    payload: payloads/kubectl-get-pods.json
    result: pass
  - name: deny-delete-namespace
    policy: nono-kubectl-readonly
    payload: payloads/kubectl-delete-ns.json
    result: fail
  - name: deny-apply
    policy: nono-kubectl-readonly
    payload: payloads/kubectl-apply.json
    result: fail
```

**`payloads/kubectl-get-pods.json`**:
```json
{
  "backend": "kyverno",
  "request": {
    "capability_type": "command",
    "request_id": "req-001",
    "session_id": "test-session",
    "child_pid": 1234,
    "command": "kubectl",
    "caller": "claude",
    "args": ["/usr/local/bin/nono-shim", "get", "pods"],
    "intercept_rule": "kubectl"
  }
}
```

**`payloads/kubectl-delete-ns.json`**:
```json
{
  "backend": "kyverno",
  "request": {
    "capability_type": "command",
    "request_id": "req-002",
    "session_id": "test-session",
    "child_pid": 1235,
    "command": "kubectl",
    "caller": "claude",
    "args": ["/usr/local/bin/nono-shim", "delete", "namespace", "production"],
    "intercept_rule": "kubectl"
  }
}
```

**Run the test suite:**
```bash
kubectl-kyverno test .
```

**Endpoint payload example** (`payloads/delete-production-ns.json`):
```json
{
  "backend": "kyverno",
  "request": {
    "capability_type": "endpoint",
    "request_id": "req-003",
    "session_id": "test-session",
    "method": "DELETE",
    "path": "/api/v1/namespaces/production",
    "upstream": "https://kube-apiserver:6443",
    "rule_label": "endpoint_policy.approve[DELETE /api/**]"
  }
}
```

---

## Configuring nono

Point nono at the kyverno-nono approval backend in your agent profile:

```toml
# .nono/profile.toml

[approval_backend]
url          = "http://localhost:8765/approve"
timeout_secs = 5

[[invocation_policy]]
name    = "kubectl"
command = "kubectl"
action  = "approve"       # send to approval backend

[[invocation_policy]]
name    = "helm"
command = "helm"
action  = "approve"

[[endpoint_policy]]
name   = "kubernetes-api"
routes = ["https://kube-apiserver:6443/**"]
action = "approve"
```

---

## Deployment

### Flags

| Flag | Default | Description |
|---|---|---|
| `--address` | `:8765` | Listen address for `POST /approve` |
| `--probes-address` | `:8766` | Liveness/readiness probe address |
| `--metrics-address` | `:8767` | Prometheus metrics address |
| `--cert-file` | `` | TLS certificate file (enables HTTPS) |
| `--key-file` | `` | TLS key file |
| `--no-kube-policy-source` | `false` | Disable watching K8s for policies (use `--policy-paths` instead) |
| `--policy-paths` | `` | Comma-separated OCI or file paths to load policies from |
| `--enable-events` | `false` | Emit Kubernetes Events for each decision |

### Kubernetes deployment (in-cluster)

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kyverno-nono
  namespace: kyverno
spec:
  replicas: 1
  selector:
    matchLabels:
      app: kyverno-nono
  template:
    metadata:
      labels:
        app: kyverno-nono
    spec:
      containers:
        - name: kyverno-nono
          image: ghcr.io/kyverno/kyverno-nono:latest
          args:
            - serve
            - --address=:8765
            - --enable-events=true
          ports:
            - containerPort: 8765
            - containerPort: 8766  # probes
            - containerPort: 8767  # metrics
          livenessProbe:
            httpGet:
              path: /healthz
              port: 8766
          readinessProbe:
            httpGet:
              path: /readyz
              port: 8766
```

Apply policies by creating `ValidatingPolicy` resources with `evaluation.mode: Nono` in the cluster — the server watches and hot-reloads them automatically.

---

## Architecture

```
nono sandbox
    │  POST /approve
    ▼
┌─────────────────────────────────────────────────┐
│  kyverno-nono server (:8765)                    │
│                                                 │
│  ParseRequest()  →  CheckRequest{               │
│      backend: "kyverno"                         │
│      request: RequestData{                      │
│          capability_type, command, args, ...    │
│      }                                          │
│  }                                              │
│       │                                         │
│       ▼                                         │
│  CEL engine evaluates ValidatingPolicies        │
│  (mode=Nono, field-selected from kube/OCI)      │
│       │                                         │
│       ├─ nono.Grant()  →  {"decision":"granted"}│
│       └─ nono.Deny(r)  →  {"decision":"denied", │
│                             "reason": r}        │
│       │                                         │
│  No match  →  deny (fail-closed)                │
│                                                 │
│  Side-effects: Prometheus metrics, K8s Events,  │
│  OpenReports PolicyReports                      │
└─────────────────────────────────────────────────┘
```
