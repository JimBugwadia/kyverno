package nono

import vpol "github.com/kyverno/api/api/policies.kyverno.io/v1"

// EvaluationModeNono is the evaluation mode identifier for kyverno-nono policies.
// It is used as a field-selector on ValidatingPolicy.spec.evaluation.mode so the
// nono server only watches its own policies.
const EvaluationModeNono vpol.EvaluationMode = "Nono"
