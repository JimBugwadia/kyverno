// Package compiler provides a Kyverno policy compiler for evaluation mode "Nono".
// It is modeled on the kyverno-authz compiler (pkg/engine/compiler/) but
// parameterised on nono.CheckRequest / nono.CheckResponse types.
package compiler

import (
	"context"
	"fmt"
	"reflect"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	v1 "github.com/kyverno/api/api/policies.kyverno.io/v1"
	authzcel "github.com/kyverno/kyverno-authz/pkg/cel"
	nonolib "github.com/kyverno/kyverno/pkg/cel/libs/authz/nono"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/cel/lazy"
	"k8s.io/client-go/dynamic"
	"k8s.io/klog/v2"
)

const (
	objectKey    = "object"
	variablesKey = "variables"
)

var reflectTypeForCheckResponse = reflect.TypeFor[*nonolib.CheckResponse]()

// Compiler compiles ValidatingPolicies for mode=Nono into CompiledPolicy values.
type Compiler struct {
	client dynamic.Interface
}

// NewCompiler returns a Compiler for nono mode policies.
func NewCompiler(client dynamic.Interface) *Compiler {
	return &Compiler{client: client}
}

// Compile builds an executable CompiledPolicy from a ValidatingPolicy and its exceptions.
func (c *Compiler) Compile(policy *v1.ValidatingPolicy, exceptions []*v1.PolicyException) (CompiledPolicy, field.ErrorList) {
	cp, errs := c.compile(policy, exceptions)
	if errs != nil {
		klog.Error("error compiling nono policy:", errs.ToAggregate().Error())
		return CompiledPolicy{}, errs
	}
	failurePolicy := admissionregistrationv1.FailurePolicyType(admissionregistrationv1.Fail)
	if policy.Spec.FailurePolicy != nil {
		failurePolicy = *policy.Spec.FailurePolicy
	}
	cp.failurePolicy = failurePolicy
	return *cp, nil
}

func (c *Compiler) compile(policy *v1.ValidatingPolicy, exceptions []*v1.PolicyException) (*CompiledPolicy, field.ErrorList) {
	var allErrs field.ErrorList

	// Start from the authz base env (k8s libs + standard CEL extensions).
	base, err := authzcel.NewBaseEnv()
	if err != nil {
		return nil, append(allErrs, field.InternalError(nil, err))
	}
	// Extend with the nono CEL type library.
	base, err = base.Extend(nonolib.Lib())
	if err != nil {
		return nil, append(allErrs, field.InternalError(nil, err))
	}

	// Register lazy variables provider.
	provider := authzcel.NewVariablesProvider(base.CELTypeProvider())
	env, err := base.Extend(
		cel.Variable(objectKey, nonolib.RequestType),
		cel.Variable(variablesKey, authzcel.VariablesType),
		cel.CustomTypeProvider(provider),
	)
	if err != nil {
		return nil, append(allErrs, field.InternalError(nil, err))
	}

	path := field.NewPath("spec")

	// Compile matchConditions.
	matchConditions := make([]cel.Program, 0, len(policy.Spec.MatchConditions))
	for i, mc := range policy.Spec.MatchConditions {
		epath := path.Child("matchConditions").Index(i).Child("expression")
		ast, issues := env.Compile(mc.Expression)
		if issues.Err() != nil {
			return nil, append(allErrs, field.Invalid(epath, mc.Expression, issues.Err().Error()))
		}
		if !ast.OutputType().IsExactType(types.BoolType) {
			return nil, append(allErrs, field.Invalid(epath, mc.Expression, "matchCondition must return bool"))
		}
		prog, err := env.Program(ast)
		if err != nil {
			return nil, append(allErrs, field.Invalid(epath, mc.Expression, err.Error()))
		}
		matchConditions = append(matchConditions, prog)
	}

	// Compile spec.variables.
	variables := map[string]cel.Program{}
	for i, variable := range policy.Spec.Variables {
		epath := path.Child("variables").Index(i).Child("expression")
		ast, issues := env.Compile(variable.Expression)
		if issues.Err() != nil {
			return nil, append(allErrs, field.Invalid(epath, variable.Expression, issues.Err().Error()))
		}
		provider.RegisterField(variable.Name, ast.OutputType())
		prog, err := env.Program(ast)
		if err != nil {
			return nil, append(allErrs, field.Invalid(epath, variable.Expression, err.Error()))
		}
		variables[variable.Name] = prog
	}

	// Compile validations; each expression must return *nono.CheckResponse or null.
	var rules []cel.Program
	for i, rule := range policy.Spec.Validations {
		epath := path.Child("validations").Index(i).Child("expression")
		ast, issues := env.Compile(rule.Expression)
		if issues.Err() != nil {
			return nil, append(allErrs, field.Invalid(epath, rule.Expression, issues.Err().Error()))
		}
		if !ast.OutputType().IsExactType(nonolib.ResponseType) && !ast.OutputType().IsExactType(types.NullType) {
			msg := fmt.Sprintf("validation expression must return %s or null, got %s",
				nonolib.ResponseType.TypeName(), ast.OutputType().TypeName())
			return nil, append(allErrs, field.Invalid(epath, rule.Expression, msg))
		}
		prog, err := env.Program(ast)
		if err != nil {
			return nil, append(allErrs, field.Invalid(epath, rule.Expression, err.Error()))
		}
		rules = append(rules, prog)
	}

	// Compile exceptions.
	var compiledExceptions []compiledException
	for _, ex := range exceptions {
		cex, errs := c.compileException(*ex, env)
		if errs != nil {
			allErrs = append(allErrs, errs...)
			continue
		}
		compiledExceptions = append(compiledExceptions, *cex)
	}
	if len(allErrs) > 0 {
		return nil, allErrs
	}

	return &CompiledPolicy{
		policyName:      policy.Name,
		matchConditions: matchConditions,
		variables:       variables,
		rules:           rules,
		exceptions:      compiledExceptions,
	}, nil
}

func (c *Compiler) compileException(ex v1.PolicyException, env *cel.Env) (*compiledException, field.ErrorList) {
	var allErrs field.ErrorList
	epath := field.NewPath("spec").Child("matchConditions")
	var progs []cel.Program
	for _, mc := range ex.Spec.MatchConditions {
		ast, issues := env.Compile(mc.Expression)
		if issues.Err() != nil {
			allErrs = append(allErrs, field.Invalid(epath, mc.Expression, issues.Err().Error()))
			continue
		}
		if !ast.OutputType().IsExactType(types.BoolType) {
			allErrs = append(allErrs, field.Invalid(epath, mc.Expression, "exception matchCondition must return bool"))
			continue
		}
		prog, err := env.Program(ast)
		if err != nil {
			allErrs = append(allErrs, field.Invalid(epath, mc.Expression, err.Error()))
			continue
		}
		progs = append(progs, prog)
	}
	if len(allErrs) > 0 {
		return nil, allErrs
	}
	return &compiledException{matchConditions: progs}, nil
}

// CompiledPolicy is an executable policy for nono requests.
// It implements policy.Policy[dynamic.Interface, *nonolib.CheckRequest, *nonolib.CheckResponse].
type CompiledPolicy struct {
	policyName      string
	failurePolicy   admissionregistrationv1.FailurePolicyType
	matchConditions []cel.Program
	variables       map[string]cel.Program
	rules           []cel.Program
	exceptions      []compiledException
}

type compiledException struct {
	matchConditions []cel.Program
}

// Name implements authzengine.Named for per-policy metrics.
func (p CompiledPolicy) Name() string { return p.policyName }

// Evaluate executes the policy against the nono request.
// Returns nil, nil when the policy does not match or is excepted (skip).
func (p CompiledPolicy) Evaluate(_ context.Context, _ dynamic.Interface, req *nonolib.CheckRequest) (*nonolib.CheckResponse, error) {
	resp, err := p.run(req)
	if err != nil && p.failurePolicy == admissionregistrationv1.Fail {
		return nil, err
	}
	return resp, nil
}

func (p CompiledPolicy) run(req *nonolib.CheckRequest) (*nonolib.CheckResponse, error) {
	// 1. Match conditions.
	data := map[string]any{objectKey: req}
	for _, prog := range p.matchConditions {
		out, _, err := prog.Eval(data)
		if err != nil {
			return nil, fmt.Errorf("matchCondition in policy %q: %w", p.policyName, err)
		}
		if b, ok := out.Value().(bool); !ok || !b {
			return nil, nil //nolint:nilnil // skip
		}
	}

	// 2. Exceptions.
	for _, ex := range p.exceptions {
		matched := true
		for _, prog := range ex.matchConditions {
			out, _, err := prog.Eval(data)
			if err != nil {
				return nil, fmt.Errorf("exception eval in policy %q: %w", p.policyName, err)
			}
			if b, ok := out.Value().(bool); !ok || !b {
				matched = false
				break
			}
		}
		if matched {
			return nil, nil //nolint:nilnil // excepted
		}
	}

	// 3. Build lazy variables activation.
	lazyVars := lazy.NewMapValue(authzcel.VariablesType)
	for varName, prog := range p.variables {
		n := varName
		pr := prog
		lazyVars.Append(n, func(_ *lazy.MapValue) ref.Val {
			d := map[string]any{objectKey: req, variablesKey: lazyVars}
			out, _, _ := pr.Eval(d)
			return out
		})
	}
	activation := map[string]any{
		objectKey:    req,
		variablesKey: lazyVars,
	}

	// 4. Evaluate rules; first non-null response wins.
	for _, prog := range p.rules {
		out, _, err := prog.Eval(activation)
		if err != nil {
			return nil, fmt.Errorf("rule eval in policy %q: %w", p.policyName, err)
		}
		if out == nil || out.Type() == types.NullType {
			continue
		}
		native, convErr := out.ConvertToNative(reflectTypeForCheckResponse)
		if convErr != nil {
			return nil, fmt.Errorf("response conversion in policy %q: %w", p.policyName, convErr)
		}
		if r, ok := native.(*nonolib.CheckResponse); ok && r != nil {
			return r, nil
		}
	}
	return nil, nil //nolint:nilnil
}
