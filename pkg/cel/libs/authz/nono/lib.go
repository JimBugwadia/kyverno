package nono

import (
	"reflect"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/ext"
)

type lib struct{}

// Lib returns the CEL environment option that registers the nono type library.
// Include this when building the CEL environment for Nono-mode policies.
func Lib() cel.EnvOption {
	return cel.Lib(&lib{})
}

func (*lib) LibraryName() string {
	return "kyverno.authz.nono"
}

func (c *lib) CompileOptions() []cel.EnvOption {
	return []cel.EnvOption{
		// Register all nono native types so CEL can inspect their fields.
		ext.NativeTypes(
			reflect.TypeFor[CheckRequest](),
			reflect.TypeFor[RequestData](),
			reflect.TypeFor[CheckResponse](),
			reflect.TypeFor[CheckResponseGranted](),
			reflect.TypeFor[CheckResponseDenied](),
			ext.ParseStructTags(true),
		),
		c.extendEnv,
	}
}

func (*lib) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}

func (c *lib) extendEnv(env *cel.Env) (*cel.Env, error) {
	i := &impl{Adapter: env.CELTypeAdapter()}

	libraryDecls := map[string][]cel.FunctionOpt{
		// nono.Grant() → CheckResponseGranted
		"nono.Grant": {
			cel.Overload(
				"nono_grant",
				[]*cel.Type{},
				ResponseGrantedType,
				cel.FunctionBinding(func(_ ...ref.Val) ref.Val { return i.grant() }),
			),
		},
		// nono.Deny(reason string) → CheckResponseDenied
		"nono.Deny": {
			cel.Overload(
				"nono_deny_string",
				[]*cel.Type{cel.StringType},
				ResponseDeniedType,
				cel.UnaryBinding(i.deny),
			),
		},
		// .Response() on CheckResponseGranted / CheckResponseDenied → CheckResponse
		"Response": {
			cel.MemberOverload(
				"nono_response_granted",
				[]*cel.Type{ResponseGrantedType},
				ResponseType,
				cel.UnaryBinding(i.responseGranted),
			),
			cel.MemberOverload(
				"nono_response_denied",
				[]*cel.Type{ResponseDeniedType},
				ResponseType,
				cel.UnaryBinding(i.responseDenied),
			),
		},
		// object.request.argv() → list(string) — drops argv[0] (the nono shim path)
		"argv": {
			cel.MemberOverload(
				"nono_request_argv",
				[]*cel.Type{RequestDataType},
				types.NewListType(cel.StringType),
				cel.UnaryBinding(i.argv),
			),
		},
	}

	opts := make([]cel.EnvOption, 0, len(libraryDecls))
	for name, overloads := range libraryDecls {
		opts = append(opts, cel.Function(name, overloads...))
	}
	return env.Extend(opts...)
}
