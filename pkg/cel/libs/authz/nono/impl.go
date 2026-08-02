package nono

import (
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	authzutils "github.com/kyverno/kyverno-authz/pkg/cel/utils"
)

type impl struct {
	types.Adapter
}

func (c *impl) grant() ref.Val {
	return c.NativeToValue(CheckResponseGranted{})
}

func (c *impl) deny(reason ref.Val) ref.Val {
	r, err := authzutils.ConvertToNative[string](reason)
	if err != nil {
		return types.WrapErr(err)
	}
	return c.NativeToValue(CheckResponseDenied{Reason: r})
}

func (c *impl) responseGranted(v ref.Val) ref.Val {
	g, err := authzutils.ConvertToNative[CheckResponseGranted](v)
	if err != nil {
		return types.WrapErr(err)
	}
	return c.NativeToValue(&CheckResponse{Granted: &g})
}

func (c *impl) responseDenied(v ref.Val) ref.Val {
	d, err := authzutils.ConvertToNative[CheckResponseDenied](v)
	if err != nil {
		return types.WrapErr(err)
	}
	return c.NativeToValue(&CheckResponse{Denied: &d})
}

// argv drops args[0] (the nono shim path) and returns args[1:].
// This mirrors the demo webhook's slicing logic.
func (c *impl) argv(v ref.Val) ref.Val {
	cmd, err := authzutils.ConvertToNative[CommandData](v)
	if err != nil {
		return types.WrapErr(err)
	}
	if len(cmd.Args) <= 1 {
		return c.NativeToValue([]string{})
	}
	return c.NativeToValue(cmd.Args[1:])
}
