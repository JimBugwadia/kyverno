package jmespath

import (
	gojmespath "github.com/kyverno/go-jmespath"
)

func newJMESPath(functions []FunctionEntry, query string) (*gojmespath.JMESPath, error) {
	jp, err := gojmespath.Compile(query)
	if err != nil {
		return nil, err
	}
	for _, function := range functions {
		jp.Register(function.FunctionEntry)
	}
	return jp, nil
}
