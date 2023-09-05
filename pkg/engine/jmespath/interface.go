package jmespath

import (
	gojmespath "github.com/kyverno/go-jmespath"
	"github.com/kyverno/kyverno/pkg/config"
)

type Query interface {
	Search(interface{}) (interface{}, error)
}

type Interface interface {
	Query(string) (Query, error)
	Search(string, interface{}) (interface{}, error)
}

type implementation struct {
	interpreter gojmespath.Interpreter
}

func New(configuration config.Configuration) Interface {
	functions := GetFunctions(configuration)
	jpFunctions := make([]gojmespath.FunctionEntry, len(functions))
	for i, f := range functions {
		jpFunctions[i] = f.FunctionEntry
	}

	i := gojmespath.NewInterpreter(jpFunctions...)
	return implementation{
		interpreter: i,
	}
}

func (i implementation) Query(query string) (Query, error) {
	parser := gojmespath.NewParser()
	ast, err := parser.Parse(query)
	if err != nil {
		return nil, err
	}

	return &gojmespath.JMESPath{
		AST:         ast,
		Interpreter: i.interpreter,
	}, nil
}

func (i implementation) Search(query string, data interface{}) (interface{}, error) {
	parser := gojmespath.NewParser()
	ast, err := parser.Parse(query)
	if err != nil {
		return nil, err
	}

	return i.interpreter.Execute(ast, data)
}
