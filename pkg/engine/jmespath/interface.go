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
	i := gojmespath.NewInterpreter()
	functions := GetFunctions(configuration)
	for _, f := range functions {
		i.Register(f.FunctionEntry)
	}

	return implementation{
		interpreter: i,
	}
}

func (i implementation) Query(query string) (Query, error) {
	return newJMESPath(i.interpreter, query)
}

func (i implementation) Search(query string, data interface{}) (interface{}, error) {
	return newExecution(i.interpreter, query, data)
}
