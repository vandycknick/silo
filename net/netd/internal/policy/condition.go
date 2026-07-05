package policy

import (
	"fmt"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types/ref"
)

type conditionProgram interface {
	Eval(any) (ref.Val, *cel.EvalDetails, error)
}

var httpConditionEnv, httpConditionEnvErr = cel.NewEnv(
	cel.Variable("http.method", cel.StringType),
	cel.Variable("http.host", cel.StringType),
	cel.Variable("http.path", cel.StringType),
	cel.Variable("http.query", cel.MapType(cel.StringType, cel.ListType(cel.StringType))),
	cel.Variable("http.headers", cel.MapType(cel.StringType, cel.ListType(cel.StringType))),
)

func compileHTTPCondition(source string) (*httpCondition, error) {
	if strings.TrimSpace(source) == "" {
		return nil, fmt.Errorf("condition is empty")
	}
	if httpConditionEnvErr != nil {
		return nil, httpConditionEnvErr
	}
	ast, issues := httpConditionEnv.Compile(source)
	if issues != nil && issues.Err() != nil {
		return nil, issues.Err()
	}
	if !ast.OutputType().IsExactType(cel.BoolType) {
		return nil, fmt.Errorf("condition must evaluate to bool, got %s", ast.OutputType())
	}
	program, err := httpConditionEnv.Program(ast)
	if err != nil {
		return nil, err
	}
	return &httpCondition{source: source, program: program}, nil
}
