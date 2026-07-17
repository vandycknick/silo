package policy

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types/ref"
)

type conditionProgram interface {
	Eval(any) (ref.Val, *cel.EvalDetails, error)
}

func buildFacetActivation(registry *Registry, family EndpointFamily, values FacetValues) (map[string]any, error) {
	familyDefinition, ok := registry.Family(family)
	if !ok {
		return nil, fmt.Errorf("unknown endpoint family %q", family)
	}
	allowedFacets := make(map[string]struct{}, len(familyDefinition.Facets))
	for _, facetName := range familyDefinition.Facets {
		allowedFacets[facetName] = struct{}{}
	}
	for facetName := range values {
		if _, ok := allowedFacets[facetName]; !ok {
			return nil, fmt.Errorf("endpoint family %q does not include facet %q", family, facetName)
		}
	}
	activation := make(map[string]any)
	for _, facetName := range familyDefinition.Facets {
		facet, ok := registry.Facet(facetName)
		if !ok {
			return nil, fmt.Errorf("endpoint family %q references unknown facet %q", family, facetName)
		}
		provided := values[facetName]
		declared := make(map[string]struct{}, len(facet.Fields))
		for _, field := range facet.Fields {
			declared[field.Name] = struct{}{}
			value, exists := provided[field.Name]
			if !exists {
				if !field.Optional {
					return nil, fmt.Errorf("facet %q requires field %q", facetName, field.Name)
				}
				value = zeroFacetValue(field.Kind)
			}
			normalized, err := normalizeFacetValue(field.Kind, value)
			if err != nil {
				return nil, fmt.Errorf("facet %q field %q: %w", facetName, field.Name, err)
			}
			activation[celVariableName(facetName, field.Name)] = normalized
		}
		for fieldName := range provided {
			if _, ok := declared[fieldName]; !ok {
				return nil, fmt.Errorf("facet %q does not declare field %q", facetName, fieldName)
			}
		}
	}
	return activation, nil
}

func zeroFacetValue(kind FacetKind) any {
	switch kind {
	case FacetString:
		return ""
	case FacetStringListMap:
		return map[string][]string{}
	case FacetInt:
		return int64(0)
	case FacetBool:
		return false
	default:
		return nil
	}
}

func normalizeFacetValue(kind FacetKind, value any) (any, error) {
	switch kind {
	case FacetString:
		if typed, ok := value.(string); ok {
			return typed, nil
		}
	case FacetStringListMap:
		if typed, ok := value.(map[string][]string); ok {
			return typed, nil
		}
	case FacetInt:
		switch typed := value.(type) {
		case int:
			return int64(typed), nil
		case int32:
			return int64(typed), nil
		case int64:
			return typed, nil
		}
	case FacetBool:
		if typed, ok := value.(bool); ok {
			return typed, nil
		}
	}
	actual := "<nil>"
	if valueType := reflect.TypeOf(value); valueType != nil {
		actual = valueType.String()
	}
	return nil, fmt.Errorf("expected %s, got %s", kind, actual)
}

func compileCondition(registry *Registry, family EndpointFamily, source string) (*httpCondition, error) {
	if strings.TrimSpace(source) == "" {
		return nil, fmt.Errorf("condition is empty")
	}
	familyDefinition, ok := registry.Family(family)
	if !ok {
		return nil, fmt.Errorf("unknown endpoint family %q", family)
	}
	if familyDefinition.Condition != ConditionKindCEL {
		return nil, fmt.Errorf("conditions are not supported for endpoint family %q", family)
	}
	preparedSource, err := prepareConditionSource(registry, familyDefinition, source)
	if err != nil {
		return nil, err
	}
	options := make([]cel.EnvOption, 0)
	for _, facetName := range familyDefinition.Facets {
		facet, ok := registry.Facet(facetName)
		if !ok {
			return nil, fmt.Errorf("endpoint family %q references unknown facet %q", family, facetName)
		}
		for _, field := range facet.Fields {
			fieldType, err := celTypeForFacet(field.Kind)
			if err != nil {
				return nil, fmt.Errorf("facet %q field %q: %w", facet.Name, field.Name, err)
			}
			options = append(options, cel.Variable(celVariableName(facet.Name, field.Name), fieldType))
		}
	}
	environment, err := cel.NewEnv(options...)
	if err != nil {
		return nil, err
	}
	ast, issues := environment.Compile(preparedSource)
	if issues != nil && issues.Err() != nil {
		return nil, issues.Err()
	}
	if !ast.OutputType().IsExactType(cel.BoolType) {
		return nil, fmt.Errorf("condition must evaluate to bool, got %s", ast.OutputType())
	}
	program, err := environment.Program(ast)
	if err != nil {
		return nil, err
	}
	return &httpCondition{source: source, program: program}, nil
}

func prepareConditionSource(registry *Registry, family FamilyDefinition, source string) (string, error) {
	prepared := source
	for _, facetName := range family.Facets {
		facet, ok := registry.Facet(facetName)
		if !ok {
			return "", fmt.Errorf("endpoint family %q references unknown facet %q", family.Family, facetName)
		}
		for _, field := range facet.Fields {
			path := facet.Name + "." + field.Name
			variable := celVariableName(facet.Name, field.Name)
			if path != variable {
				prepared = rewriteCELIdentifier(prepared, path, variable)
			}
		}
		if facet.Name == "package" && containsCELPathPrefix(prepared, "package.") {
			return "", fmt.Errorf("unknown package condition facet")
		}
	}
	return prepared, nil
}

func rewriteCELIdentifier(source string, original string, replacement string) string {
	var prepared strings.Builder
	prepared.Grow(len(source))
	for index := 0; index < len(source); {
		if source[index] == '\'' || source[index] == '"' {
			end := quotedCELLiteralEnd(source, index)
			prepared.WriteString(source[index:end])
			index = end
			continue
		}
		if strings.HasPrefix(source[index:], original) && celIdentifierBoundary(source, index, len(original)) {
			prepared.WriteString(replacement)
			index += len(original)
			continue
		}
		prepared.WriteByte(source[index])
		index++
	}
	return prepared.String()
}

func quotedCELLiteralEnd(source string, start int) int {
	quote := source[start]
	for index := start + 1; index < len(source); index++ {
		if source[index] == '\\' {
			index++
			continue
		}
		if source[index] == quote {
			return index + 1
		}
	}
	return len(source)
}

func celIdentifierBoundary(source string, start int, length int) bool {
	if !celIdentifierStartBoundary(source, start) {
		return false
	}
	end := start + length
	return end == len(source) || !isCELIdentifierByte(source[end])
}

func containsCELPathPrefix(source string, prefix string) bool {
	for index := 0; index < len(source); {
		if source[index] == '\'' || source[index] == '"' {
			index = quotedCELLiteralEnd(source, index)
			continue
		}
		if strings.HasPrefix(source[index:], prefix) && celIdentifierStartBoundary(source, index) {
			return true
		}
		index++
	}
	return false
}

func celIdentifierStartBoundary(source string, start int) bool {
	return start == 0 || !isCELIdentifierByte(source[start-1]) && source[start-1] != '.'
}

func isCELIdentifierByte(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' || value == '_'
}

func celVariableName(facet string, field string) string {
	if facet == "package" {
		return "__silo_package_" + field
	}
	return facet + "." + field
}

func celTypeForFacet(kind FacetKind) (*cel.Type, error) {
	switch kind {
	case FacetString:
		return cel.StringType, nil
	case FacetStringListMap:
		return cel.MapType(cel.StringType, cel.ListType(cel.StringType)), nil
	case FacetInt:
		return cel.IntType, nil
	case FacetBool:
		return cel.BoolType, nil
	default:
		return nil, fmt.Errorf("unsupported kind %q", kind)
	}
}
