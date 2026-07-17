package policy

import "testing"

func TestPackageFacetCondition(t *testing.T) {
	registry := BuiltinRegistry()
	condition, err := compileCondition(
		registry,
		EndpointFamilyPackage,
		`http.method == "GET" && package.identity_known && package.age_hours < 24 && !package.malware`,
	)
	if err != nil {
		t.Fatalf("compile condition: %v", err)
	}
	activation, err := buildFacetActivation(registry, EndpointFamilyPackage, FacetValues{
		"http": {
			"method":  "GET",
			"host":    "registry.npmjs.org",
			"path":    "/example",
			"query":   map[string][]string{},
			"headers": map[string][]string{},
		},
		"package": {
			"ecosystem":              "npm",
			"operation":              "artifact",
			"name":                   "example",
			"version":                "1.0.0",
			"identity_known":         true,
			"age_known":              true,
			"age_hours":              1,
			"age_source":             "registry_metadata",
			"malware_data_available": true,
			"malware":                false,
		},
	})
	if err != nil {
		t.Fatalf("build activation: %v", err)
	}
	result, _, err := condition.program.Eval(activation)
	if err != nil {
		t.Fatalf("evaluate condition: %v", err)
	}
	matched, ok := result.Value().(bool)
	if !ok || !matched {
		t.Fatalf("condition result = %#v", result.Value())
	}
	if activation[celVariableName("package", "malware_reason")] != "" {
		t.Fatalf("optional field was not zero-filled: %#v", activation[celVariableName("package", "malware_reason")])
	}
}

func TestPackageFacetRequiresDeclaredFields(t *testing.T) {
	_, err := buildFacetActivation(BuiltinRegistry(), EndpointFamilyPackage, FacetValues{
		"package": {"ecosystem": "npm"},
	})
	if err == nil {
		t.Fatal("incomplete package facet was accepted")
	}
}

func TestFacetRewritePreservesStringLiterals(t *testing.T) {
	prepared, err := prepareConditionSource(
		BuiltinRegistry(),
		FamilyDefinition{Family: EndpointFamilyPackage, Facets: []string{"package"}},
		`package.name == "package.age_hours"`,
	)
	if err != nil {
		t.Fatal(err)
	}
	if prepared != `__silo_package_name == "package.age_hours"` {
		t.Fatalf("prepared condition = %q", prepared)
	}
}
