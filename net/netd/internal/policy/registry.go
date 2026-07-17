package policy

type EndpointSchema string

const (
	EndpointSchemaIP         EndpointSchema = "ip"
	EndpointSchemaHosts      EndpointSchema = "hosts"
	EndpointSchemaRegistries EndpointSchema = "registries"
)

type TLSMode string

const (
	TLSModeNone      TLSMode = "none"
	TLSModeTerminate TLSMode = "terminate"
)

type ConditionKind string

const (
	ConditionKindNone ConditionKind = "none"
	ConditionKindCEL  ConditionKind = "cel"
)

type FacetKind string

const (
	FacetString        FacetKind = "string"
	FacetStringListMap FacetKind = "string-list-map"
	FacetInt           FacetKind = "int"
	FacetBool          FacetKind = "bool"
)

type FacetField struct {
	Name     string
	Kind     FacetKind
	Optional bool
}

type FacetDefinition struct {
	Name   string
	Fields []FacetField
}

type EndpointDefinition struct {
	Kind                string
	Family              EndpointFamily
	Transport           Transport
	TLSMode             TLSMode
	DefaultPort         uint16
	Schema              EndpointSchema
	SupportsCredentials bool
}

type FamilyDefinition struct {
	Family    EndpointFamily
	Condition ConditionKind
	Facets    []string
}

type Registry struct {
	endpoints map[string]EndpointDefinition
	families  map[EndpointFamily]FamilyDefinition
	facets    map[string]FacetDefinition
}

func BuiltinRegistry() *Registry {
	return &Registry{
		endpoints: map[string]EndpointDefinition{
			"ip":         {Kind: "ip", Family: EndpointFamilyIP, Transport: TransportPacketFilter, TLSMode: TLSModeNone, Schema: EndpointSchemaIP},
			"http":       {Kind: "http", Family: EndpointFamilyHTTP, Transport: TransportHTTPProxy, TLSMode: TLSModeNone, DefaultPort: 80, Schema: EndpointSchemaHosts},
			"https":      {Kind: "https", Family: EndpointFamilyHTTP, Transport: TransportHTTPSMITM, TLSMode: TLSModeTerminate, DefaultPort: 443, Schema: EndpointSchemaHosts, SupportsCredentials: true},
			"registries": {Kind: "registries", Family: EndpointFamilyPackage, Transport: TransportTLSTerminate, TLSMode: TLSModeTerminate, DefaultPort: 443, Schema: EndpointSchemaRegistries},
		},
		families: map[EndpointFamily]FamilyDefinition{
			EndpointFamilyIP:      {Family: EndpointFamilyIP, Condition: ConditionKindNone},
			EndpointFamilyHTTP:    {Family: EndpointFamilyHTTP, Condition: ConditionKindCEL, Facets: []string{"http"}},
			EndpointFamilyPackage: {Family: EndpointFamilyPackage, Condition: ConditionKindCEL, Facets: []string{"http", "package"}},
		},
		facets: map[string]FacetDefinition{
			"http":    {Name: "http", Fields: []FacetField{{Name: "method", Kind: FacetString}, {Name: "host", Kind: FacetString}, {Name: "path", Kind: FacetString}, {Name: "query", Kind: FacetStringListMap}, {Name: "headers", Kind: FacetStringListMap}}},
			"package": {Name: "package", Fields: []FacetField{{Name: "ecosystem", Kind: FacetString}, {Name: "operation", Kind: FacetString}, {Name: "name", Kind: FacetString}, {Name: "version", Kind: FacetString}, {Name: "identity_known", Kind: FacetBool}, {Name: "age_known", Kind: FacetBool}, {Name: "age_hours", Kind: FacetInt}, {Name: "age_source", Kind: FacetString}, {Name: "malware_data_available", Kind: FacetBool}, {Name: "malware", Kind: FacetBool}, {Name: "malware_reason", Kind: FacetString, Optional: true}}},
		},
	}
}

func (r *Registry) Endpoint(kind string) (EndpointDefinition, bool) {
	definition, ok := r.endpoints[kind]
	return definition, ok
}

func (r *Registry) Family(family EndpointFamily) (FamilyDefinition, bool) {
	definition, ok := r.families[family]
	return definition, ok
}

func (r *Registry) Facet(name string) (FacetDefinition, bool) {
	definition, ok := r.facets[name]
	return definition, ok
}
