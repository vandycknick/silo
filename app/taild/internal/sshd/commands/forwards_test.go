package commands

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/vandycknick/silo/app/taild/internal/service"
)

func TestShowForwardsRendering(t *testing.T) {
	v := service.VM{Policy: "preview", GuestTCPPorts: []uint16{8080}, Forwards: []service.ForwardView{
		{Name: "web", Protocol: "https", ListenPort: 443, TargetPort: 8080, URL: "https://web.tail.test/"},
		{Name: "database", Protocol: "tcp", ListenPort: 15432, TargetPort: 5432, URL: "tcp://web.tail.test:15432"},
		{Name: "unavailable\n", Protocol: "tcp", ListenPort: 8081, TargetPort: 8080},
	}}
	want := "Policy: preview\nForwards:\n  web: https://web.tail.test/ -> guest 8080 (https)\n  database: tcp://web.tail.test:15432 -> guest 5432 (tcp)\n  unavailable�: :8081 -> guest 8080 (tcp)\nGuest TCP hints"
	if text := renderShow(v); !strings.Contains(text, want) {
		t.Fatal(text)
	}
	v.Forwards = nil
	if text := renderShow(v); strings.Contains(text, "Forwards:") {
		t.Fatal(text)
	}
}

// Check the documented strict schema against the actual serialized forward fields.
func TestShowForwardsJSONSchemaContract(t *testing.T) {
	raw, err := os.ReadFile("../../../docs/json.md")
	if err != nil {
		t.Fatal(err)
	}
	_, block, ok := strings.Cut(string(raw), "```json\n")
	if !ok {
		t.Fatal("JSON schema missing")
	}
	block, _, ok = strings.Cut(block, "\n```")
	if !ok {
		t.Fatal("JSON schema block unterminated")
	}
	type property struct {
		Type    string   `json:"type"`
		Enum    []string `json:"enum"`
		Minimum int      `json:"minimum"`
		Maximum int      `json:"maximum"`
		Format  string   `json:"format"`
	}
	type object struct {
		Type                 string              `json:"type"`
		Required             []string            `json:"required"`
		Properties           map[string]property `json:"properties"`
		AdditionalProperties bool                `json:"additionalProperties"`
	}
	var schema struct {
		Defs struct {
			VM struct {
				AdditionalProperties bool                       `json:"additionalProperties"`
				Properties           map[string]json.RawMessage `json:"properties"`
			} `json:"vm"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal([]byte(block), &schema); err != nil {
		t.Fatal(err)
	}
	var forwards struct {
		Type  string `json:"type"`
		Items object `json:"items"`
	}
	if err := json.Unmarshal(schema.Defs.VM.Properties["forwards"], &forwards); err != nil {
		t.Fatal(err)
	}
	want := map[string]property{
		"name":        {Type: "string"},
		"protocol":    {Enum: []string{"tcp", "https"}},
		"listen_port": {Type: "integer", Minimum: 1, Maximum: 65535},
		"target_port": {Type: "integer", Minimum: 1, Maximum: 65535},
		"url":         {Type: "string", Format: "uri"},
	}
	if schema.Defs.VM.AdditionalProperties || forwards.Type != "array" || forwards.Items.Type != "object" || forwards.Items.AdditionalProperties || !reflect.DeepEqual(forwards.Items.Properties, want) || !reflect.DeepEqual(forwards.Items.Required, []string{"name", "protocol", "listen_port", "target_port"}) {
		t.Fatalf("unexpected strict forward schema: %+v", forwards)
	}
	for _, url := range []string{"https://web.tail.test/", ""} {
		data, err := json.Marshal(service.ForwardView{Name: "web", Protocol: "https", ListenPort: 443, TargetPort: 8080, URL: url})
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(data, &fields); err != nil {
			t.Fatal(err)
		}
		for key := range fields {
			if _, ok := forwards.Items.Properties[key]; !ok {
				t.Fatalf("serialized forward field %q rejected by strict schema", key)
			}
		}
		for _, key := range forwards.Items.Required {
			if _, ok := fields[key]; !ok {
				t.Fatalf("required forward field %q missing", key)
			}
		}
		if _, present := fields["url"]; present != (url != "") {
			t.Fatal("URL omission mismatch", string(data))
		}
	}
}
