package policy

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/zclconf/go-cty/cty"
)

func decodeStringAttr(attr *hcl.Attribute) (string, error) {
	var value string
	if diagnostics := gohcl.DecodeExpression(attr.Expr, nil, &value); diagnostics.HasErrors() {
		return "", fmt.Errorf("%s", diagnostics.Error())
	}
	return value, nil
}

func decodeIntAttr(attr *hcl.Attribute) (int, error) {
	var value int
	if diagnostics := gohcl.DecodeExpression(attr.Expr, nil, &value); diagnostics.HasErrors() {
		return 0, fmt.Errorf("%s", diagnostics.Error())
	}
	return value, nil
}

func decodeBoolAttr(attr *hcl.Attribute) (bool, error) {
	var value bool
	if diagnostics := gohcl.DecodeExpression(attr.Expr, nil, &value); diagnostics.HasErrors() {
		return false, fmt.Errorf("%s", diagnostics.Error())
	}
	return value, nil
}

func decodeRefAttr(attr *hcl.Attribute) (Ref, error) {
	traversal, diagnostics := hcl.AbsTraversalForExpr(attr.Expr)
	if diagnostics.HasErrors() {
		return Ref{}, fmt.Errorf("expected reference like https.github: %s", diagnostics.Error())
	}
	return refFromTraversal(traversal)
}

func decodeRefListAttr(attr *hcl.Attribute) ([]Ref, error) {
	variables := attr.Expr.Variables()
	if len(variables) == 0 {
		return nil, fmt.Errorf("expected at least one reference")
	}
	refs := make([]Ref, 0, len(variables))
	for _, variable := range variables {
		ref, err := refFromTraversal(variable)
		if err != nil {
			return nil, err
		}
		refs = append(refs, ref)
	}
	return refs, nil
}

func decodePortRangesAttr(attr *hcl.Attribute) ([]PortRange, error) {
	value, diagnostics := attr.Expr.Value(nil)
	if diagnostics.HasErrors() {
		return nil, fmt.Errorf("%s", diagnostics.Error())
	}
	if !value.CanIterateElements() {
		return nil, fmt.Errorf("expected list of ports or port ranges")
	}
	var ports []PortRange
	iterator := value.ElementIterator()
	for iterator.Next() {
		_, element := iterator.Element()
		if !element.IsKnown() || element.IsNull() {
			return nil, fmt.Errorf("port entries must be known and non-null")
		}
		switch element.Type() {
		case cty.Number:
			port, _ := element.AsBigFloat().Int64()
			if port < 1 || port > 65535 {
				return nil, fmt.Errorf("port %d is out of range", port)
			}
			ports = append(ports, PortRange{Start: uint16(port), End: uint16(port)})
		case cty.String:
			portRange, err := parsePortRange(element.AsString())
			if err != nil {
				return nil, err
			}
			ports = append(ports, portRange)
		default:
			return nil, fmt.Errorf("ports entries must be numbers or string ranges")
		}
	}
	return ports, nil
}

func parsePortRange(value string) (PortRange, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return PortRange{}, fmt.Errorf("port range must not be empty")
	}
	if !strings.Contains(value, "-") {
		port, err := parsePort(value)
		if err != nil {
			return PortRange{}, err
		}
		return PortRange{Start: port, End: port}, nil
	}
	startText, endText, ok := strings.Cut(value, "-")
	if !ok || strings.Contains(endText, "-") {
		return PortRange{}, fmt.Errorf("invalid port range %q", value)
	}
	start, err := parsePort(strings.TrimSpace(startText))
	if err != nil {
		return PortRange{}, err
	}
	end, err := parsePort(strings.TrimSpace(endText))
	if err != nil {
		return PortRange{}, err
	}
	if end < start {
		return PortRange{}, fmt.Errorf("port range %q ends before it starts", value)
	}
	return PortRange{Start: start, End: end}, nil
}

func refFromTraversal(traversal hcl.Traversal) (Ref, error) {
	if len(traversal) != 2 {
		return Ref{}, fmt.Errorf("expected two-part reference like https.github")
	}
	root, ok := traversal[0].(hcl.TraverseRoot)
	if !ok {
		return Ref{}, fmt.Errorf("expected reference root")
	}
	attr, ok := traversal[1].(hcl.TraverseAttr)
	if !ok {
		return Ref{}, fmt.Errorf("expected reference attribute")
	}
	if !validTraversalIdentifier(root.Name) || !validTraversalIdentifier(attr.Name) {
		return Ref{}, fmt.Errorf("reference %q must use traversal identifiers", root.Name+"."+attr.Name)
	}
	return Ref{Kind: root.Name, Name: attr.Name}, nil
}

func parseTerminalAction(value string) (Action, error) {
	switch Action(value) {
	case "", ActionAllow:
		return ActionAllow, nil
	case ActionDeny:
		return ActionDeny, nil
	default:
		return "", fmt.Errorf("invalid action %q, expected allow or deny", value)
	}
}

func parseRuleAction(value string) (Action, error) {
	switch Action(value) {
	case ActionAllow, ActionDeny:
		return Action(value), nil
	default:
		return "", fmt.Errorf("invalid verdict %q, expected allow or deny", value)
	}
}

func validTraversalIdentifier(value string) bool {
	if value == "" {
		return false
	}
	for index, r := range value {
		if index == 0 {
			if r == '_' || unicode.IsLetter(r) {
				continue
			}
			return false
		}
		if r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r) {
			continue
		}
		return false
	}
	return true
}
