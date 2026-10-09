package policy

// Tailscale returns a copy so runtime setup cannot mutate the compiled policy.
func (p *Policy) Tailscale() *TailscaleDecl {
	if p == nil || p.tailscale == nil {
		return nil
	}
	decl := *p.tailscale
	decl.Tags = append([]string(nil), decl.Tags...)
	return &decl
}
