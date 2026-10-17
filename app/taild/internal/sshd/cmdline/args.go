package cmdline

// Args is what remains of a command line once the options are consumed.
type Args struct {
	Positional []string
	// Literal holds every token after "--"; Delimited records that "--" was
	// present even when nothing followed it.
	Literal   []string
	Delimited bool
}

// PositionalError carries schema labels only, never supplied argument values.
type PositionalError struct{ Reason string }

func (e *PositionalError) Error() string { return e.Reason }

func Missing(label string) error { return &PositionalError{Reason: "missing " + label + " argument"} }

func Unexpected(label string) error {
	return &PositionalError{Reason: "unexpected " + label + " argument"}
}

var (
	errPositional = &PositionalError{Reason: "unexpected positional argument"}
	errLiteral    = &PositionalError{Reason: "unexpected literal arguments after --"}
)

// None requires that nothing but options was supplied.
func (a Args) None() error {
	if len(a.Positional) != 0 {
		return errPositional
	}
	return a.NoLiteral()
}

// One requires exactly one positional argument and no literal tail.
func (a Args) One(label string) (string, error) {
	switch {
	case a.Delimited:
		return "", errLiteral
	case len(a.Positional) == 0:
		return "", Missing(label)
	case len(a.Positional) > 1:
		return "", Unexpected(label)
	}
	return a.Positional[0], nil
}

// NoLiteral rejects a "--" tail for commands that run nothing in the guest.
func (a Args) NoLiteral() error {
	if a.Delimited {
		return errLiteral
	}
	return nil
}
