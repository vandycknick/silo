// Package commands defines every command the SSH front end offers. Each file
// holds one command: what it is, which options it declares, and what it does.
// The transport hands a tokenized line to Execute and renders the Result.
package commands

import (
	"context"

	"github.com/vandycknick/silo/app/taild/internal/authz"
	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/service"
	"github.com/vandycknick/silo/app/taild/internal/sshd/cmdline"
)

// Context is one authenticated command line and the session it runs in. It is
// a context.Context, so handlers pass it straight to the domain.
type Context struct {
	context.Context
	Service *service.Service
	Caller  service.Caller
	Streams service.IO
	// JSON asks for the structured envelope; Execute sets it from --json.
	JSON bool
}

// Result is a command's outcome. Exit carries guest or stream exit codes and is
// zero for daemon-owned commands; failures travel as errors. Data may accompany
// an error, as a failed operation does.
type Result struct {
	Data  any
	Human string
	Exit  int
}

// Handler is one command's parsed state. Command.New returns a fresh value per
// invocation, so concurrent sessions never share option storage.
type Handler interface {
	// Flags declares the options once; parsing, help and the session-flag
	// scanner all read this declaration.
	Flags(*cmdline.FlagSet)
	// Run receives the positionals; options are already parsed into the receiver.
	Run(*Context, cmdline.Args) (Result, error)
}

// Topic is the help for one subcommand of a command that has them.
type Topic struct {
	Summary, Usage, Arguments, Example string
}

// Command is what the registry knows about a verb without running it.
type Command struct {
	Name        string
	Summary     string
	Usage       string
	Arguments   string
	Example     string
	Aliases     []string
	Subcommands []string
	// Streaming commands relay guest output and its exit code; the JSON
	// envelope cannot wrap them.
	Streaming bool
	// Topics describes subcommands for help, when the command has any.
	Topics func(sub string) (Topic, bool)
	New    func() Handler
}

func Usage() *authz.Error {
	return &authz.Error{Code: "usage", Message: "invalid command arguments; see help", Exit: 2}
}

func usageReason(message string) *authz.Error {
	return &authz.Error{Code: "usage", Message: message, Exit: 2}
}

func principal(dst *identity.Principal) func(string) error {
	return func(v string) error { *dst = identity.Principal(v); return nil }
}
