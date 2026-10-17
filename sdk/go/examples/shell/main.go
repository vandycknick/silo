// Run with an already-running machine: go run ./examples/shell <machine-reference>.
package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	silo "github.com/vandycknick/silo/sdk/go"
)

// A bytes.Buffer cannot block, so this finite-memory writer does not need to
// interrupt a syscall. A network/outer SSH writer must honor ctx cancellation.
// The SDK serializes both sinks, so this one buffer needs no separate mutex.
type memoryOutput struct{ bytes.Buffer }

func (w *memoryOutput) WriteContext(ctx context.Context, data []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return w.Write(data)
}
func run(ctx context.Context, reference string) (int, error) {
	runtime, err := silo.Open(ctx)
	if err != nil {
		return 1, err
	}
	defer runtime.Close()
	machine, err := runtime.Machine(ctx, reference)
	if err != nil {
		return 1, err
	}
	defer machine.Close()
	var output memoryOutput
	controls := make(chan silo.SSHShellControl, 1)
	controls <- silo.SSHShellControl{Kind: silo.SSHShellResize, Rows: 37, Columns: 119}
	close(controls)
	status, err := machine.Shell(ctx, silo.WithSSHTerm("xterm-256color"), silo.WithShellAttachment(silo.SSHShellAttachment{
		Rows: 37, Columns: 119, Stdout: &output, Stderr: &output, Controls: controls,
		Input: func(context.Context) io.Reader {
			// A finite reader cannot block. A streaming reader must unblock on the
			// factory's child context, which is stopped even after successful guest exit.
			return strings.NewReader("printf 'embedded:%s\\n' \"$USER\"; exit 7\n")
		},
	}))
	if err != nil {
		return 1, err
	}
	if _, err := os.Stdout.Write(output.Bytes()); err != nil {
		return 1, err
	}
	fmt.Printf("SSH exit: %d\n", status.Code)
	return int(status.Code), nil
}
func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: shell <machine-reference>")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	code, err := run(ctx, os.Args[1])
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(code)
}
