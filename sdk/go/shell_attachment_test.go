package silo

import (
	"context"
	"io"
	"testing"
)

func TestShellAttachmentRejectsInvalidConfigurationBeforeNativeUse(t *testing.T) {
	machine := &Machine{closed: true}
	for _, attachment := range []SSHShellAttachment{{}, {Rows: 1}, {Columns: 1}} {
		_, err := machine.Shell(context.Background(), WithShellAttachment(attachment))
		if !IsErrorKind(err, ErrorInvalidArgument) {
			t.Fatalf("dimensions: %v", err)
		}
	}
	_, err := machine.Shell(context.Background(), WithShellAttachment(SSHShellAttachment{Rows: 37, Columns: 119}), WithSSHDetachKeys(""))
	if !IsErrorKind(err, ErrorInvalidArgument) {
		t.Fatalf("explicit empty detach keys: %v", err)
	}
	_, err = machine.Shell(context.Background(), WithShellAttachment(SSHShellAttachment{Rows: 37, Columns: 119}))
	if !IsErrorKind(err, ErrorClosed) {
		t.Fatalf("valid attachment: %v", err)
	}
}

func TestShellControlValidation(t *testing.T) {
	supported := []SSHShellSignal{SSHShellHUP, SSHShellINT, SSHShellQUIT, SSHShellILL, SSHShellABRT, SSHShellFPE, SSHShellKILL, SSHShellUSR1, SSHShellSEGV, SSHShellUSR2, SSHShellPIPE, SSHShellALRM, SSHShellTERM}
	for signal := SSHShellSignal(0); signal <= 64; signal++ {
		want := false
		for _, valid := range supported {
			if signal == valid {
				want = true
			}
		}
		err := validateShellControl(SSHShellControl{Kind: SSHShellSendSignal, Signal: signal})
		if (err == nil) != want {
			t.Fatalf("signal %d: %v", signal, err)
		}
	}
	for _, control := range []SSHShellControl{{}, {Kind: "unknown"}, {Kind: SSHShellResize}, {Kind: SSHShellResize, Rows: 1}, {Kind: SSHShellResize, Columns: 1}} {
		if !IsErrorKind(validateShellControl(control), ErrorInvalidArgument) {
			t.Fatalf("accepted %+v", control)
		}
	}
	if err := validateShellControl(SSHShellControl{Kind: SSHShellResize, Rows: 65535, Columns: 65535}); err != nil {
		t.Fatal(err)
	}
}

func TestCanceledInputDoesNotConstructBorrowedReader(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := shellInput(ctx, nil, func(context.Context) io.Reader { t.Fatal("factory called after cancellation"); return nil })
	if err != nil {
		t.Fatal(err)
	}
}
