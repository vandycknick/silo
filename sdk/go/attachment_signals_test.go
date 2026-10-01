package silo

import (
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"testing"
	"time"
)

func TestAttachmentSignalsPreserveApplicationSubscribers(t *testing.T) {
	if os.Getenv("SILO_SIGNAL_SUBSCRIPTION_CHILD") != "1" {
		command := exec.Command(os.Args[0], "-test.run=^TestAttachmentSignalsPreserveApplicationSubscribers$", "-test.v")
		command.Env = append(os.Environ(), "SILO_SIGNAL_SUBSCRIPTION_CHILD=1")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("signal child: %v\n%s", err, output)
		}
		return
	}
	app := make(chan os.Signal, 16)
	signal.Notify(app, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(app)
	for i := 0; i < 10; i++ {
		notifications, stop := attachmentSignals(false)
		for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM} {
			if err := syscall.Kill(os.Getpid(), sig); err != nil {
				t.Fatal(err)
			}
			select {
			case got := <-app:
				if got != sig {
					t.Fatalf("got %v, want %v", got, sig)
				}
			case <-time.After(time.Second):
				t.Fatal("application missed signal during attachment")
			}
			select {
			case got := <-notifications:
				if got != sig {
					t.Fatalf("SDK got %v, want %v", got, sig)
				}
			case <-time.After(time.Second):
				t.Fatal("SDK subscription missed signal")
			}
		}
		stop()
		if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
			t.Fatal(err)
		}
		select {
		case <-app:
		case <-time.After(time.Second):
			t.Fatal("Stop removed application subscriber")
		}
	}
}
