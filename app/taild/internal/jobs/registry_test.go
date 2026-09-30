package jobs

import (
	"context"
	"testing"
)

func TestRestartRegistryIsEmptyAndShutdownJoins(t *testing.T) {
	r := &Registry{}
	if e := r.Wait(context.Background()); e != nil {
		t.Fatal(e)
	}
	if !r.closing {
		t.Fatal("registry did not seal")
	}
}
