package silo

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeInventoryIsolatesTimestampOverflow(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 stdlib sqlite3 is required for real corrupt-timestamp inventory coverage")
	}
	r, home := phase7Runtime(t)
	ctx := context.Background()
	disk := filepath.Join(home, "input.raw")
	if err := os.WriteFile(disk, []byte("root-disk"), 0600); err != nil {
		t.Fatal(err)
	}
	healthy, err := r.CreateMachine(ctx, DiskImage(disk), WithName("healthy-neighbor"))
	if err != nil {
		t.Fatal(err)
	}
	defer healthy.Close()
	bad, err := r.CreateMachine(ctx, DiskImage(disk), WithName("reserved-corrupt-time"))
	if err != nil {
		t.Fatal(err)
	}
	defer bad.Close()
	// Modify the real persisted configuration, retaining its indexed identity
	// and all other fields. This exercises libvm and the native DTO, not a wire stub.
	output, err := exec.Command(python, "-c", `import sqlite3,sys
db=sqlite3.connect(sys.argv[1])
cursor=db.execute("UPDATE machine_config SET config_json=jsonb_set(config_json, '$.createdAt', ?) WHERE name=?", (9223372036854775806,sys.argv[2]))
assert cursor.rowcount == 1
db.commit()`, filepath.Join(home, "state.db"), "reserved-corrupt-time").CombinedOutput()
	if err != nil {
		t.Fatalf("corrupt real SQLite timestamp: %v %s", err, output)
	}
	entries, err := r.Inventory(ctx)
	if err != nil || len(entries) != 2 {
		t.Fatalf("inventory must retain both indexed entries: %#v %v", entries, err)
	}
	foundHealthy, foundBad := false, false
	for _, entry := range entries {
		switch entry.ID {
		case healthy.ID():
			foundHealthy = true
			if entry.Name != "healthy-neighbor" || entry.Data == nil || entry.Data.CreatedAt.Year() < 2026 {
				t.Fatalf("healthy neighbor lost: %#v", entry)
			}
		case bad.ID():
			foundBad = true
			if entry.Name != "reserved-corrupt-time" || entry.Data != nil || len(entry.Issues) != 1 {
				t.Fatalf("corrupt entry lost identity/issues: %#v", entry)
			}
			issue := entry.Issues[0]
			if issue.Component != "configuration" || issue.Message != "machine.created_at: native DTO conversion failed (InvalidCreateRequest)" {
				t.Fatalf("unstable timestamp issue: %#v", issue)
			}
			if strings.Contains(issue.Message, home) || strings.Contains(issue.Message, "9223372036854775806") {
				t.Fatalf("inventory issue leaked stored values: %#v", issue)
			}
		}
	}
	if !foundHealthy || !foundBad {
		t.Fatal("indexed identity missing", entries)
	}
	if _, err := bad.Inspect(ctx); !IsErrorKind(err, ErrorInvalidCreateRequest) || !strings.Contains(err.Error(), "machine.created_at") {
		t.Fatalf("Inspect must retain timestamp error: %v", err)
	}
	duplicate, err := r.CreateMachine(ctx, DiskImage(disk), WithName("reserved-corrupt-time"))
	if duplicate != nil {
		_ = duplicate.Close()
	}
	if !IsErrorKind(err, ErrorMachineAlreadyExists) {
		t.Fatalf("corrupt timestamp must retain indexed name reservation: %v", err)
	}
	if _, err := healthy.Inspect(ctx); err != nil {
		t.Fatalf("healthy neighbor became inoperable: %v", err)
	}
	// A schema failure affects the database as a whole, not one entry, and must
	// still propagate through inventory rather than being disguised as issues.
	output, err = exec.Command(python, "-c", `import sqlite3,sys
db=sqlite3.connect(sys.argv[1])
db.execute("DROP TABLE machine_config")
db.commit()`, filepath.Join(home, "state.db")).CombinedOutput()
	if err != nil {
		t.Fatalf("break temp database schema: %v %s", err, output)
	}
	if entries, err := r.Inventory(ctx); !IsErrorKind(err, ErrorDatabase) || entries != nil {
		t.Fatalf("global database failure must remain fatal: %#v %v", entries, err)
	}
}
