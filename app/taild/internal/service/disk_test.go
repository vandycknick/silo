package service

import (
	"fmt"
	"math"
	"testing"

	"github.com/vandycknick/silo/app/taild/internal/config"
	"golang.org/x/sys/unix"
)

func TestActualFilesystemDiskReservationFloor(t *testing.T) {
	c := config.Defaults()
	c.Home = t.TempDir()
	var stat unix.Statfs_t
	if err := unix.Statfs(c.Home, &stat); err != nil {
		t.Fatal(err)
	}
	available := uint64(stat.Bavail) * uint64(stat.Bsize)
	if available < 256<<20 {
		t.Skip("insufficient filesystem space for admission test")
	}
	c.DiskReserve = fmt.Sprintf("%dB", available-(128<<20))
	s := &Service{Config: c, diskPending: map[string]uint64{}}
	if err := s.diskAdmissionLocked(512); err != nil {
		t.Fatal(err)
	}
	s.diskPending["first"] = 256 << 20
	if err := s.diskAdmissionLocked(1024); Categorize(err).Exit != 6 {
		t.Fatal("concurrent reservation admitted", err)
	}
	delete(s.diskPending, "first")
	if err := s.diskAdmissionLocked(512); err != nil {
		t.Fatal("release did not restore admission", err)
	}
	s.diskPending["overflow"] = math.MaxUint64
	if err := s.diskAdmissionLocked(1); Categorize(err).Exit != 6 {
		t.Fatal("reservation overflow", err)
	}
}
