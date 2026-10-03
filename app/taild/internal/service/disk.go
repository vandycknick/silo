package service

import (
	"math"
	"sync"

	"github.com/vandycknick/silo/app/taild/internal/units"
	"golang.org/x/sys/unix"
)

// Admission reserves logical requested capacity, conservatively, although sparse
// disks consume allocated blocks. statfs Bavail counts blocks usable by this UID,
// excluding filesystem/root reserves; existing allocation is already reflected.
func (s *Service) diskAdmissionLocked(add uint64) error {
	floor, err := units.Bytes(s.Config.DiskReserve)
	if err != nil {
		return failure("unavailable", "disk reserve configuration unavailable", 9)
	}
	var stat unix.Statfs_t
	if err = unix.Statfs(s.Config.Home, &stat); err != nil {
		return failure("unavailable", "disk availability unavailable", 9)
	}
	if stat.Bsize <= 0 || stat.Bavail > math.MaxUint64/uint64(stat.Bsize) {
		return failure("unavailable", "disk availability invalid", 9)
	}
	available := stat.Bavail * uint64(stat.Bsize)
	needed := floor
	for _, size := range s.diskPending {
		if size > math.MaxUint64-needed {
			return failure("limit", "disk reserve admission exceeded", 6)
		}
		needed += size
	}
	if add > math.MaxUint64-needed || needed+add > available {
		return failure("limit", "disk free-space floor or concurrent reservations exceeded", 6)
	}
	return nil
}

func (s *Service) reserveDiskGrowth(id string, growth uint64) (func(), error) {
	s.createMu.Lock()
	defer s.createMu.Unlock()
	if err := s.diskAdmissionLocked(growth); err != nil {
		return nil, err
	}
	if s.diskPending == nil {
		s.diskPending = make(map[string]uint64)
	}
	key := "resize:" + id
	s.diskPending[key] = growth
	var once sync.Once
	return func() { once.Do(func() { s.createMu.Lock(); delete(s.diskPending, key); s.createMu.Unlock() }) }, nil
}
