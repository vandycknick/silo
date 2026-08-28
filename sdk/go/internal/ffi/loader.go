//go:build cgo && (linux || darwin)

package ffi

import (
	"fmt"
	"sync"

	"github.com/vandycknick/silo/sdk/go/internal/bundle"
)

var bridgeLoader struct {
	once sync.Once
	err  error
}

// Load validates and pins the exact native bridge for this SDK.
func Load(expectedVersion string, expectedABI uint32) error {
	bridgeLoader.once.Do(func() {
		path, err := bundle.Path()
		if err != nil {
			bridgeLoader.err = fmt.Errorf("locate native Silo bridge: %w", err)
			return
		}
		bridgeLoader.err = load(path, expectedVersion, expectedABI)
	})
	return bridgeLoader.err
}

// OpenRuntime opens libvm using a bridge-owned JSON request.
func OpenRuntime(request []byte) (*Runtime, error) { return openRuntime(request) }
