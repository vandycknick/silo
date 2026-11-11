package enroll

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

type NodePin struct {
	Tailnet    string `json:"tailnet"`
	Suffix     string `json:"suffix"`
	ControlURL string `json:"control_url"`
}

// PinNodeControl publishes a complete file atomically without replacing an
// existing pin. Concurrent first writers must agree on the same identity.
func PinNodeControl(dir string, pin NodePin) error {
	pin.Suffix = canonicalDNS(pin.Suffix)
	pin.ControlURL = controlURL(pin.ControlURL)
	if pin.Tailnet == "" || pin.Suffix == "" {
		return errors.New("missing verified node control identity")
	}
	path := filepath.Join(dir, "control-pin.json")
	check := func() error {
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() > 4096 {
			return errors.New("node control pin unreadable")
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		b, err := io.ReadAll(io.LimitReader(f, 4097))
		if err != nil {
			return err
		}
		var old NodePin
		if len(b) > 4096 || json.Unmarshal(b, &old) != nil || old != pin {
			return errors.New("node control identity differs from pin")
		}
		return nil
	}
	if err := check(); !errors.Is(err, os.ErrNotExist) {
		return err
	}
	b, err := json.Marshal(pin)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".control-pin-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err = f.Write(b); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Link(f.Name(), path); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return check()
}
