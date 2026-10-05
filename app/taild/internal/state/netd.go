package state

import (
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// NetdStatus mirrors the v1 observation file published by netd. It carries no
// credentials. Live fields require a matching run and recent observation;
// LastKnown is historical display metadata only.
type NetdStatus struct {
	LastKnown      *NodeObservation `json:"last_known,omitempty"`
	Tags           []string         `json:"tags,omitempty"`
	Version        int              `json:"version"`
	VMID           string           `json:"vm_id"`
	RunID          string           `json:"run_id"`
	ObservedAt     time.Time        `json:"observed_at"`
	State          string           `json:"state"`
	ApprovalURL    string           `json:"approval_url,omitempty"`
	NodeID         string           `json:"node_id,omitempty"`
	DNSName        string           `json:"dns_name,omitempty"`
	ErrorCode      string           `json:"error_code,omitempty"`
	Addresses      []netip.Addr     `json:"addresses,omitempty"`
	KeyExpiry      *time.Time       `json:"key_expiry,omitempty"`
	KeyExpiryKnown bool             `json:"key_expiry_known"`
}

type NodeObservation struct {
	ObservedAt time.Time  `json:"observed_at"`
	Owner      string     `json:"owner,omitempty"`
	Tailnet    string     `json:"tailnet"`
	NodeID     string     `json:"node_id"`
	DNSName    string     `json:"dns_name"`
	Tags       []string   `json:"tags,omitempty"`
	KeyExpiry  *time.Time `json:"key_expiry,omitempty"`
}

func ReadNetdStatus(dir, vm, run string, now time.Time) (NetdStatus, error) {
	v, err := readNetdSnapshot(dir, vm)
	if err != nil {
		return NetdStatus{}, err
	}
	if run == "" || v.RunID != run || v.ObservedAt.IsZero() || v.ObservedAt.After(now.Add(5*time.Second)) || now.Sub(v.ObservedAt) > time.Minute {
		return NetdStatus{}, errors.New("live node status unavailable")
	}
	return v, nil
}

// ReadNodeObservation never exposes a previous run's status or approval URL.
func ReadNodeObservation(dir, vm string, now time.Time) (*NodeObservation, error) {
	v, err := readNetdSnapshot(dir, vm)
	if err != nil {
		return nil, err
	}
	o := v.LastKnown
	if o == nil || o.ObservedAt.IsZero() || o.ObservedAt.After(now.Add(5*time.Second)) || o.ObservedAt.After(v.ObservedAt) || o.NodeID == "" || o.DNSName == "" {
		return nil, errors.New("node observation unavailable")
	}
	return o, nil
}

func readNetdSnapshot(dir, vm string) (NetdStatus, error) {
	var v NetdStatus
	invalid := errors.New("live node status unavailable")
	root, err := os.OpenRoot(filepath.Dir(dir))
	if err != nil {
		return v, invalid
	}
	defer root.Close()
	f, err := root.OpenFile(filepath.Base(dir)+".status.json", os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return v, invalid
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 4096 {
		return v, invalid
	}
	var stat unix.Stat_t
	if unix.Fstat(int(f.Fd()), &stat) != nil || stat.Uid != uint32(os.Geteuid()) {
		return v, invalid
	}
	b, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(b) > 4096 || json.Unmarshal(b, &v) != nil || v.Version != 1 || v.VMID != vm {
		return NetdStatus{}, invalid
	}
	switch v.State {
	case "connecting", "approval_required", "ready", "disconnected", "failed", "stopped":
	default:
		return NetdStatus{}, invalid
	}
	if v.ApprovalURL != "" {
		u, err := url.Parse(v.ApprovalURL)
		if err != nil || len(v.ApprovalURL) > 1000 || u.Scheme != "https" || u.Host == "" || u.User != nil || strings.ContainsAny(v.ApprovalURL, "\r\n\x1b") || v.State != "approval_required" {
			return NetdStatus{}, invalid
		}
	}
	return v, nil
}
