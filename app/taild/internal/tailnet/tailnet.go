package tailnet

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"time"

	_ "github.com/vandycknick/silo/app/taild/internal/bootenv"
	"github.com/vandycknick/silo/app/taild/internal/config"
	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/state"
	"tailscale.com/client/local"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tsnet"
)

type Node struct {
	Server   *tsnet.Server
	Client   *local.Client
	config   config.Config
	defaults identity.Limits
	log      *slog.Logger
}

func Start(ctx context.Context, c config.Config, secrets config.Secrets, log *slog.Logger) (*Node, error) {
	dir := filepath.Join(c.Home, "taild", "tsnet")
	if e := state.PrivateDir(dir); e != nil {
		return nil, e
	}
	authKey := ""
	// Reuse enrolled service state; never mint on every daemon restart.
	_, existing := state.ReadNode(dir, c.Tailnet.Hostname, identity.Principal(c.Tailnet.Tag))
	if secrets.ClientSecret != "" && existing != state.Enrolled {
		client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		var e error
		authKey, e = Mint(ctx, client, "https://api.tailscale.com", secrets.ClientSecret, c.Tailnet.Tag)
		if e != nil {
			return nil, e
		}
	}
	defaults, e := c.Limits()
	if e != nil {
		return nil, e
	}
	n := &Node{config: c, defaults: defaults, log: log}
	n.Server = &tsnet.Server{Dir: dir, Hostname: c.Tailnet.Hostname, AuthKey: authKey, AdvertiseTags: []string{c.Tailnet.Tag}, ControlURL: c.Tailnet.ControlURL, UserLogf: func(format string, args ...any) { log.Info("tailnet", "message", fmt.Sprintf(format, args...)) }}
	if e = n.Server.Start(); e != nil {
		return nil, e
	}
	n.Client, e = n.Server.LocalClient()
	if e != nil {
		n.Server.Close()
		return nil, e
	}
	return n, nil
}
func (n *Node) WaitReady(ctx context.Context) error {
	for {
		attempt, cancel := context.WithTimeout(ctx, time.Minute)
		status, e := n.Server.Up(attempt)
		cancel()
		if e == nil {
			if e = n.verify(status); e == nil {
				return nil
			}
			if status != nil && status.CurrentTailnet != nil && status.CurrentTailnet.Name != "" {
				if pinErr := state.PinTailnet(n.config.Home, status.CurrentTailnet.Name); pinErr != nil {
					return pinErr
				}
			}
			n.log.Info("waiting for tagged service node", "reason", e)
		} else {
			n.log.Info("waiting for tailnet login", "reason", e)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}
func (n *Node) verify(s *ipnstate.Status) error {
	if s == nil || s.BackendState != "Running" || s.Self == nil || s.CurrentTailnet == nil || s.CurrentTailnet.Name == "" {
		return errors.New("tailnet not ready")
	}
	if e := state.PinTailnet(n.config.Home, s.CurrentTailnet.Name); e != nil {
		return e
	}
	if s.Self.Tags == nil || !slices.Contains(s.Self.Tags.AsSlice(), n.config.Tailnet.Tag) {
		return errors.New("node not tagged")
	}
	return nil
}
func (n *Node) WhoIs(ctx context.Context, remote string) (identity.Peer, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	status, e := n.Client.StatusWithoutPeers(ctx)
	if e != nil {
		return identity.Peer{}, errors.New("tailnet status unavailable")
	}
	if e = n.verify(status); e != nil {
		return identity.Peer{}, e
	}
	who, e := n.Client.WhoIs(ctx, remote)
	if e != nil {
		return identity.Peer{}, errors.New("WhoIs unavailable")
	}
	return identity.FromWhoIs(who, n.config.Tailnet.Capability, n.defaults, n.log)
}
func (n *Node) Close() error { return n.Server.Close() }

func (n *Node) Status(ctx context.Context) (*ipnstate.Status, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	status, err := n.Client.Status(ctx)
	if err != nil {
		return nil, errors.New("tailnet status unavailable")
	}
	if err = n.verify(status); err != nil {
		return nil, err
	}
	return status, nil
}

func (n *Node) VisibleNames(ctx context.Context) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	status, e := n.Client.Status(ctx)
	if e != nil {
		return nil, e
	}
	if e = n.verify(status); e != nil {
		return nil, e
	}
	names := []string{}
	add := func(peer *ipnstate.PeerStatus) {
		if peer == nil {
			return
		}
		dns := strings.TrimSuffix(strings.ToLower(peer.DNSName), ".")
		name, _, _ := strings.Cut(dns, ".")
		if name != "" {
			names = append(names, name)
		}
	}
	add(status.Self)
	for _, peer := range status.Peer {
		add(peer)
	}
	return names, nil
}
