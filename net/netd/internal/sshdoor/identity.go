// Package sshdoor terminates tailnet SSH and relays authorized connections to
// the guest. Offline callers exercise the relay with already-authorized metadata.
package sshdoor

import (
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"
	"tailscale.com/client/local"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/ipn/ipnstate"
)

type Identity struct {
	Login  string
	Node   string
	UserID string
}

// Owner never treats a tagged node's creator as its owner.
func Owner(peer *apitype.WhoIsResponse, status *ipnstate.Status) (Identity, error) {
	deny := errors.New("not the owner of this VM")
	if peer == nil || peer.Node == nil {
		return Identity{}, deny
	}
	id := Identity{Node: string(peer.Node.StableID)}
	if len(peer.Node.Tags) != 0 {
		id.Login = "node:" + id.Node
	} else if peer.UserProfile != nil {
		id.Login = peer.UserProfile.LoginName
		id.UserID = fmt.Sprint(peer.UserProfile.ID)
	}
	if status == nil || status.BackendState != "Running" || status.Self == nil {
		return id, deny
	}
	if id.Node == "" {
		return id, deny
	}
	if status.Self.Tags != nil && status.Self.Tags.Len() != 0 {
		for _, a := range status.Self.Tags.AsSlice() {
			for _, b := range peer.Node.Tags {
				if a == b {
					id.Login = "node:" + id.Node
					return id, nil
				}
			}
		}
		return id, deny
	}
	if len(peer.Node.Tags) != 0 || peer.UserProfile == nil || status.Self.UserID == 0 || peer.UserProfile.ID != status.Self.UserID || peer.Node.User != peer.UserProfile.ID {
		return id, deny
	}
	id.Login = peer.UserProfile.LoginName
	id.UserID = fmt.Sprint(peer.UserProfile.ID)
	if id.Login == "" {
		return id, deny
	}
	return id, nil
}

func boundedWhoIs(ctx context.Context, client *local.Client, remote string) (Identity, error) {
	if client == nil {
		return Identity{}, errors.New("tailnet identity unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	peer, err := client.WhoIs(ctx, remote)
	if err != nil {
		return Identity{}, err
	}
	status, err := client.Status(ctx)
	if err != nil {
		id, _ := Owner(peer, nil)
		return id, err
	}
	return Owner(peer, status)
}

func permissions(id Identity) *ssh.Permissions {
	return &ssh.Permissions{Extensions: map[string]string{"silo.login": id.Login, "silo.node": id.Node, "silo.user_id": id.UserID}}
}
