package authz

import (
	"github.com/vandycknick/silo/app/taild/internal/identity"
)

type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Exit    int    `json:"-"`
}

func (e *Error) Error() string { return e.Message }

type VM struct {
	Owner    identity.Principal
	Instance string
}

func Allow(peer identity.Peer, action identity.Action, vm *VM) error {
	if !peer.Valid() {
		return &Error{"forbidden", "verified identity required", 4}
	}
	if vm != nil && !peer.Owns(vm.Owner) {
		return &Error{"not_found", "VM not found", 3}
	}
	if action == identity.Restart {
		if !peer.Permissions.Has(identity.Stop) || !peer.Permissions.Has(identity.Start) {
			return &Error{"forbidden", "requires vm.stop and vm.start", 4}
		}
	} else if !peer.Permissions.Has(action) {
		return &Error{"forbidden", "capability does not grant " + string(action), 4}
	}
	return nil
}
