package router

import (
	"context"
	"log/slog"

	"github.com/nickvan/bentobox/net/bento-netd/internal/gateway/audit"
	"github.com/nickvan/bentobox/net/bento-netd/internal/gateway/hooks"
)

type Router struct {
	hook  hooks.Hook
	audit *audit.Logger
}

func New(hook hooks.Hook, audit *audit.Logger) *Router {
	return &Router{hook: hook, audit: audit}
}

func (r *Router) Decide(ctx context.Context, flow hooks.Flow) (hooks.RouteDecision, error) {
	decision, err := r.hook.Decide(ctx, flow)
	if err != nil {
		return hooks.RouteDecision{}, err
	}
	r.audit.Record(flow, decision)
	slog.Info("network flow decision",
		"action", decision.Action,
		"reason", decision.Reason,
		"rule_name", decision.RuleName,
		"protocol", flow.Protocol,
		"source_ip", flow.SourceIP.String(),
		"source_port", flow.SourcePort,
		"dest_ip", flow.DestIP.String(),
		"dest_port", flow.DestPort,
		"vm_id", flow.VMID,
		"network_id", flow.NetworkID,
		"profile", flow.ProfileName,
	)
	return decision, nil
}
