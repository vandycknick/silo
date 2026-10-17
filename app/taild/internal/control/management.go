package control

import (
	"context"
	"io"
	"time"

	"github.com/google/uuid"
	silo "github.com/vandycknick/silo/sdk/go"
	w "github.com/vandycknick/silo/specs/protocol/go/silo/daemon/v1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/emptypb"
)

// Snapshot owns a pure public SDK-data projection. Network.Policy is deliberately
// nil: canonical policy and authoritative observations never require native parsing.
type Snapshot struct {
	*silo.MachineData
	PolicyJSON         string
	NetworkObservation *w.NetworkObservation
}
type InventoryEntry struct {
	ID, Name string
	Data     *Snapshot
	Issues   []silo.MachineIssue
}
type Policy struct {
	CanonicalJSON, HCL string
	Secrets            silo.NetworkSecretMetadata
}
type StartResult struct {
	RunID string
	Data  *Snapshot
}
type ReadinessResult struct {
	Outcome w.ReadinessOutcome
	Data    *Snapshot
}

func reference(ref string) *w.MachineRef {
	if id, err := uuid.Parse(ref); err == nil {
		return &w.MachineRef{Reference: &w.MachineRef_Id{Id: id.String()}}
	}
	return &w.MachineRef{Reference: &w.MachineRef_Name{Name: ref}}
}
func (c *Client) Inventory(ctx context.Context) ([]InventoryEntry, error) {
	stream, err := c.Machines.ListMachines(ctx, &emptypb.Empty{})
	if err != nil {
		return nil, rpcError(ctx, err)
	}
	entries := []InventoryEntry{}
	for {
		v, err := stream.Recv()
		if err == io.EOF {
			return entries, nil
		}
		if err != nil {
			return nil, rpcError(ctx, err)
		}
		if v == nil {
			return nil, invalidResponse()
		}
		issues, err := convertIssues(v.Issues)
		if err != nil {
			return nil, err
		}
		entry := InventoryEntry{ID: v.Id, Name: v.Name, Issues: issues}
		if v.Data != nil {
			entry.Data, err = convertSnapshot(v.Data)
			if err != nil {
				entry.Issues = append(entry.Issues, silo.MachineIssue{Component: "configuration", Message: "invalid daemon machine snapshot"})
			} else if entry.Data.ID != entry.ID || entry.Data.Name != entry.Name {
				entry.Data = nil
				entry.Issues = append(entry.Issues, silo.MachineIssue{Component: "configuration", Message: "inconsistent daemon inventory identity"})
			}
		}
		entries = append(entries, entry)
	}
}
func (c *Client) Inspect(ctx context.Context, ref string) (*Snapshot, error) {
	v, e := c.Machines.InspectMachine(ctx, reference(ref))
	if e != nil {
		return nil, rpcError(ctx, e)
	}
	return convertSnapshot(v)
}
func (c *Client) Create(ctx context.Context, spec *w.NormalizedMachineCreate, source *w.OciIdentity) (*Snapshot, error) {
	stream, e := c.Machines.CreateMachine(ctx, &w.CreateMachineRequest{Configuration: spec, Source: &w.CreateMachineRequest_Oci{Oci: source}})
	if e != nil {
		return nil, rpcError(ctx, e)
	}
	var result *Snapshot
	for {
		v, e := stream.Recv()
		if e == io.EOF {
			if result == nil {
				return nil, invalidResponse()
			}
			return result, nil
		}
		if e != nil {
			return nil, rpcError(ctx, e)
		}
		if v == nil || result != nil {
			return nil, invalidResponse()
		}
		switch event := v.Event.(type) {
		case *w.CreateMachineEvent_Machine:
			result, e = convertSnapshot(event.Machine)
			if e != nil {
				return nil, e
			}
		case *w.CreateMachineEvent_Progress:
			if event.Progress == nil || event.Progress.Event == nil {
				return nil, invalidResponse()
			}
		default:
			return nil, invalidResponse()
		}
	}
}
func (c *Client) Start(ctx context.Context, id string) (StartResult, error) {
	v, e := c.Machines.StartMachine(ctx, &w.StartMachineRequest{Machine: reference(id), Options: &w.StartOptions{}})
	if e != nil {
		return StartResult{}, rpcError(ctx, e)
	}
	if v == nil || v.RunId == "" {
		return StartResult{}, invalidResponse()
	}
	d, e := convertSnapshot(v.Data)
	if e == nil && (d.RunID == nil || *d.RunID != v.RunId) {
		e = invalidResponse()
	}
	return StartResult{RunID: v.RunId, Data: d}, e
}
func (c *Client) Stop(ctx context.Context, id string, expectedRun *string, options silo.StopOptions) (*Snapshot, error) {
	var timeout *durationpb.Duration
	if options.Timeout != 0 {
		timeout = durationpb.New(options.Timeout)
	}
	v, e := c.Machines.StopMachine(ctx, &w.StopMachineRequest{Machine: reference(id), Force: options.Force, Timeout: timeout, ExpectedRun: expectedRun})
	if e != nil {
		return nil, rpcError(ctx, e)
	}
	return convertSnapshot(v)
}
func (c *Client) Remove(ctx context.Context, id string) error {
	_, e := c.Machines.RemoveMachine(ctx, &w.RemoveMachineRequest{Machine: reference(id)})
	return rpcError(ctx, e)
}
func (c *Client) Update(ctx context.Context, id string, update *w.MachineUpdate) (*Snapshot, error) {
	v, e := c.Machines.UpdateMachine(ctx, &w.UpdateMachineRequest{Machine: reference(id), Update: update})
	if e != nil {
		return nil, rpcError(ctx, e)
	}
	return convertSnapshot(v)
}
func (c *Client) WaitReady(ctx context.Context, id, run string, timeout time.Duration) (ReadinessResult, error) {
	v, e := c.Machines.WaitReady(ctx, &w.WaitReadyRequest{Id: id, ExpectedRun: &run, Timeout: durationpb.New(timeout)})
	if e != nil {
		return ReadinessResult{}, rpcError(ctx, e)
	}
	if v == nil || v.Outcome < 1 || v.Outcome > 3 {
		return ReadinessResult{}, invalidResponse()
	}
	d, e := convertSnapshot(v.Data)
	return ReadinessResult{Outcome: v.Outcome, Data: d}, e
}
func (c *Client) SetSecret(ctx context.Context, id, name string, value []byte) error {
	_, e := c.Machines.SetMachineSecret(ctx, &w.SetMachineSecretRequest{Id: id, Name: name, Value: value})
	return rpcError(ctx, e)
}
func (c *Client) ResolveImage(ctx context.Context, reference string, policy w.PullPolicy) (*w.ResolvedImage, error) {
	stream, e := c.Runtime.ResolveImage(ctx, &w.ResolveImageRequest{Reference: reference, PullPolicy: policy})
	if e != nil {
		return nil, rpcError(ctx, e)
	}
	var result *w.ResolvedImage
	for {
		v, e := stream.Recv()
		if e == io.EOF {
			if result == nil {
				return nil, invalidResponse()
			}
			return result, nil
		}
		if e != nil {
			return nil, rpcError(ctx, e)
		}
		if v == nil || result != nil {
			return nil, invalidResponse()
		}
		switch event := v.Event.(type) {
		case *w.ResolveImageEvent_Image:
			result = event.Image
			if result == nil || result.Identity == nil || result.Identity.PullPolicy < 1 || result.Identity.PullPolicy > 3 || result.CacheState < 1 || result.CacheState > 2 {
				return nil, invalidResponse()
			}
		case *w.ResolveImageEvent_Progress:
			if event.Progress == nil || event.Progress.Event == nil {
				return nil, invalidResponse()
			}
		default:
			return nil, invalidResponse()
		}
	}
}
func (c *Client) PullImage(ctx context.Context, reference string) error {
	stream, e := c.Runtime.PullImage(ctx, &w.PullImageRequest{Reference: reference})
	if e != nil {
		return rpcError(ctx, e)
	}
	complete := false
	for {
		v, e := stream.Recv()
		if e == io.EOF {
			if !complete {
				return invalidResponse()
			}
			return nil
		}
		if e != nil {
			return rpcError(ctx, e)
		}
		if v == nil || v.Event == nil || complete {
			return invalidResponse()
		}
		_, complete = v.Event.(*w.ImageProgress_Complete)
	}
}
func (c *Client) ProposeMachineName(ctx context.Context) (string, error) {
	v, e := c.Runtime.ProposeMachineName(ctx, &emptypb.Empty{})
	if e != nil {
		return "", rpcError(ctx, e)
	}
	if v == nil || v.Name == "" {
		return "", invalidResponse()
	}
	return v.Name, nil
}
func (c *Client) ParseResource(ctx context.Context, kind w.ResourceKind, text string) (silo.ByteSize, error) {
	v, e := c.Runtime.ParseResource(ctx, &w.ParseResourceRequest{Kind: kind, Value: text})
	if e != nil {
		return silo.ByteSize{}, rpcError(ctx, e)
	}
	if v == nil {
		return silo.ByteSize{}, invalidResponse()
	}
	return silo.Bytes(v.Bytes), nil
}
func (c *Client) NormalizePolicy(ctx context.Context, input *w.NormalizePolicyRequest) (*Policy, error) {
	v, e := c.Runtime.NormalizePolicy(ctx, input)
	if e != nil {
		return nil, rpcError(ctx, e)
	}
	if v == nil {
		return nil, invalidResponse()
	}
	secrets, e := convertSecrets(v.SecretSlots, v.SecretRequirements)
	if e != nil {
		return nil, e
	}
	return &Policy{CanonicalJSON: v.CanonicalJson, HCL: v.Hcl, Secrets: secrets}, nil
}
func (c *Client) CheckPolicySecrets(ctx context.Context, policy *Policy, machineID string) (*w.PolicySecretsResult, error) {
	if policy == nil {
		return nil, &silo.Error{Kind: silo.ErrorInvalidArgument, Message: "policy is required"}
	}
	request := &w.CheckPolicySecretsRequest{PolicyJson: policy.CanonicalJSON}
	if machineID != "" {
		request.MachineId = &machineID
	}
	v, e := c.Runtime.CheckPolicySecrets(ctx, request)
	if e != nil {
		return nil, rpcError(ctx, e)
	}
	if v == nil || v.State < 1 || v.State > 3 {
		return nil, invalidResponse()
	}
	if _, e = convertSecrets(v.Slots, v.Requirements); e != nil {
		return nil, e
	}
	for _, d := range v.Diagnostics {
		if d == nil {
			return nil, invalidResponse()
		}
	}
	return v, nil
}

type LogStream struct {
	ctx    context.Context
	stream grpc.ServerStreamingClient[w.LogChunk]
}

func (c *Client) ReadLogs(ctx context.Context, request *w.ReadLogsRequest) (*LogStream, error) {
	s, e := c.Machines.ReadLogs(ctx, request)
	if e != nil {
		return nil, rpcError(ctx, e)
	}
	return &LogStream{ctx: ctx, stream: s}, nil
}
func (s *LogStream) Recv() (*w.LogChunk, error) {
	v, e := s.stream.Recv()
	if e != nil {
		return nil, rpcError(s.ctx, e)
	}
	if v == nil || v.Source < 1 || v.Source > 6 || v.Output < 1 || v.Output > 3 {
		return nil, invalidResponse()
	}
	return v, nil
}

// RemoveAfterRun retains the observed generation fence through deletion.
func (c *Client) RemoveAfterRun(ctx context.Context, id, run string) error {
	_, e := c.Machines.RemoveAfterRun(ctx, &w.MachineRunRef{Id: id, RunId: run})
	return rpcError(ctx, e)
}
