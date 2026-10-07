package control_test

import (
	"context"
	"testing"

	"github.com/vandycknick/silo/app/taild/internal/service"
	"github.com/vandycknick/silo/app/taild/internal/testfixture"
	"github.com/vandycknick/silo/app/taild/internal/testfixture/daemon"
	silo "github.com/vandycknick/silo/sdk/go"
	w "github.com/vandycknick/silo/specs/protocol/go/silo/daemon/v1"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestActualManagementAdapters(t *testing.T) {
	root := testfixture.Path(t, "SILO_TEST_RUNTIME_ROOT", true)
	registry := testfixture.OCIRegistry(t, "")
	c := testfixture.Config()
	c.Home = t.TempDir()
	c.Components = testfixture.Components(root)
	n := daemon.Open(t, c, "instance", 1)
	ctx := context.Background()
	size, e := n.Control.ParseResource(ctx, w.ResourceKind_RESOURCE_KIND_MEMORY, "4GiB")
	if e != nil || size.Bytes() != 4*1024*1024*1024 {
		t.Fatalf("resource: %v %v", size, e)
	}
	policy, e := n.Control.NormalizePolicy(ctx, &w.NormalizePolicyRequest{Input: &w.NormalizePolicyRequest_Empty{Empty: &emptypb.Empty{}}})
	if e != nil || policy.CanonicalJSON == "" || policy.HCL == "" {
		t.Fatalf("normalize: %+v %v", policy, e)
	}
	secrets, e := n.Control.CheckPolicySecrets(ctx, policy, "")
	if e != nil || secrets.State != w.PolicySecretsState_POLICY_SECRETS_STATE_READY {
		t.Fatalf("secrets: %+v %v", secrets, e)
	}
	if e = n.Control.PullImage(ctx, registry.Reference); e != nil {
		t.Fatal(e)
	}
	image, e := n.Control.ResolveImage(ctx, registry.Reference, w.PullPolicy_PULL_POLICY_NEVER)
	if e != nil {
		t.Fatal(e)
	}
	if image.CacheState != w.CacheState_CACHE_STATE_COMPLETE || image.Identity.ManifestDigest == "" || image.Identity.ConfigDigest == "" {
		t.Fatal("image terminal identity incomplete")
	}
	name := "adapter-dev"
	d, e := n.Control.Create(ctx, &w.NormalizedMachineCreate{Name: &name, Retention: w.Retention_RETENTION_PERSISTENT, Process: &w.ProcessConfig{}, Network: &w.ResolvedNetwork{Attachment: &w.ResolvedNetwork_None{None: &emptypb.Empty{}}}, Agent: &w.Agent{Mode: &w.Agent_DefaultAgent{DefaultAgent: &emptypb.Empty{}}}}, image.Identity)
	if e != nil {
		t.Fatal(e)
	}
	if d.ID == "" || d.Name != name || d.Status.Kind != silo.MachineStatusStopped {
		t.Fatal("create did not return stopped terminal snapshot")
	}
	inspected, e := n.Control.Inspect(ctx, name)
	if e != nil || inspected.ID != d.ID {
		t.Fatalf("exact name inspect: %+v %v", inspected, e)
	}
	if e = n.Control.Remove(ctx, d.ID); e != nil {
		t.Fatal(e)
	}
	_, e = n.Control.Inspect(ctx, d.ID)
	if !silo.IsErrorKind(e, silo.ErrorMachineNotFound) {
		t.Fatalf("rich native error: %v", e)
	}
	category := service.Categorize(e)
	if category.Code != "not_found" || category.Exit != 3 {
		t.Fatalf("category: %+v", category)
	}
	_, invalid := n.Control.ParseResource(ctx, w.ResourceKind_RESOURCE_KIND_MEMORY, "not-a-size")
	if invalid == nil || service.Categorize(invalid).Code != "usage" {
		t.Fatalf("invalid resource category: %v", invalid)
	}
}
