// Package control owns taild's same-user daemon management transport. Guest
// execution stays in the native SDK; this package never opens a VM handle.
package control

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"

	daemonv1 "github.com/vandycknick/silo/specs/protocol/go/silo/daemon/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"
)

const HelperGenerationHeader = "x-silo-helper-generation"
const MaxMessageBytes = 16 << 20

// Client exposes owned protobuf snapshots and immutable IDs, not closable native
// machines. Close releases only the local management connection.
type Client struct {
	Daemon     daemonv1.DaemonServiceClient
	Machines   daemonv1.MachineServiceClient
	Networks   daemonv1.NetworkServiceClient
	Runtime    daemonv1.RuntimeServiceClient
	connection *grpc.ClientConn
}

// New validates the private local endpoint. Callers perform GetStatus admission
// before using the client; New does not claim the remote daemon is ready.
func New(endpoint, helperGeneration string) (*Client, error) {
	if !filepath.IsAbs(endpoint) {
		return nil, fmt.Errorf("control endpoint must be absolute")
	}
	if err := validateEndpoint(endpoint); err != nil {
		return nil, err
	}
	tag := func(ctx context.Context) context.Context {
		if helperGeneration == "" {
			return ctx
		}
		return metadata.AppendToOutgoingContext(ctx, HelperGenerationHeader, helperGeneration)
	}
	connection, err := grpc.NewClient("passthrough:///silod",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDisableRetry(),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(MaxMessageBytes), grpc.MaxCallSendMsgSize(MaxMessageBytes)),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			if err := validateEndpoint(endpoint); err != nil {
				return nil, err
			}
			return (&net.Dialer{}).DialContext(ctx, "unix", endpoint)
		}),
		grpc.WithUnaryInterceptor(func(ctx context.Context, method string, request, response interface{}, cc *grpc.ClientConn, invoke grpc.UnaryInvoker, options ...grpc.CallOption) error {
			return invoke(tag(ctx), method, request, response, cc, options...)
		}),
		grpc.WithStreamInterceptor(func(ctx context.Context, description *grpc.StreamDesc, cc *grpc.ClientConn, method string, stream grpc.Streamer, options ...grpc.CallOption) (grpc.ClientStream, error) {
			return stream(tag(ctx), description, cc, method, options...)
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("open daemon management transport: %w", err)
	}
	return &Client{
		Daemon:     daemonv1.NewDaemonServiceClient(connection),
		Machines:   daemonv1.NewMachineServiceClient(connection),
		Networks:   daemonv1.NewNetworkServiceClient(connection),
		Runtime:    daemonv1.NewRuntimeServiceClient(connection),
		connection: connection,
	}, nil
}

func (c *Client) Close() error { return c.connection.Close() }

// Admit verifies the bootstrap-selected daemon before any management operation.
// A mismatch is never a reason to switch to native lifecycle calls.
func (c *Client) Admit(ctx context.Context, productVersion, generation, home, configDir string) (*daemonv1.DaemonStatus, error) {
	status, err := c.Daemon.GetStatus(ctx, &emptypb.Empty{})
	if err != nil {
		return nil, fmt.Errorf("inspect daemon identity: %w", err)
	}
	if status.ProtocolMajor != 1 || status.ProductVersion != productVersion {
		return nil, fmt.Errorf("daemon management product/protocol mismatch")
	}
	if status.Generation != generation || string(status.Home) != home || string(status.ConfigDir) != configDir {
		return nil, fmt.Errorf("daemon management generation or Home/config identity mismatch")
	}
	return status, nil
}
func validateEndpoint(endpoint string) error {
	for _, path := range []string{filepath.Dir(endpoint), endpoint} {
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("inspect control endpoint: %w", err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || int(stat.Uid) != os.Geteuid() {
			return fmt.Errorf("control endpoint is not owned by current uid")
		}
		if path == endpoint {
			if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0600 {
				return fmt.Errorf("control endpoint must be a private 0600 socket")
			}
		} else if !info.IsDir() || info.Mode().Perm() != 0700 {
			return fmt.Errorf("control endpoint directory must be private 0700")
		}
	}
	return nil
}
