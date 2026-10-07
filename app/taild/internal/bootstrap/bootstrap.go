// Package bootstrap consumes the manager's one-use configuration and owner pipe.
package bootstrap

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/vandycknick/silo/app/taild/internal/config"
	"github.com/vandycknick/silo/app/taild/internal/units"
	silo "github.com/vandycknick/silo/sdk/go"
	daemonv1 "github.com/vandycknick/silo/specs/protocol/go/silo/daemon/v1"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
)

const MaxFrame = 64 << 10
const ReadTimeout = 10 * time.Second

type Mode uint8

const (
	Normal Mode = iota
	ShutdownOnly
)

// Input deliberately has no String or Debug representation of credentials.
type Input struct {
	Config           config.Config
	Secrets          config.Secrets
	DaemonGeneration string
	HelperGeneration string
	Endpoint         string
	ConfigDir        string
}

func (*Input) String() string     { return "managed helper bootstrap (credentials redacted)" }
func (i *Input) GoString() string { return i.String() }

// Read owns fd on success and failure. The returned pipe is also the lifeline.
func Read(ctx context.Context, fd int, mode Mode) (*Input, *os.File, error) {
	if fd < 0 {
		return nil, nil, errors.New("bootstrap descriptor is required")
	}
	var pipe *os.File
	defer func() {
		if pipe == nil {
			_ = unix.Close(fd)
		}
	}()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, nil, errors.New("invalid bootstrap descriptor")
	}
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil || stat.Mode&unix.S_IFMT != unix.S_IFIFO || flags&unix.O_ACCMODE != unix.O_RDONLY {
		return nil, nil, errors.New("bootstrap descriptor must be a read-only FIFO")
	}
	unix.CloseOnExec(fd)
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, nil, errors.New("cannot make bootstrap pipe nonblocking")
	}
	pipe = os.NewFile(uintptr(fd), "taild-owner")
	if pipe == nil {
		return nil, nil, errors.New("invalid bootstrap descriptor")
	}
	input, err := readFrame(ctx, pipe, ReadTimeout, mode)
	if err != nil {
		_ = pipe.Close()
		return nil, nil, err
	}
	return input, pipe, nil
}

func readFrame(ctx context.Context, pipe *os.File, timeout time.Duration, mode Mode) (*Input, error) {
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := pipe.SetReadDeadline(deadline); err != nil {
		return nil, errors.New("bootstrap pipe does not support deadlines")
	}
	stop := context.AfterFunc(ctx, func() { _ = pipe.SetReadDeadline(time.Now()) })
	defer stop()
	var header [4]byte
	if _, err := io.ReadFull(pipe, header[:]); err != nil {
		return nil, errors.New("bootstrap frame header incomplete or timed out")
	}
	length := binary.BigEndian.Uint32(header[:])
	if length == 0 || length > MaxFrame {
		return nil, errors.New("bootstrap frame length outside 1..64KiB")
	}
	buffer := make([]byte, int(length))
	defer clear(buffer)
	if _, err := io.ReadFull(pipe, buffer); err != nil {
		return nil, errors.New("bootstrap frame incomplete or timed out")
	}
	var wire daemonv1.HelperBootstrap
	defer func() { clear(wire.ClientSecret); clear(wire.OauthAppSecret); clear(wire.ApiToken) }()
	if err := proto.Unmarshal(buffer, &wire); err != nil {
		return nil, errors.New("invalid bootstrap protobuf")
	}
	input, err := Validate(&wire, mode)
	if err != nil {
		return nil, err
	}
	if err := pipe.SetReadDeadline(time.Time{}); err != nil {
		return nil, errors.New("cannot reset owner pipe deadline")
	}
	return input, nil
}

// Watch treats EOF, read failure, or unexpected post-frame bytes as owner loss.
func Watch(pipe *os.File, lost func()) func() {
	done := make(chan struct{})
	go func() {
		defer close(done)
		var byte [1]byte
		_, _ = pipe.Read(byte[:])
		lost()
	}()
	return func() { _ = pipe.Close(); <-done }
}

func canonical(path []byte, directory bool) (string, error) {
	value := string(path)
	if !utf8.Valid(path) || strings.IndexByte(value, 0) >= 0 || !filepath.IsAbs(value) || filepath.Clean(value) != value {
		return "", errors.New("bootstrap paths must be canonical absolute paths")
	}
	resolved, err := filepath.EvalSymlinks(value)
	if err != nil || resolved != value {
		return "", errors.New("bootstrap path missing or noncanonical")
	}
	info, err := os.Stat(value)
	if err != nil || directory && !info.IsDir() || !directory && !info.Mode().IsRegular() {
		return "", errors.New("bootstrap asset has incorrect file type")
	}
	return value, nil
}

func Validate(w *daemonv1.HelperBootstrap, mode Mode) (*Input, error) {
	if mode != Normal && mode != ShutdownOnly {
		return nil, errors.New("invalid bootstrap mode")
	}
	if mode == ShutdownOnly && (w.RuntimeComponents != nil || len(w.NativeBridgePath) != 0 || len(w.TemplatesDir) != 0 || len(w.PoliciesDir) != 0 || w.ClientSecret != nil || w.OauthAppSecret != nil || w.ApiToken != nil) {
		return nil, errors.New("shutdown bootstrap must not contain native assets or credentials")
	}
	if w.ProtocolMajor != 1 || w.ProductVersion != silo.Version {
		return nil, errors.New("bootstrap product/protocol mismatch")
	}
	for _, generation := range []string{w.DaemonGeneration, w.HelperGeneration} {
		id, err := uuid.Parse(generation)
		if err != nil || id == uuid.Nil || id.String() != generation {
			return nil, errors.New("bootstrap generation must be a canonical UUID")
		}
	}
	for _, value := range [][]byte{w.ClientSecret, w.OauthAppSecret, w.ApiToken} {
		if err := validateCredential(value); err != nil {
			return nil, err
		}
	}
	input := &Input{DaemonGeneration: w.DaemonGeneration, HelperGeneration: w.HelperGeneration}
	var err error
	input.Config.Home, err = canonical(w.Home, true)
	if err != nil {
		return nil, err
	}
	if _, err = config.ResolveHome(input.Config.Home, os.Geteuid()); err != nil {
		return nil, err
	}
	input.ConfigDir, err = canonical(w.ConfigDir, true)
	if err != nil {
		return nil, err
	}
	for _, root := range []struct {
		source []byte
		target *string
	}{{w.TemplatesDir, &input.Config.TemplatesDir}, {w.PoliciesDir, &input.Config.PoliciesDir}} {
		if len(root.source) != 0 {
			*root.target, err = canonical(root.source, true)
			if err != nil {
				return nil, err
			}
		}
	}
	input.Endpoint = string(w.ControlEndpoint)
	if !utf8.Valid(w.ControlEndpoint) || strings.IndexByte(input.Endpoint, 0) >= 0 || !filepath.IsAbs(input.Endpoint) || filepath.Clean(input.Endpoint) != input.Endpoint {
		return nil, errors.New("invalid bootstrap control endpoint")
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(input.Endpoint))
	if err != nil || parent != filepath.Dir(input.Endpoint) {
		return nil, errors.New("noncanonical control endpoint directory")
	}
	if mode == ShutdownOnly {
		if err := shutdownSettings(&input.Config, w.Settings); err != nil {
			return nil, err
		}
		return input, nil
	}
	if w.RuntimeComponents == nil {
		return nil, errors.New("bootstrap runtime components required")
	}
	r := w.RuntimeComponents
	c := &input.Config.Components
	for i, asset := range []struct {
		source []byte
		target *string
	}{{r.SupervisorPath, &c.SupervisorPath}, {r.NetdPath, &c.NetdPath}, {r.KernelPath, &c.KernelPath}, {r.InitramfsPath, &c.InitramfsPath}, {r.AgentPath, &c.AgentPath}, {r.AssetDir, &c.AssetDir}} {
		*asset.target, err = canonical(asset.source, i == 5)
		if err != nil {
			return nil, err
		}
		if i == 0 || i == 1 || i == 4 {
			info, err := os.Stat(*asset.target)
			if err != nil || info.Mode().Perm()&0111 == 0 {
				return nil, errors.New("bootstrap runtime executable is not executable")
			}
		}
	}
	input.Config.BridgePath, err = canonical(w.NativeBridgePath, false)
	if err != nil {
		return nil, err
	}
	executable, err := os.Executable()
	if err != nil {
		return nil, errors.New("cannot identify helper executable")
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return nil, errors.New("cannot canonicalize helper executable")
	}
	name := "libsilo_go_ffi.so"
	if runtime.GOOS == "darwin" {
		name = "libsilo_go_ffi.dylib"
	}
	if input.Config.BridgePath != filepath.Join(filepath.Dir(executable), name) {
		return nil, errors.New("native bridge must be product-owned adjacent helper asset")
	}
	bridgeInfo, err := os.Stat(input.Config.BridgePath)
	if err != nil {
		return nil, errors.New("native bridge unavailable")
	}
	bridgeStat, ok := bridgeInfo.Sys().(*syscall.Stat_t)
	if !ok || int(bridgeStat.Uid) != os.Geteuid() && bridgeStat.Uid != 0 || bridgeInfo.Mode().Perm()&0022 != 0 {
		return nil, errors.New("native bridge has unsafe ownership or permissions")
	}
	if err := settings(&input.Config, w.Settings); err != nil {
		return nil, err
	}
	for _, credential := range []struct {
		value  []byte
		target *string
	}{{w.ClientSecret, &input.Secrets.ClientSecret}, {w.OauthAppSecret, &input.Secrets.AppSecret}, {w.ApiToken, &input.Secrets.APIToken}} {
		if credential.value == nil {
			continue
		}
		*credential.target = strings.TrimSpace(string(credential.value))
	}
	if input.Config.Enrollment.DisableKeyExpiry && input.Secrets.APIToken == "" {
		return nil, errors.New("disable_key_expiry requires api token")
	}
	return input, nil
}
func validateCredential(value []byte) error {
	if value == nil {
		return nil
	}
	if len(value) == 0 || len(value) > 16<<10 || !utf8.Valid(value) || strings.IndexByte(string(value), 0) >= 0 || strings.TrimSpace(string(value)) == "" {
		return errors.New("bootstrap credential empty, invalid or exceeds 16KiB")
	}
	return nil
}

func settings(c *config.Config, s *daemonv1.TailscaleSettings) error {
	if s == nil || s.Defaults == nil || s.Ceilings == nil || s.StopBudget == nil || s.ShutdownMargin == nil {
		return errors.New("fully resolved bootstrap settings required")
	}
	if s.StopBudget.CheckValid() != nil || s.ShutdownMargin.CheckValid() != nil {
		return errors.New("invalid bootstrap shutdown duration")
	}
	c.Tailnet.Hostname, c.Tailnet.Tag, c.Tailnet.ControlURL = s.Hostname, s.Tag, s.ControlUrl
	c.Tailnet.Capability = "github.com/vandycknick/silo/cap/taild"
	switch s.EnrollmentMode {
	case daemonv1.EnrollmentMode_ENROLLMENT_MODE_OAUTH_APP:
		c.Enrollment.Mode = "oauth-app"
	case daemonv1.EnrollmentMode_ENROLLMENT_MODE_INTERACTIVE:
		c.Enrollment.Mode = "interactive"
	case daemonv1.EnrollmentMode_ENROLLMENT_MODE_NONE:
		c.Enrollment.Mode = "none"
	default:
		return errors.New("invalid bootstrap enrollment mode")
	}
	c.Enrollment.DisableKeyExpiry = s.DisableKeyExpiry
	c.VM.AllowedRegistries = s.AllowedRegistries
	c.VM.Defaults = config.Resources{CPUs: uint64(s.Defaults.Cpus), Memory: units.Size(s.Defaults.MemoryBytes), Disk: units.Size(s.Defaults.DiskBytes)}
	c.VM.Ceilings = config.Ceilings{Resources: config.Resources{CPUs: uint64(s.Ceilings.Cpus), Memory: units.Size(s.Ceilings.MemoryBytes), Disk: units.Size(s.Ceilings.DiskBytes)}, VMs: s.Ceilings.VmsPerPrincipal}
	if s.SessionsGlobal > uint64(^uint(0)>>1) || s.SessionsPerPeer > uint64(^uint(0)>>1) {
		return fmt.Errorf("bootstrap session limits overflow")
	}
	c.Sessions.Global, c.Sessions.PerPeer = int(s.SessionsGlobal), int(s.SessionsPerPeer)
	c.DiskReserve = units.Size(s.DiskReserveBytes)
	c.Shutdown.StopBudget = units.Duration{Duration: s.StopBudget.AsDuration()}
	c.Shutdown.Margin = units.Duration{Duration: s.ShutdownMargin.AsDuration()}
	return c.Validate()
}

func shutdownSettings(c *config.Config, s *daemonv1.TailscaleSettings) error {
	if s == nil || s.StopBudget == nil || s.ShutdownMargin == nil ||
		s.StopBudget.CheckValid() != nil || s.ShutdownMargin.CheckValid() != nil {
		return errors.New("valid shutdown settings required")
	}
	budget, margin := s.StopBudget.AsDuration(), s.ShutdownMargin.AsDuration()
	if budget <= 0 || budget > time.Minute || margin <= 0 || margin > time.Second {
		return errors.New("shutdown durations outside supported bounds")
	}
	c.Shutdown.StopBudget = units.Duration{Duration: budget}
	c.Shutdown.Margin = units.Duration{Duration: margin}
	return nil
}
