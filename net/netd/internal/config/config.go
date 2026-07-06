package config

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"github.com/vandycknick/silo/net/netd/internal/policy"
)

type uint16Flags []uint16

func (f *uint16Flags) String() string { return fmt.Sprint([]uint16(*f)) }

func (f *uint16Flags) Set(value string) error {
	port, err := strconv.ParseUint(value, 10, 16)
	if err != nil {
		return fmt.Errorf("invalid port %q: %w", value, err)
	}
	*f = append(*f, uint16(port))
	return nil
}

type stringFlags []string

func (f *stringFlags) String() string { return strings.Join(*f, ",") }

func (f *stringFlags) Set(value string) error {
	*f = append(*f, value)
	return nil
}

type Config struct {
	ListenVfkit string
	PIDFile     string
	LogFile     string
	Stack       types.Configuration
	PolicyFile  string
	Policy      *policy.Policy
	TLS         TLSConfig
	Metadata    Metadata
}

type TLSConfig struct {
	CACert string
	CAKey  string
}

type Metadata struct {
	VMID      string
	NetworkID string
}

func Parse(args []string) (*Config, error) {
	cfg := &Config{}
	var subnet, pcapFile string
	var sshPort int

	flags := flag.NewFlagSet("netd", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&cfg.ListenVfkit, "listen-vfkit", "", "unixgram socket used by vfkit-compatible applications")
	flags.IntVar(&sshPort, "ssh-port", 2222, "guest SSH host forward port, or -1 to disable")
	flags.StringVar(&subnet, "subnet", "192.168.127.0/24", "guest network subnet")
	flags.StringVar(&cfg.PIDFile, "pid-file", "", "write process ID to this file")
	flags.StringVar(&cfg.LogFile, "log-file", "", "write logs to this file")
	flags.StringVar(&pcapFile, "pcap", "", "capture network traffic to a pcap file")
	flags.StringVar(&cfg.PolicyFile, "policy-file", "", "canonical network policy JSON file")
	flags.StringVar(&cfg.TLS.CACert, "tls-ca-cert", "", "CA certificate used for HTTPS interception")
	flags.StringVar(&cfg.TLS.CAKey, "tls-ca-key", "", "CA private key used for HTTPS interception")
	flags.StringVar(&cfg.Metadata.VMID, "vm-id", "", "VM identifier added to flow logs")
	flags.StringVar(&cfg.Metadata.NetworkID, "network-id", "", "network identifier added to flow logs")
	if err := flags.Parse(args); err != nil {
		return cfg, err
	}
	if cfg.ListenVfkit == "" {
		return cfg, errors.New("--listen-vfkit is required")
	}
	if !strings.HasPrefix(cfg.ListenVfkit, "unixgram://") {
		return cfg, errors.New("--listen-vfkit must use unixgram://")
	}
	stack, err := stackConfig(subnet, sshPort, pcapFile)
	if err != nil {
		return cfg, err
	}
	cfg.Stack = stack
	if (cfg.TLS.CACert == "") != (cfg.TLS.CAKey == "") {
		return cfg, errors.New("--tls-ca-cert and --tls-ca-key must be provided together")
	}
	return cfg, nil
}

func LoadPolicy(cfg *Config) error {
	if cfg == nil {
		return errors.New("missing configuration")
	}
	var compiledPolicy *policy.Policy
	var err error
	if cfg.PolicyFile != "" {
		compiledPolicy, err = policy.LoadFile(cfg.PolicyFile)
	} else {
		compiledPolicy = policy.Default()
	}
	if err != nil {
		return err
	}
	if compiledPolicy.HasHTTPS() {
		if cfg.TLS.CACert == "" || cfg.TLS.CAKey == "" {
			return errors.New("--tls-ca-cert and --tls-ca-key are required when policy contains https endpoints")
		}
	}
	cfg.Policy = compiledPolicy
	return nil
}

func stackConfig(subnetText string, sshPort int, pcapFile string) (types.Configuration, error) {
	subnet, err := netip.ParsePrefix(subnetText)
	if err != nil {
		return types.Configuration{}, fmt.Errorf("parse subnet: %w", err)
	}
	gatewayIP, err := getFirstUsableIPFromSubnet(subnet)
	if err != nil {
		return types.Configuration{}, err
	}
	deviceIP, err := getNextUsableIPFromSubnet(subnet, gatewayIP)
	if err != nil {
		return types.Configuration{}, err
	}
	hostIP, err := getLastUsableIPFromSubnet(subnet)
	if err != nil {
		return types.Configuration{}, err
	}
	if sshPort != -1 && (sshPort < 1024 || sshPort > 65535) {
		return types.Configuration{}, errors.New("ssh-port value must be -1 or between 1024 and 65535")
	}

	forwards := map[string]string{}
	if sshPort != -1 {
		forwards[fmt.Sprintf("127.0.0.1:%d", sshPort)] = net.JoinHostPort(deviceIP.String(), "22")
	}

	return types.Configuration{
		CaptureFile:       pcapFile,
		MTU:               1500,
		Subnet:            subnetText,
		GatewayIP:         gatewayIP.String(),
		DeviceIP:          deviceIP.String(),
		HostIP:            hostIP.String(),
		GatewayMacAddress: "5a:94:ef:e4:0c:dd",
		DNS: []types.Zone{
			{Name: "containers.internal.", Records: []types.Record{{Name: "gateway", IP: net.ParseIP(gatewayIP.String())}, {Name: "host", IP: net.ParseIP(hostIP.String())}}},
			{Name: "docker.internal.", Records: []types.Record{{Name: "gateway", IP: net.ParseIP(gatewayIP.String())}, {Name: "host", IP: net.ParseIP(hostIP.String())}}},
		},
		DNSSearchDomains:  searchDomains(),
		Forwards:          forwards,
		NAT:               map[string]string{hostIP.String(): "127.0.0.1"},
		GatewayVirtualIPs: []string{hostIP.String()},
		DHCPStaticLeases: map[string]string{
			deviceIP.String(): "5a:94:ef:e4:0c:ee",
		},
		VpnKitUUIDMacAddresses: map[string]string{
			"c3d68012-0208-11ea-9fd7-f2189899ab08": "5a:94:ef:e4:0c:ee",
		},
		Protocol: types.VfkitProtocol,
	}, nil
}

func getFirstUsableIPFromSubnet(subnet netip.Prefix) (netip.Addr, error) {
	if subnet.Bits()+3 > subnet.Addr().BitLen() {
		return netip.Addr{}, errors.New("subnet too small")
	}
	return getNextUsableIPFromSubnet(subnet, subnet.Masked().Addr())
}

func getNextUsableIPFromSubnet(subnet netip.Prefix, addr netip.Addr) (netip.Addr, error) {
	nextIP := addr.Next()
	if !nextIP.IsValid() || !subnet.Contains(nextIP) {
		return netip.Addr{}, errors.New("no usable IP in subnet")
	}
	return nextIP, nil
}

func getLastUsableIPFromSubnet(subnet netip.Prefix) (netip.Addr, error) {
	if subnet.Bits()+3 > subnet.Addr().BitLen() {
		return netip.Addr{}, errors.New("subnet too small")
	}
	b := subnet.Masked().Addr().AsSlice()
	for i, v := range net.CIDRMask(subnet.Bits(), subnet.Addr().BitLen()) {
		b[i] += ^v
	}
	b[len(b)-1]--
	addr, ok := netip.AddrFromSlice(b)
	if !ok {
		return netip.Addr{}, errors.New("bad IP address")
	}
	return addr, nil
}

func searchDomains() []string {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		return nil
	}
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "search ") {
			return parseSearchString(line)
		}
	}
	return nil
}

func parseSearchString(text string) []string {
	const searchPrefix = "search "
	if runtime.GOOS == "darwin" && len(text) > 256 {
		text = text[:256]
		if lastSpace := strings.LastIndex(text, " "); lastSpace != -1 {
			text = text[:lastSpace]
		}
	}
	domains := strings.Fields(strings.TrimPrefix(text, searchPrefix))
	if runtime.GOOS == "darwin" && len(domains) > 6 {
		domains = domains[:6]
	}
	return domains
}
