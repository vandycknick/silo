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
	"strings"

	"github.com/vandycknick/silo/net/netd/internal/policy"
)

type Config struct {
	ListenVfkit string
	PIDFile     string
	LogFile     string
	Stack       NetworkConfig
	PolicyFile  string
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

type NetworkConfig struct {
	CaptureFile       string
	Debug             bool
	MTU               int
	Subnet            string
	GatewayIP         string
	DeviceIP          string
	HostIP            string
	GatewayMACAddress string
	DNS               []DNSZone
	DNSSearchDomains  []string
	Forwards          map[string]string
	NAT               map[string]string
	GatewayVirtualIPs []string
	DHCPStaticLeases  map[string]string
	EC2MetadataAccess bool
}

type DNSZone struct {
	Name    string
	Records []DNSRecord
}

type DNSRecord struct {
	Name string
	IP   net.IP
}

func Parse(args []string) (*Config, error) {
	cfg := &Config{}
	var subnet, pcapFile, staticLease string

	flags := flag.NewFlagSet("netd", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&cfg.ListenVfkit, "listen-vfkit", "", "unixgram socket used by vfkit-compatible applications")
	flags.StringVar(&subnet, "subnet", "192.168.127.0/24", "guest network subnet")
	flags.StringVar(&staticLease, "static-lease", "", "guest DHCP lease in IP=MAC form")
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
	stack, err := stackConfig(subnet, staticLease, pcapFile)
	if err != nil {
		return cfg, err
	}
	cfg.Stack = stack
	if (cfg.TLS.CACert == "") != (cfg.TLS.CAKey == "") {
		return cfg, errors.New("--tls-ca-cert and --tls-ca-key must be provided together")
	}
	return cfg, nil
}

func LoadPolicy(cfg *Config) (*policy.Policy, error) {
	if cfg == nil {
		return nil, errors.New("missing configuration")
	}
	var compiledPolicy *policy.Policy
	var err error
	if cfg.PolicyFile != "" {
		compiledPolicy, err = policy.LoadFile(cfg.PolicyFile)
	} else {
		compiledPolicy = policy.Default()
	}
	if err != nil {
		return nil, err
	}
	if compiledPolicy.HasHTTPS() || compiledPolicy.HasRegistries() {
		if cfg.TLS.CACert == "" || cfg.TLS.CAKey == "" {
			return nil, errors.New("--tls-ca-cert and --tls-ca-key are required when policy contains TLS-terminating endpoints")
		}
	}
	return compiledPolicy, nil
}

func stackConfig(subnetText, staticLease, pcapFile string) (NetworkConfig, error) {
	subnet, err := netip.ParsePrefix(subnetText)
	if err != nil {
		return NetworkConfig{}, fmt.Errorf("parse subnet: %w", err)
	}
	if !subnet.Addr().Is4() {
		return NetworkConfig{}, errors.New("subnet must be IPv4")
	}
	gatewayIP, err := getFirstUsableIPFromSubnet(subnet)
	if err != nil {
		return NetworkConfig{}, err
	}
	deviceIP, err := getNextUsableIPFromSubnet(subnet, gatewayIP)
	if err != nil {
		return NetworkConfig{}, err
	}
	hostIP, err := getLastUsableIPFromSubnet(subnet)
	if err != nil {
		return NetworkConfig{}, err
	}
	staticLeases := map[string]string{}
	if staticLease != "" {
		leaseIP, leaseMAC, err := parseStaticLease(staticLease, subnet, gatewayIP, hostIP)
		if err != nil {
			return NetworkConfig{}, err
		}
		deviceIP = leaseIP
		staticLeases[leaseIP.String()] = leaseMAC
	}

	return NetworkConfig{
		CaptureFile:       pcapFile,
		MTU:               1500,
		Subnet:            subnetText,
		GatewayIP:         gatewayIP.String(),
		DeviceIP:          deviceIP.String(),
		HostIP:            hostIP.String(),
		GatewayMACAddress: "5a:94:ef:e4:0c:dd",
		DNS: []DNSZone{
			{Name: "containers.internal.", Records: []DNSRecord{{Name: "gateway", IP: net.ParseIP(gatewayIP.String())}, {Name: "host", IP: net.ParseIP(hostIP.String())}}},
			{Name: "docker.internal.", Records: []DNSRecord{{Name: "gateway", IP: net.ParseIP(gatewayIP.String())}, {Name: "host", IP: net.ParseIP(hostIP.String())}}},
		},
		DNSSearchDomains:  searchDomains(),
		Forwards:          map[string]string{},
		NAT:               map[string]string{hostIP.String(): "127.0.0.1"},
		GatewayVirtualIPs: []string{hostIP.String()},
		DHCPStaticLeases:  staticLeases,
	}, nil
}

func parseStaticLease(value string, subnet netip.Prefix, gatewayIP, hostIP netip.Addr) (netip.Addr, string, error) {
	ipText, macText, ok := strings.Cut(value, "=")
	if !ok || ipText == "" || macText == "" || strings.Contains(macText, "=") {
		return netip.Addr{}, "", errors.New("--static-lease must use IP=MAC form")
	}
	ip, err := netip.ParseAddr(ipText)
	if err != nil || !ip.Is4() {
		return netip.Addr{}, "", fmt.Errorf("invalid static lease IPv4 address %q", ipText)
	}
	mac, err := net.ParseMAC(macText)
	if err != nil || len(mac) != 6 || !isColonSeparatedMAC(macText) {
		return netip.Addr{}, "", fmt.Errorf("invalid static lease Ethernet MAC address %q", macText)
	}
	if mac[0]&1 != 0 || allZeroMAC(mac) {
		return netip.Addr{}, "", fmt.Errorf("static lease Ethernet MAC address %q must be nonzero unicast", macText)
	}
	broadcastIP, err := getLastUsableIPFromSubnet(subnet)
	if err != nil {
		return netip.Addr{}, "", err
	}
	broadcastIP = broadcastIP.Next()
	if !subnet.Contains(ip) || ip == subnet.Masked().Addr() || ip == broadcastIP || ip == gatewayIP || ip == hostIP {
		return netip.Addr{}, "", fmt.Errorf("static lease address %q is not a usable guest address", ipText)
	}
	return ip, mac.String(), nil
}

func allZeroMAC(mac net.HardwareAddr) bool {
	for _, value := range mac {
		if value != 0 {
			return false
		}
	}
	return true
}

func isColonSeparatedMAC(value string) bool {
	parts := strings.Split(value, ":")
	if len(parts) != 6 {
		return false
	}
	for _, part := range parts {
		if len(part) != 2 {
			return false
		}
	}
	return true
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
