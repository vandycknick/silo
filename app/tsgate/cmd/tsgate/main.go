package main

import (
	_ "github.com/vandycknick/silo/app/tsgate/internal/bootenv"

	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"

	"github.com/vandycknick/silo/app/tsgate/internal/gateway"
	"golang.org/x/sys/unix"
	"runtime/debug"
)

func main() { os.Exit(run(os.Args[1:], os.Stderr)) }
func run(args []string, stderr io.Writer) int {
	if len(args) == 1 && args[0] == "version" {
		fmt.Printf("tsgate control protocol 1, tailscale %s\n", tailscaleVersion())
		return 0
	}
	flags := flag.NewFlagSet("tsgate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	fdText := flags.String("control-fd", "", "inherited Unix stream control socket")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 || *fdText == "" {
		fmt.Fprintln(stderr, "usage: tsgate --control-fd N | tsgate version")
		return 2
	}
	fd, err := strconv.Atoi(*fdText)
	if err != nil || fd < 0 {
		fmt.Fprintln(stderr, "tsgate: invalid control fd")
		return 2
	}
	typ, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil || typ != unix.SOCK_STREAM {
		fmt.Fprintln(stderr, "tsgate: control fd must be a Unix stream socket")
		return 2
	}
	addr, err := unix.Getsockname(fd)
	if err != nil {
		fmt.Fprintln(stderr, "tsgate: cannot inspect control fd")
		return 2
	}
	if _, ok := addr.(*unix.SockaddrUnix); !ok {
		fmt.Fprintln(stderr, "tsgate: control fd must be a Unix stream socket")
		return 2
	}
	file := os.NewFile(uintptr(fd), "tsgate-control")
	conn, err := net.FileConn(file)
	file.Close()
	if err != nil {
		fmt.Fprintln(stderr, "tsgate: cannot open control socket")
		return 1
	}
	control, ok := conn.(*net.UnixConn)
	if !ok {
		conn.Close()
		fmt.Fprintln(stderr, "tsgate: invalid control socket")
		return 2
	}
	if err = gateway.Run(context.Background(), control); err != nil {
		fmt.Fprintln(stderr, "tsgate:", err)
		return 1
	}
	return 0
}

// tailscaleVersion reports the pinned tailscale.com module this binary embeds.
func tailscaleVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range info.Deps {
			if dep.Path == "tailscale.com" {
				return dep.Version
			}
		}
	}
	return "unknown"
}
