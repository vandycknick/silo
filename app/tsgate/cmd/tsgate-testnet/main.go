// tsgate-testnet is an offline end-to-end test helper, never a shipped daemon.
package main

import (
	_ "github.com/vandycknick/silo/app/tsgate/internal/bootenv"

	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vandycknick/silo/app/tsgate/internal/testnet"
	"tailscale.com/tsnet"
)

// The upstream helpers accept testing.TB, including its private marker method.
// Embed it for that marker and implement every method those helpers exercise.
type harness struct {
	testing.TB
	mu       sync.Mutex
	cleanups []func()
}

func (*harness) Helper()                   {}
func (*harness) Logf(f string, a ...any)   { log.Printf(f, a...) }
func (*harness) Fatal(a ...any)            { log.Print(a...); os.Exit(1) }
func (*harness) Fatalf(f string, a ...any) { log.Printf(f, a...); os.Exit(1) }
func (h *harness) Cleanup(f func()) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cleanups = append(h.cleanups, f)
}
func (h *harness) close() {
	h.mu.Lock()
	fs := h.cleanups
	h.cleanups = nil
	h.mu.Unlock()
	for i := len(fs) - 1; i >= 0; i-- {
		fs[i]()
	}
}

func main() {
	if err := run(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}
func run() error {
	capability := flag.String("capability", "silo.dev/cap/lobby", "app capability key")
	value := flag.String("cap-value", `true`, "one raw JSON capability value")
	flag.Parse()
	if flag.NArg() != 0 || !json.Valid([]byte(*value)) {
		return fmt.Errorf("invalid testnet arguments")
	}
	inputCtx, stopInput := context.WithCancel(context.Background())
	defer stopInput()
	lines := make(chan string)
	inputDone := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Buffer(make([]byte, 4096), 65536)
		for scanner.Scan() {
			select {
			case lines <- scanner.Text():
			case <-inputCtx.Done():
				return
			}
		}
		inputDone <- scanner.Err()
		stopInput()
	}()
	h := &harness{}
	defer h.close()
	controlURL := testnet.Start(h, *capability, *value)
	dir, err := os.MkdirTemp("", "tsgate-peer-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	peer := &tsnet.Server{Dir: dir, Hostname: "peer", ControlURL: controlURL, AdvertiseTags: []string{"tag:peer"}, Logf: h.Logf, UserLogf: h.Logf}
	defer peer.Close()
	ctx, cancel := context.WithTimeout(inputCtx, 30*time.Second)
	_, err = peer.Up(ctx)
	cancel()
	if err != nil {
		if inputCtx.Err() != nil {
			return <-inputDone
		}
		return err
	}
	out := json.NewEncoder(os.Stdout)
	if err = out.Encode(map[string]string{"control_url": controlURL}); err != nil {
		return err
	}
	for {
		var line string
		select {
		case line = <-lines:
		case err := <-inputDone:
			return err
		}
		if line == "quit" {
			return nil
		}
		parts := strings.SplitN(line, " ", 3)
		if len(parts) != 3 || parts[0] != "probe" {
			if err = out.Encode(map[string]string{"probe": "error", "error": "expected probe <hostname> <payload> or quit"}); err != nil {
				return err
			}
			continue
		}
		received, e := probe(inputCtx, peer, parts[1], parts[2])
		result := map[string]string{"probe": "ok", "received": received}
		if e != nil {
			result = map[string]string{"probe": "error", "error": e.Error()}
		}
		if err = out.Encode(result); err != nil {
			return err
		}
	}
}
func probe(parent context.Context, peer *tsnet.Server, hostname, payload string) (string, error) {
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	conn, err := peer.Dial(ctx, "tcp", net.JoinHostPort(hostname, "22"))
	if err != nil {
		return "", err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	if _, err = io.WriteString(conn, payload); err != nil {
		return "", err
	}
	cw, ok := conn.(interface{ CloseWrite() error })
	if !ok {
		return "", fmt.Errorf("peer stream lacks CloseWrite")
	}
	if err = cw.CloseWrite(); err != nil {
		return "", err
	}
	body, err := io.ReadAll(io.LimitReader(conn, 1<<20+1))
	if len(body) > 1<<20 {
		return "", fmt.Errorf("probe response exceeds 1 MiB")
	}
	return string(body), err
}
