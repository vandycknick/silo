// tsgate-testnet is an offline end-to-end test helper, never a shipped daemon.
package main

import (
	_ "github.com/vandycknick/silo/app/tsgate/internal/bootenv"

	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vandycknick/silo/app/tsgate/internal/testnet"
	"golang.org/x/crypto/ssh"
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
		if len(parts) == 3 && parts[0] == "ssh" {
			request, parseErr := parseSSH(parts[2])
			var result sshResult
			if parseErr != nil {
				result = sshResult{Status: "error", Error: parseErr.Error()}
			} else {
				result = sshProbe(inputCtx, peer, parts[1], request)
			}
			if err = out.Encode(result); err != nil {
				return err
			}
			continue
		}
		if len(parts) != 3 || parts[0] != "probe" {
			if err = out.Encode(map[string]string{"probe": "error", "error": `expected probe <hostname> <payload>, ssh <hostname> "<command>" ["<stdin>"] [pty], or quit`}); err != nil {
				return err
			}
			continue
		}
		payload := parts[2]
		if strings.HasPrefix(payload, `"`) {
			payload, err = strconv.Unquote(payload)
			if err != nil {
				if err = out.Encode(map[string]string{"probe": "error", "error": "invalid quoted payload"}); err != nil {
					return err
				}
				continue
			}
		}
		received, e := probe(inputCtx, peer, parts[1], payload)
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

type sshRequest struct {
	command string
	input   string
	pty     bool
}

func parseSSH(text string) (sshRequest, error) {
	var request sshRequest
	quoted := func() (string, error) {
		text = strings.TrimSpace(text)
		if !strings.HasPrefix(text, `"`) {
			return "", fmt.Errorf("SSH command and stdin must be JSON strings")
		}
		decoder := json.NewDecoder(strings.NewReader(text))
		var value string
		if err := decoder.Decode(&value); err != nil {
			return "", fmt.Errorf("invalid SSH JSON string: %w", err)
		}
		text = strings.TrimSpace(text[decoder.InputOffset():])
		return value, nil
	}
	var err error
	if request.command, err = quoted(); err != nil {
		return request, err
	}
	if request.command == "" {
		return request, fmt.Errorf("SSH command must not be empty")
	}
	if strings.HasPrefix(text, `"`) {
		if request.input, err = quoted(); err != nil {
			return request, err
		}
	}
	switch text {
	case "":
	case "pty":
		request.pty = true
	default:
		return request, fmt.Errorf("unexpected SSH arguments")
	}
	return request, nil
}

type sshResult struct {
	Status string `json:"ssh"`
	Stdout string `json:"stdout"`
	Stderr string `json:"stderr"`
	Exit   int    `json:"exit"`
	Error  string `json:"error,omitempty"`
}

type limitedBuffer struct {
	buffer bytes.Buffer
}

func (b *limitedBuffer) Write(data []byte) (int, error) {
	if len(data) > (1<<20)-b.Len() {
		return 0, fmt.Errorf("SSH output exceeds 1 MiB")
	}
	return b.buffer.Write(data)
}

func (b *limitedBuffer) Len() int       { return b.buffer.Len() }
func (b *limitedBuffer) String() string { return b.buffer.String() }

func sshProbe(parent context.Context, peer *tsnet.Server, hostname string, request sshRequest) (result sshResult) {
	result.Status = "error"
	result.Exit = -1
	var stdout, stderr limitedBuffer
	defer func() {
		result.Stdout = stdout.String()
		result.Stderr = stderr.String()
	}()
	fail := func(err error) sshResult {
		result.Error = err.Error()
		return result
	}
	ctx, cancel := context.WithTimeout(parent, 240*time.Second)
	defer cancel()
	address := net.JoinHostPort(hostname, "22")
	conn, err := peer.Dial(ctx, "tcp", address)
	if err != nil {
		return fail(err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		if err = conn.SetDeadline(deadline); err != nil {
			return fail(err)
		}
	}
	clientConn, channels, requests, err := ssh.NewClientConn(conn, address, &ssh.ClientConfig{
		User:            "offline-peer",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		return fail(err)
	}
	client := ssh.NewClient(clientConn, channels, requests)
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return fail(err)
	}
	defer session.Close()
	session.Stdout = &stdout
	session.Stderr = &stderr
	// x/crypto/ssh copies the input and sends channel EOF after the reader ends.
	session.Stdin = strings.NewReader(request.input)
	if request.pty {
		if err = session.RequestPty("xterm", 24, 80, ssh.TerminalModes{ssh.ECHO: 0}); err != nil {
			return fail(err)
		}
	}
	err = session.Run(request.command)
	result.Exit = 0
	if err != nil {
		var exit *ssh.ExitError
		if !errors.As(err, &exit) {
			return fail(err)
		}
		result.Exit = exit.ExitStatus()
	}
	result.Status = "ok"
	return result
}
