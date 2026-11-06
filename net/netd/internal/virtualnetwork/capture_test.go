package virtualnetwork

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vandycknick/silo/net/netd/internal/gateway/packet"
	"github.com/vandycknick/silo/net/netd/internal/gateway/router"
	"github.com/vandycknick/silo/net/netd/internal/policy"
)

func capturedFrames(t *testing.T, data []byte) [][]byte {
	t.Helper()
	if len(data) < 24 || binary.LittleEndian.Uint32(data[:4]) != 0xa1b23c4d ||
		binary.LittleEndian.Uint32(data[20:24]) != 1 {
		t.Fatalf("not a nanosecond Ethernet pcap: %x", data)
	}
	var frames [][]byte
	for data = data[24:]; len(data) != 0; {
		if len(data) < 16 {
			t.Fatalf("torn record header: %x", data)
		}
		length := int(binary.LittleEndian.Uint32(data[8:12]))
		if length != int(binary.LittleEndian.Uint32(data[12:16])) || length > len(data)-16 {
			t.Fatalf("truncated frame: %x", data)
		}
		if binary.LittleEndian.Uint32(data[:4]) == 0 || binary.LittleEndian.Uint32(data[4:8]) >= 1_000_000_000 {
			t.Fatalf("invalid timestamp: %x", data[:8])
		}
		frames = append(frames, data[16:16+length])
		data = data[16+length:]
	}
	return frames
}

func TestEthernetCapturePreservesBothDirections(t *testing.T) {
	var output bytes.Buffer
	capture, err := newEthernetCapture(&output)
	if err != nil {
		t.Fatal(err)
	}
	netd, guest := net.Pipe()
	t.Cleanup(func() { _ = netd.Close(); _ = guest.Close() })
	_ = netd.SetDeadline(time.Now().Add(5 * time.Second))
	_ = guest.SetDeadline(time.Now().Add(5 * time.Second))
	conn := &captureConn{Conn: netd, capture: capture}
	// Preserve headers and arbitrary payloads byte-for-byte, not just IPv4.
	for _, etherType := range []uint16{0x0800, 0x0806, 0x86dd, 0x88b5} {
		frame := []byte{0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xdd, 2, 0, 0, 0, 0, 0x22, byte(etherType >> 8), byte(etherType), 1, 2, 3}
		done := make(chan error, 1)
		go func() { _, err := guest.Write(frame); done <- err }()
		buffer := make([]byte, 128)
		n, err := conn.Read(buffer)
		if err != nil || !bytes.Equal(buffer[:n], frame) {
			t.Fatalf("read changed frame: %x, %v", buffer[:n], err)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		reply := append([]byte(nil), frame...)
		copy(reply[:6], frame[6:12])
		copy(reply[6:12], frame[:6])
		go func() { _, err := conn.Write(reply); done <- err }()
		n, err = guest.Read(buffer)
		if err != nil || !bytes.Equal(buffer[:n], reply) {
			t.Fatalf("write changed frame: %x, %v", buffer[:n], err)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		frames := capturedFrames(t, output.Bytes())
		if !bytes.Equal(frames[len(frames)-2], frame) || !bytes.Equal(frames[len(frames)-1], reply) {
			t.Fatalf("capture lost Ethernet identity: %x", frames)
		}
	}
	if len(capturedFrames(t, output.Bytes())) != 8 {
		t.Fatal("capture duplicated or lost frames")
	}
}

func TestVirtualNetworkCapturesBeforeSwitchFiltering(t *testing.T) {
	path := filepath.Join(t.TempDir(), "network.pcap")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	network, err := New(context.Background(), testNetworkConfig(), file,
		router.New(policy.Default(), nil), packet.NewTCPDispatcher(), packet.NewFlowTracker(),
		Metadata{}, PublicationOptions{})
	if err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = network.Close() })
	netd, guest := net.Pipe()
	t.Cleanup(func() { _ = netd.Close(); _ = guest.Close() })
	_ = netd.SetDeadline(time.Now().Add(5 * time.Second))
	_ = guest.SetDeadline(time.Now().Add(5 * time.Second))
	done := make(chan error, 1)
	go func() { done <- network.Run(context.Background(), netd) }()
	// Unknown destination: the switch drops this before the stack endpoint.
	frame := []byte{2, 0, 0, 0, 0, 0x33, 2, 0, 0, 0, 0, 0x11, 0x88, 0xb5, 1, 2, 3}
	if _, err := guest.Write(frame); err != nil {
		t.Fatal(err)
	}
	_ = guest.Close()
	<-done
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	frames := capturedFrames(t, data)
	if len(frames) != 1 || !bytes.Equal(frames[0], frame) {
		t.Fatalf("capture missed original source MAC before filtering: %x", frames)
	}
}

type shortCaptureWriter struct{}

func (shortCaptureWriter) Write(data []byte) (int, error) { return len(data) - 1, nil }

func TestEthernetCaptureFailsClosedOnWriteError(t *testing.T) {
	if _, err := newEthernetCapture(shortCaptureWriter{}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("header short write: %v", err)
	}
	var output bytes.Buffer
	capture, err := newEthernetCapture(&output)
	if err != nil {
		t.Fatal(err)
	}
	capture.writer = shortCaptureWriter{}
	netd, guest := net.Pipe()
	t.Cleanup(func() { _ = netd.Close(); _ = guest.Close() })
	_ = netd.SetDeadline(time.Now().Add(5 * time.Second))
	_ = guest.SetDeadline(time.Now().Add(5 * time.Second))
	conn := &captureConn{Conn: netd, capture: capture}
	done := make(chan error, 1)
	go func() { _, err := guest.Write(make([]byte, 14)); done <- err }()
	if n, err := conn.Read(make([]byte, 128)); n != 0 || !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("forwarded unrecorded traffic: n=%d err=%v", n, err)
	}
	<-done
	capture.writer = &output
	if err := capture.record(make([]byte, 14), time.Now()); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("capture resumed after torn record: %v", err)
	}
	if output.Len() != 24 {
		t.Fatal("appended records after capture failure")
	}
	file, err := os.Create(filepath.Join(t.TempDir(), "failed.pcap"))
	if err != nil {
		t.Fatal(err)
	}
	network := &VirtualNetwork{captureFile: file, capture: capture}
	if err := network.Close(); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("close lost capture failure: %v", err)
	}
}
