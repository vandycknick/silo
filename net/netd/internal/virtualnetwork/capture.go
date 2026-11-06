package virtualnetwork

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Capture at the vfkit datagram boundary, not the stack's network endpoint:
// tap strips incoming Ethernet headers and only adds outgoing ones below the
// stack sniffer. Each vfkit datagram is one original Ethernet frame, including
// ARP, IPv6 and frames the switch will subsequently drop.
type ethernetCapture struct {
	mu     sync.Mutex
	writer io.Writer
	err    error
	header [16]byte
}

func newEthernetCapture(writer io.Writer) (*ethernetCapture, error) {
	capture := &ethernetCapture{writer: writer}
	var header [24]byte
	binary.LittleEndian.PutUint32(header[0:4], 0xa1b23c4d) // nanosecond classic pcap
	binary.LittleEndian.PutUint16(header[4:6], 2)
	binary.LittleEndian.PutUint16(header[6:8], 4)
	binary.LittleEndian.PutUint32(header[16:20], 128*1024) // tap's receive buffer
	binary.LittleEndian.PutUint32(header[20:24], 1)        // LINKTYPE_ETHERNET
	if err := capture.write(header[:]); err != nil {
		return nil, err
	}
	return capture, nil
}

// The first write failure is sticky: never append plausible records after a
// torn record. Close reports the same failure even if the switch swallowed it.
func (c *ethernetCapture) write(data []byte) error {
	if c.err != nil {
		return c.err
	}
	n, err := c.writer.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err != nil {
		c.err = fmt.Errorf("write Ethernet capture: %w", err)
	}
	return c.err
}

func (c *ethernetCapture) record(frame []byte, timestamp time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	header := c.header[:]
	binary.LittleEndian.PutUint32(header[0:4], uint32(timestamp.Unix()))
	binary.LittleEndian.PutUint32(header[4:8], uint32(timestamp.Nanosecond()))
	binary.LittleEndian.PutUint32(header[8:12], uint32(len(frame)))
	binary.LittleEndian.PutUint32(header[12:16], uint32(len(frame)))
	if err := c.write(header[:]); err != nil {
		return err
	}
	return c.write(frame)
}

type captureConn struct {
	net.Conn
	capture *ethernetCapture
}

func (c *captureConn) Read(buffer []byte) (int, error) {
	n, err := c.Conn.Read(buffer)
	if n > 0 {
		if captureErr := c.capture.record(buffer[:n], time.Now()); captureErr != nil {
			_ = c.Conn.Close()
			return 0, captureErr // do not forward unrecorded guest traffic
		}
	}
	return n, err
}

func (c *captureConn) Write(frame []byte) (int, error) {
	timestamp := time.Now()
	n, err := c.Conn.Write(frame)
	if n > 0 {
		if captureErr := c.capture.record(frame[:n], timestamp); captureErr != nil {
			_ = c.Conn.Close() // also unblock the switch's receive loop
			return n, captureErr
		}
	}
	return n, err
}
