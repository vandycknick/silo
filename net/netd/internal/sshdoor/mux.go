package sshdoor

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

func readBounded(r io.Reader, max int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if int64(len(b)) > max {
		return nil, errors.New("SSH input exceeds size limit")
	}
	return b, err
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.reader.Read(b) }

// DialMux retains all bytes read ahead of OK's newline, including SSH banners.
// The setup owner clears the absolute deadline only after SSH authentication.
func DialMux(ctx context.Context, path string) (net.Conn, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(30 * time.Second)
	}
	if err := c.SetDeadline(deadline); err != nil {
		c.Close()
		return nil, err
	}
	if _, err := io.WriteString(c, "CONNECT 22\n"); err != nil {
		c.Close()
		return nil, err
	}
	r := bufio.NewReaderSize(c, 4096)
	line, err := r.ReadSlice('\n')
	if err != nil || len(line) > 64 {
		c.Close()
		return nil, errors.New("invalid mux acknowledgement")
	}
	text := strings.TrimSuffix(string(line), "\n")
	portText, ok := strings.CutPrefix(text, "OK ")
	port, err := strconv.ParseUint(portText, 10, 32)
	if !ok || err != nil || port == 0 || strconv.FormatUint(port, 10) != portText {
		c.Close()
		return nil, fmt.Errorf("mux rejected SSH connection: %q", text)
	}
	if ctx.Err() != nil {
		c.Close()
		return nil, ctx.Err()
	}
	return &bufferedConn{Conn: c, reader: r}, nil
}
