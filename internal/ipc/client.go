package ipc

import (
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/adumbdinosaur/vex-cli/internal/state"
)

// Client connects to the vexd daemon over a Unix domain socket.
type Client struct {
	socketPath string
	timeout    time.Duration
}

// NewClient creates a client that talks to the daemon.
func NewClient() *Client {
	return &Client{
		socketPath: state.SocketPath,
		timeout:    10 * time.Second,
	}
}

// Send sends a request to the daemon and returns the response.
func (c *Client) Send(req *Request) (*Response, error) {
	conn, err := net.DialTimeout("unix", c.socketPath, c.timeout)
	if err != nil {
		return nil, fmt.Errorf("could not connect to vexd at %s: %w (is the service running?)", c.socketPath, err)
	}
	defer conn.Close()

	// Set a deadline for the entire exchange.
	conn.SetDeadline(time.Now().Add(c.timeout))

	// Write request
	enc := json.NewEncoder(conn)
	if err := enc.Encode(req); err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	// Read response
	dec := json.NewDecoder(conn)
	var resp Response
	if err := dec.Decode(&resp); err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return &resp, nil
}
