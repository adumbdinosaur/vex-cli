package ipc

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"

	vexlog "github.com/adumbdinosaur/vex-cli/internal/logging"
	"github.com/adumbdinosaur/vex-cli/internal/state"
)

// Handler is the callback the daemon registers to process each command.
// It receives the current system state (which it may mutate) and the
// request, and returns a response.  If the handler mutates state the
// server will persist it automatically.
type Handler func(s *state.SystemState, req *Request) *Response

// Server listens on the Unix domain socket and dispatches commands.
type Server struct {
	listener net.Listener
	handlers map[string]Handler
	state    *state.SystemState
}

// NewServer creates a server bound to the well-known socket path.
func NewServer(sysState *state.SystemState) (*Server, error) {
	if err := state.EnsureSocketDir(); err != nil {
		return nil, fmt.Errorf("failed to create socket dir: %w", err)
	}

	// Remove stale socket from a previous run.
	os.Remove(state.SocketPath)

	ln, err := net.Listen("unix", state.SocketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %w", state.SocketPath, err)
	}

	// Let non-root users connect (they still need to be root to run
	// vex-cli, but this avoids permission issues during testing).
	os.Chmod(state.SocketPath, 0660)

	return &Server{
		listener: ln,
		handlers: make(map[string]Handler),
		state:    sysState,
	}, nil
}

// Handle registers a handler for a command name.
func (s *Server) Handle(command string, h Handler) {
	s.handlers[command] = h
}

// Serve accepts connections forever (blocking).  Run in a goroutine.
func (s *Server) Serve() {
	log.Printf("IPC: Listening on %s", state.SocketPath)
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			// listener closed
			log.Printf("IPC: Accept error: %v", err)
			return
		}
		go s.handle(conn)
	}
}

// Close tears down the listener.
func (s *Server) Close() error {
	return s.listener.Close()
}

// GetState returns a pointer to the current state (for the daemon to read).
func (s *Server) GetState() *state.SystemState {
	return s.state
}

// SetState replaces the in-memory state (for the daemon to call after
// applying settings imperatively, e.g. from penance enforcement).
func (s *Server) SetState(st *state.SystemState) {
	s.state = st
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()

	// Decode request
	dec := json.NewDecoder(conn)
	var req Request
	if err := dec.Decode(&req); err != nil {
		writeResp(conn, &Response{OK: false, Error: "malformed request"})
		return
	}

	vexlog.LogEvent("IPC", "REQUEST", fmt.Sprintf("cmd=%s args=%v", req.Command, req.Args))

	h, ok := s.handlers[req.Command]
	if !ok {
		writeResp(conn, &Response{OK: false, Error: fmt.Sprintf("unknown command: %s", req.Command)})
		return
	}

	resp := h(s.state, &req)

	// Persist state after every mutation (handlers that are read-only
	// can simply not modify the state struct).
	if err := state.Save(s.state); err != nil {
		log.Printf("IPC: Failed to persist state after %s: %v", req.Command, err)
	}

	writeResp(conn, resp)
}

func writeResp(conn net.Conn, resp *Response) {
	enc := json.NewEncoder(conn)
	enc.Encode(resp)
}

// ── Built-in handler helpers ────────────────────────────────────────

// ParseIntArg is a convenience for handlers that need an integer arg.
func ParseIntArg(args map[string]string, key string) (int, error) {
	v, ok := args[key]
	if !ok {
		return 0, fmt.Errorf("missing required argument: %s", key)
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("invalid integer for %s: %q", key, v)
	}
	return n, nil
}
