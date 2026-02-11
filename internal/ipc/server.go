package ipc

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/user"
	"strconv"
	"syscall"

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

	// Clear the umask before bind() so the socket is created with full
	// permissions.  We restore it immediately after Listen returns.
	// Without this the default umask (often 0022 or 0077) strips the
	// group-write bit that non-root vex-group members need to connect().
	oldMask := syscall.Umask(0)
	ln, err := net.Listen("unix", state.SocketPath)
	syscall.Umask(oldMask) // restore original umask
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %w", state.SocketPath, err)
	}

	// Set permissions so vex group members can connect.
	// Both the directory AND the socket must be accessible.
	// Unix domain sockets require 'w' (write) permission to connect().
	if err := os.Chmod(state.SocketPath, 0660); err != nil {
		log.Printf("IPC: WARNING - Could not chmod socket to 0660: %v", err)
	}

	if err := setSocketGroup(state.SocketPath, "vex"); err != nil {
		log.Printf("IPC: WARNING - Could not set socket group to 'vex': %v", err)
		log.Printf("IPC: Non-root users will need to run with sudo")
	} else {
		log.Printf("IPC: Socket group set to 'vex' — non-root group members can connect")
	}

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

// setSocketGroup attempts to change the group ownership of the socket file
// to the specified group name. Returns error if the group doesn't exist or
// the operation fails.
func setSocketGroup(socketPath, groupName string) error {
	grp, err := user.LookupGroup(groupName)
	if err != nil {
		return fmt.Errorf("group '%s' not found: %w", groupName, err)
	}

	gid, err := strconv.Atoi(grp.Gid)
	if err != nil {
		return fmt.Errorf("invalid group ID: %w", err)
	}

	// Change group ownership (keep owner as root, uid -1 means no change)
	if err := os.Chown(socketPath, -1, gid); err != nil {
		return fmt.Errorf("failed to chown socket: %w", err)
	}

	return nil
}

