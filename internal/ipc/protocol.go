// Package ipc defines the request/response protocol used over the Unix
// domain socket between vex-cli (client) and vexd (server).
package ipc

import "github.com/adumbdinosaur/vex-cli/internal/state"

// ── Command constants ───────────────────────────────────────────────

const (
	CmdStatus   = "status"
	CmdThrottle = "throttle"
	CmdCPU      = "cpu"
	CmdLatency  = "latency"
	CmdOOM      = "oom"
	CmdBlock    = "block"
	CmdUnlock   = "unlock"
	CmdPenance  = "penance"
	CmdCheck    = "check"
	CmdState    = "state" // raw state dump
)

// Request is sent from the CLI to the daemon over the socket.
type Request struct {
	Command string            `json:"command"`
	Args    map[string]string `json:"args,omitempty"`
}

// Response is sent from the daemon back to the CLI.
type Response struct {
	OK      bool               `json:"ok"`
	Message string             `json:"message,omitempty"`
	Error   string             `json:"error,omitempty"`
	State   *state.SystemState `json:"state,omitempty"` // included for status/state commands
}
