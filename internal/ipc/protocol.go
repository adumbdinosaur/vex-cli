// Package ipc defines the request/response protocol used over the Unix
// domain socket between vex-cli (client) and vexd (server).
package ipc

import "github.com/adumbdinosaur/vex-cli/internal/state"

// ── Command constants ───────────────────────────────────────────────

const (
	CmdStatus      = "status"
	CmdThrottle    = "throttle"
	CmdCPU         = "cpu"
	CmdLatency     = "latency"
	CmdOOM         = "oom"
	CmdBlock       = "block"       // legacy: show guardian status
	CmdBlockAdd    = "block-add"   // add a domain to the SNI blocklist
	CmdBlockRemove = "block-rm"    // remove a domain from the SNI blocklist
	CmdBlockList   = "block-list"  // list currently blocked domains
	CmdUnlock      = "unlock"
	CmdPenance     = "penance"
	CmdCheck       = "check"
	CmdState       = "state" // raw state dump
	CmdLinesSet    = "lines-set"    // assign a writing-lines task
	CmdLinesClear  = "lines-clear"  // cancel a writing-lines task
	CmdLinesStatus = "lines-status" // check progress
	CmdLinesSubmit = "lines-submit" // submit one line of text
	CmdResetScore  = "reset-score"  // reset failure score to zero
	CmdAppAdd      = "app-add"      // add an app to the forbidden list
	CmdAppRemove   = "app-rm"       // remove an app from the forbidden list
	CmdAppList     = "app-list"     // list forbidden apps
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
