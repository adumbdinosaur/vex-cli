package throttler

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
)

// Profile definitions
type Profile string

const (
	ProfileStandard  Profile = "standard"   // 10Gbps (Uncapped)
	ProfileChoke     Profile = "choke"      // 1Mbps
	ProfileDialUp    Profile = "dial-up"    // 56kbps
	ProfileBlackHole Profile = "black-hole" // 0kbps (Effective Drop)
)

// Interfaces for testing
type NetlinkOps interface {
	LinkByName(name string) (netlink.Link, error)
	QdiscList(link netlink.Link) ([]netlink.Qdisc, error)
	QdiscAdd(qdisc netlink.Qdisc) error
	QdiscDel(qdisc netlink.Qdisc) error
	RouteList(link netlink.Link, family int) ([]netlink.Route, error)
	LinkByIndex(index int) (netlink.Link, error)
}

type FileOps interface {
	WriteFile(filename string, data []byte, perm os.FileMode) error
	ReadFile(filename string) ([]byte, error)
	Stat(name string) (os.FileInfo, error)
}

// Default Implementations (Real System)

type RealNetlinkOps struct{}

func (r *RealNetlinkOps) LinkByName(name string) (netlink.Link, error) {
	return netlink.LinkByName(name)
}
func (r *RealNetlinkOps) QdiscList(link netlink.Link) ([]netlink.Qdisc, error) {
	return netlink.QdiscList(link)
}
func (r *RealNetlinkOps) QdiscAdd(qdisc netlink.Qdisc) error {
	return netlink.QdiscAdd(qdisc)
}
func (r *RealNetlinkOps) QdiscDel(qdisc netlink.Qdisc) error {
	return netlink.QdiscDel(qdisc)
}
func (r *RealNetlinkOps) RouteList(link netlink.Link, family int) ([]netlink.Route, error) {
	return netlink.RouteList(link, family)
}
func (r *RealNetlinkOps) LinkByIndex(index int) (netlink.Link, error) {
	return netlink.LinkByIndex(index)
}

type RealFileOps struct{}

func (r *RealFileOps) WriteFile(filename string, data []byte, perm os.FileMode) error {
	return os.WriteFile(filename, data, perm)
}
func (r *RealFileOps) ReadFile(filename string) ([]byte, error) {
	return os.ReadFile(filename)
}
func (r *RealFileOps) Stat(name string) (os.FileInfo, error) {
	return os.Stat(name)
}

// Config holds the configuration for the throttler
type Config struct {
	Interface string
}

var (
	currentConfig Config
	nlOps         NetlinkOps = &RealNetlinkOps{}
	fsOps         FileOps    = &RealFileOps{}
)

func Init() error {
	log.Println("Initializing Throttler Subsystem...")

	// Allow explicit override via environment
	if envIface := os.Getenv("VEX_INTERFACE"); envIface != "" {
		currentConfig.Interface = envIface
		log.Printf("Throttler attached to interface: %s (from VEX_INTERFACE)", envIface)
		return nil
	}

	// Auto-detect interface from the default route
	iface, err := getDefaultInterface()
	if err != nil {
		// Try common physical interface names before giving up
		for _, candidate := range []string{"enp9s0", "enp0s31f6", "eth0", "eno1"} {
			if _, lerr := nlOps.LinkByName(candidate); lerr == nil {
				currentConfig.Interface = candidate
				log.Printf("Throttler attached to interface: %s (fallback probe)", candidate)
				return nil
			}
		}
		log.Printf("Could not detect default interface: %v (set VEX_INTERFACE to override)", err)
		return fmt.Errorf("no usable network interface found")
	}
	currentConfig.Interface = iface
	log.Printf("Throttler attached to interface: %s", iface)

	return nil
}

// ---------------------------------------------------------------------
// Network Throttling
// ---------------------------------------------------------------------

// ApplyNetworkProfile applies the specified traffic shaping profile
func ApplyNetworkProfile(profile Profile) error {
	link, err := nlOps.LinkByName(currentConfig.Interface)
	if err != nil {
		return fmt.Errorf("failed to find interface %s: %w", currentConfig.Interface, err)
	}

	// Clear existing qdiscs (resets to default pfifo_fast/noqueue)
	if err := clearQdiscs(link); err != nil {
		return fmt.Errorf("failed to clear qdiscs: %w", err)
	}

	if profile == ProfileStandard {
		log.Printf("Applied Profile: %s (Restrictions Lifted)", profile)
		return nil
	}

	// Common attributes for the Root Qdisc
	attrs := netlink.QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    netlink.MakeHandle(1, 0),
		Parent:    netlink.HANDLE_ROOT,
	}

	var qdisc netlink.Qdisc

	switch profile {
	case ProfileChoke:
		// 1Mbps = 125,000 bytes/sec
		qdisc = &netlink.Tbf{
			QdiscAttrs: attrs,
			Rate:       125000,
			Limit:      1000000, // Burst tolerance
			Buffer:     100000,
		}
	case ProfileDialUp:
		// 56kbps = 7,000 bytes/sec
		qdisc = &netlink.Tbf{
			QdiscAttrs: attrs,
			Rate:       7000,
			Limit:      10000,
			Buffer:     5000,
		}
	case ProfileBlackHole:
		// 1kbps = 125 bytes/sec (Allows minimal C2 heartbeat)
		qdisc = &netlink.Tbf{
			QdiscAttrs: attrs,
			Rate:       125,
			Limit:      1250,
			Buffer:     1250,
		}
	default:
		return fmt.Errorf("unknown profile: %s", profile)
	}

	if err := nlOps.QdiscAdd(qdisc); err != nil {
		return fmt.Errorf("failed to apply qdisc for %s: %w", profile, err)
	}

	log.Printf("Applied Profile: %s on %s", profile, currentConfig.Interface)
	return nil
}

// ApplyNetworkProfileWithEntropy applies a traffic shaping profile combined with
// artificial packet loss in a single netem qdisc, avoiding the qdisc conflict
// that occurs when ApplyNetworkProfile and InjectEntropy are called separately.
func ApplyNetworkProfileWithEntropy(profile Profile, lossPercentage float32) error {
	link, err := nlOps.LinkByName(currentConfig.Interface)
	if err != nil {
		return fmt.Errorf("failed to find interface %s: %w", currentConfig.Interface, err)
	}

	if err := clearQdiscs(link); err != nil {
		return fmt.Errorf("failed to clear qdiscs: %w", err)
	}

	// If standard profile with no loss, just clear and return
	if profile == ProfileStandard && lossPercentage <= 0 {
		log.Printf("Applied Profile: %s (Restrictions Lifted)", profile)
		return nil
	}

	attrs := netlink.QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    netlink.MakeHandle(1, 0),
		Parent:    netlink.HANDLE_ROOT,
	}

	// Determine rate from profile
	var rateBytes uint64
	switch profile {
	case ProfileStandard:
		rateBytes = 0 // No rate limiting
	case ProfileChoke:
		rateBytes = 125000 // 1Mbps
	case ProfileDialUp:
		rateBytes = 7000 // 56kbps
	case ProfileBlackHole:
		rateBytes = 125 // 1kbps
	default:
		return fmt.Errorf("unknown profile: %s", profile)
	}

	// If only rate limiting, no packet loss, use TBF for precision
	if lossPercentage <= 0 && rateBytes > 0 {
		var qdisc netlink.Qdisc
		switch profile {
		case ProfileChoke:
			qdisc = &netlink.Tbf{QdiscAttrs: attrs, Rate: rateBytes, Limit: 1000000, Buffer: 100000}
		case ProfileDialUp:
			qdisc = &netlink.Tbf{QdiscAttrs: attrs, Rate: rateBytes, Limit: 10000, Buffer: 5000}
		case ProfileBlackHole:
			qdisc = &netlink.Tbf{QdiscAttrs: attrs, Rate: rateBytes, Limit: 1250, Buffer: 1250}
		}
		if err := nlOps.QdiscAdd(qdisc); err != nil {
			return fmt.Errorf("failed to apply qdisc for %s: %w", profile, err)
		}
		log.Printf("Applied Profile: %s on %s", profile, currentConfig.Interface)
		return nil
	}

	// Combined netem qdisc: packet loss + optional rate limiting
	netem := &netlink.Netem{
		QdiscAttrs: attrs,
		Loss:       uint32(lossPercentage * 100), // netem loss is in 1/100th of a percent
	}

	// Netem supports rate limiting via its Rate64 field (bytes per second)
	if rateBytes > 0 {
		netem.Rate64 = rateBytes
	}

	if err := nlOps.QdiscAdd(netem); err != nil {
		return fmt.Errorf("failed to apply combined netem qdisc: %w", err)
	}

	log.Printf("Applied Profile: %s with %.2f%% packet loss on %s", profile, lossPercentage, currentConfig.Interface)
	return nil
}

// InjectEntropy adds artificial packet loss via Netem (standalone, no rate limiting)
func InjectEntropy(lossPercentage float32) error {
	return ApplyNetworkProfileWithEntropy(ProfileStandard, lossPercentage)
}

func clearQdiscs(link netlink.Link) error {
	qdiscs, err := nlOps.QdiscList(link)
	if err != nil {
		return err
	}
	for _, q := range qdiscs {
		if q.Attrs().Parent == netlink.HANDLE_ROOT {
			// Ignore potential errors if qdisc acts weird on delete, though usually clean
			nlOps.QdiscDel(q)
		}
	}
	return nil
}

func getDefaultInterface() (string, error) {
	routes, err := nlOps.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return "", err
	}
	for _, r := range routes {
		if r.Dst == nil { // Default Gateway
			link, err := nlOps.LinkByIndex(r.LinkIndex)
			if err != nil {
				return "", err
			}
			if link.Attrs().Name != "" {
				return link.Attrs().Name, nil
			}
		}
	}
	return "", fmt.Errorf("no default route found")
}

// ---------------------------------------------------------------------
// CPU Governance (Cgroup v2)
// ---------------------------------------------------------------------

// ---------------------------------------------------------------------
// State Persistence
// ---------------------------------------------------------------------

const stateFilePath = "/var/lib/vex-cli/throttler-state.json"

// ThrottlerState is the persisted state written to disk so that the active
// profile survives reboots.
type ThrottlerState struct {
	ActiveProfile  string  `json:"active_profile"`
	PacketLossPct  float32 `json:"packet_loss_pct"`
	CPULimitPct    int     `json:"cpu_limit_pct"`
	LastChanged    string  `json:"last_changed"`
	ChangedBy      string  `json:"changed_by"` // "cli", "penance", "unlock"
}

// SaveState persists the current throttler state to disk.
func SaveState(state *ThrottlerState) error {
	state.LastChanged = time.Now().UTC().Format(time.RFC3339)
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal throttler state: %w", err)
	}
	// Ensure directory exists
	dir := filepath.Dir(stateFilePath)
	if _, err := fsOps.Stat(dir); os.IsNotExist(err) {
		if mkErr := os.MkdirAll(dir, 0755); mkErr != nil {
			return fmt.Errorf("failed to create state directory %s: %w", dir, mkErr)
		}
	}
	if err := fsOps.WriteFile(stateFilePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write throttler state: %w", err)
	}
	log.Printf("Throttler state persisted: profile=%s, loss=%.2f%%, cpu=%d%%, by=%s",
		state.ActiveProfile, state.PacketLossPct, state.CPULimitPct, state.ChangedBy)
	return nil
}

// LoadState reads the persisted throttler state from disk.
// Returns nil (no error) if the file does not exist.
func LoadState() (*ThrottlerState, error) {
	data, err := fsOps.ReadFile(stateFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read throttler state: %w", err)
	}
	var state ThrottlerState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("failed to parse throttler state: %w", err)
	}
	return &state, nil
}

// ---------------------------------------------------------------------
// Profile Validation & Aliases
// ---------------------------------------------------------------------

// profileAliases maps common alternative names to canonical profile values.
var profileAliases = map[string]Profile{
	"standard":   ProfileStandard,
	"uncapped":   ProfileStandard,
	"choke":      ProfileChoke,
	"throttle":   ProfileChoke,
	"dial-up":    ProfileDialUp,
	"dialup":     ProfileDialUp,
	"56k":        ProfileDialUp,
	"black-hole": ProfileBlackHole,
	"blackhole":  ProfileBlackHole,
	"blackout":   ProfileBlackHole,
	"drop":       ProfileBlackHole,
}

// ResolveProfile normalises a user-supplied profile string to a canonical Profile.
// Returns an error if the input doesn't match any known profile or alias.
func ResolveProfile(input string) (Profile, error) {
	norm := strings.ToLower(strings.TrimSpace(input))
	if p, ok := profileAliases[norm]; ok {
		return p, nil
	}
	return "", fmt.Errorf("unknown profile %q — valid profiles: standard, choke, dial-up, black-hole (aliases: blackout, dialup, 56k, uncapped)", input)
}

const cgroupMount = "/sys/fs/cgroup"

// cpuMaxCandidates lists paths to try for cpu.max, in priority order.
// The root cgroup never has cpu.max on a real host — it only exists
// inside containers where the root *is* the container's cgroup.
// On a normal NixOS/systemd host we target user.slice so the penalty
// affects all user sessions.
var cpuMaxCandidates = []string{
	filepath.Join(cgroupMount, "cpu.max"),              // containers
	filepath.Join(cgroupMount, "user.slice", "cpu.max"), // user processes (NixOS / systemd)
	filepath.Join(cgroupMount, "system.slice", "cpu.max"),
}

// resolveCPUMaxPath finds the first existing cpu.max file from the
// candidate list, or returns an error.
func resolveCPUMaxPath() (string, error) {
	for _, p := range cpuMaxCandidates {
		if _, err := fsOps.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("cgroup v2 cpu.max not found (tried %v). Ensure cgroups v2 is enabled", cpuMaxCandidates)
}

// SetCPULimit limits CPU usage via Cgroup v2 cpu.max.
// limitPercent: 0-100 (e.g., 15 for 15% of 1 core, or total capacity).
func SetCPULimit(limitPercent int) error {
	if limitPercent < 0 || limitPercent > 100 {
		return fmt.Errorf("invalid percentage: %d", limitPercent)
	}

	// Default period in microseconds (100ms)
	period := 100000

	// If limit is 100, we write "max" (unlimited)
	var quota string
	if limitPercent == 100 {
		quota = "max"
	} else {
		quotaVal := (limitPercent * period) / 100
		quota = strconv.Itoa(quotaVal)
	}

	value := fmt.Sprintf("%s %d", quota, period)

	path, err := resolveCPUMaxPath()
	if err != nil {
		return err
	}

	if err := fsOps.WriteFile(path, []byte(value), 0644); err != nil {
		return fmt.Errorf("failed to write cpu limit to %s: %w", path, err)
	}

	log.Printf("CPU Limit Set: %d%% (%s) → %s", limitPercent, strings.TrimSpace(value), path)
	return nil
}
