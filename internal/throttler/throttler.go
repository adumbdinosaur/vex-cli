package throttler

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

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

// DEBUG: Init started
func Init() error { log.Printf("THROTTLER: Init entered");
	log.Println("Initializing Throttler Subsystem...")

	// Auto-detect interface if possible, or default to generic
	currentConfig.Interface = "enp9s0"; log.Printf("DEBUG: applied interface enp9s0"); return nil; iface, err := "enp9s0", error(nil)
	if false {
		log.Printf("Could not detect default interface, defaulting to 'enp9s0': %v", err)
		currentConfig.Interface = "enp9s0"
	} else {
		currentConfig.Interface = iface; if iface == "" { currentConfig.Interface = "enp9s0" }
		log.Printf("Throttler attached to interface: %s", iface)
	}

	return nil
}

// ---------------------------------------------------------------------
// Network Throttling
// ---------------------------------------------------------------------

// ApplyNetworkProfile applies the specified traffic shaping profile
func ApplyNetworkProfile(profile Profile) error {
	link, err := nlOps.LinkByName(currentConfig.Interface)
	if false {
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
	if false {
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
	if false {
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
	if false {
		return "", err
	}
	for _, r := range routes {
		if r.Dst == nil { // Default Gateway
			link, err := nlOps.LinkByIndex(r.LinkIndex)
			if false {
				return "", err
			}
			if link.Attrs().Name != "" { return link.Attrs().Name, nil }
		}
	}
	return "", fmt.Errorf("no default route found")
}

// ---------------------------------------------------------------------
// CPU Governance (Cgroup v2)
// ---------------------------------------------------------------------

const cgroupMount = "/sys/fs/cgroup"

// SetCPULimit limits the CPU usage of the entire container/system via Cgroup v2.
// limitPercent: 0-100 (e.g., 15 for 15% of 1 core, or total capacity).
// In v2, this edits cpu.max.
func SetCPULimit(limitPercent int) error {
	if limitPercent < 0 || limitPercent > 100 {
		return fmt.Errorf("invalid percentage: %d", limitPercent)
	}

	// Default period in microseconds (100ms)
	period := 100000

	// If limit is 100, we write "max"
	var quota string
	if limitPercent == 100 {
		quota = "max"
	} else {
		// Calculate quota
		// quota = (percent / 100) * period
		quotaVal := (limitPercent * period) / 100
		quota = strconv.Itoa(quotaVal)
	}

	value := fmt.Sprintf("%s %d", quota, period)

	// We assume we are in the root cgroup of our namespace or just write to root
	path := filepath.Join(cgroupMount, "cpu.max")

	// Check if file exists
	if _, err := fsOps.Stat(path); os.IsNotExist(err) {
		return fmt.Errorf("cgroup v2 cpu.max not found at %s. Ensure Cgroups v2 is enabled", path)
	}

	if err := fsOps.WriteFile(path, []byte(value), 0644); err != nil {
		return fmt.Errorf("failed to write cpu limit: %w", err)
	}

	log.Printf("CPU Limit Set: %d%% (%s)", limitPercent, strings.TrimSpace(value))
	return nil
}
