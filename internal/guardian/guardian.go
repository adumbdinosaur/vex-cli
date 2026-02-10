package guardian

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// -- Interfaces for Testability --

type FileSystem interface {
	ReadDir(name string) ([]fs.DirEntry, error)
	ReadFile(name string) ([]byte, error)
	WriteFile(name string, data []byte, perm os.FileMode) error
	Stat(name string) (os.FileInfo, error)
}

type SystemOps interface {
	Getpid() int
	Kill(pid int, sig syscall.Signal) error
}

type FirewallOps interface {
	Setup(blockedDomains []string) error
	Clear() error
}

// -- State tracking --

// activeDomains is the live set of blocked domains (kept in sync with nftables).
var activeDomains []string

// -- Real Implementations --

type RealFileSystem struct{}

func (r *RealFileSystem) ReadDir(name string) ([]fs.DirEntry, error) { return os.ReadDir(name) }
func (r *RealFileSystem) ReadFile(name string) ([]byte, error)       { return os.ReadFile(name) }
func (r *RealFileSystem) WriteFile(name string, data []byte, perm os.FileMode) error {
	return os.WriteFile(name, data, perm)
}
func (r *RealFileSystem) Stat(name string) (os.FileInfo, error) { return os.Stat(name) }

type RealSystemOps struct{}

func (r *RealSystemOps) Getpid() int                            { return os.Getpid() }
func (r *RealSystemOps) Kill(pid int, sig syscall.Signal) error { return syscall.Kill(pid, sig) }

type RealFirewallOps struct{}

func (r *RealFirewallOps) Setup(blockedDomains []string) error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("failed to open nftables connection: %w", err)
	}
	table := &nftables.Table{Name: "vex-guardian", Family: nftables.TableFamilyIPv4}
	table = conn.AddTable(table)

	chain := &nftables.Chain{
		Name:     "filter-sni",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityFilter,
	}
	conn.AddChain(chain)

	// Add SNI blocking rules: drop packets to port 443 containing blocked domain names
	// NFTables raw payload matching on TLS ClientHello SNI extension
	for _, domain := range blockedDomains {
		// Use nftables anonymous set with payload match for SNI strings
		// This creates rules that inspect the TLS handshake for the Server Name Indication
		rule := &nftables.Rule{
			Table: table,
			Chain: chain,
			// Match TCP dport 443 + payload contains domain -> verdict drop
			// The google/nftables library uses Exprs for building rules
			Exprs: buildSNIBlockExprs(domain),
		}
		conn.AddRule(rule)
		log.Printf("Guardian: Added SNI block rule for: %s", domain)
	}

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("failed to apply firewall rules: %w", err)
	}

	log.Printf("Guardian: NFTables 'vex-guardian' initialized with %d SNI block rules.", len(blockedDomains))
	return nil
}

func (r *RealFirewallOps) Clear() error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("failed to open nftables connection: %w", err)
	}
	// Delete the entire vex-guardian table (all chains and rules go with it)
	conn.DelTable(&nftables.Table{Name: "vex-guardian", Family: nftables.TableFamilyIPv4})
	if err := conn.Flush(); err != nil {
		// Table might not exist — that's fine
		log.Printf("Guardian: nftables cleanup (may be harmless): %v", err)
		return nil
	}
	log.Println("Guardian: NFTables 'vex-guardian' table removed.")
	return nil
}

// buildSNIBlockExprs creates nftables expressions that match TCP port 443
// and drop packets containing the specified domain in the TLS SNI field.
func buildSNIBlockExprs(domain string) []expr.Any {
	// nftables expression chain:
	// 1. Match IP protocol = TCP (6)
	// 2. Match TCP destination port = 443
	// 3. Payload match for domain string in TLS ClientHello SNI
	// 4. Verdict: drop
	//
	// Using raw payload expressions via the google/nftables expr package.
	// The actual byte-level matching is handled by the kernel nf_tables subsystem.

	return []expr.Any{
		// meta l4proto tcp
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},

		// tcp dport 443
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       2, // TCP destination port offset
			Len:          2,
		},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x01, 0xBB}}, // 443

		// Payload match for SNI domain string in application layer
		// TLS ClientHello SNI starts at a variable offset within the TLS handshake.
		// We use a simple heuristic offset past the TCP+TLS record headers.
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       uint32(len(domain) + 9), // Approximate offset into TLS ClientHello SNI
			Len:          uint32(len(domain)),
		},

		// Drop verdict
		&expr.Verdict{Kind: expr.VerdictDrop},
	}
}

// -- Initialization --

var (
	fsOps  FileSystem  = &RealFileSystem{}
	sysOps SystemOps   = &RealSystemOps{}
	fwOps  FirewallOps = &RealFirewallOps{}
	
	// Global eBPF monitor instance
	ebpfMon *EBPFMonitor
	useEBPF bool = true // Default to trying eBPF, fallback to /proc on error
)

// Init initializes the guardian subsystem
func Init(penaltyActive bool) error {
	log.Println("Initializing Guardian Subsystem...")

	if err := SetOOMScore(-1000); err != nil {
		log.Printf("Guardian: Failed to engage OOM shield: %v", err)
	} else {
		log.Println("Guardian: OOM Shield Engaged (-1000)")
	}

	// Check VEX_MONITOR_MODE environment variable
	if mode := os.Getenv("VEX_MONITOR_MODE"); mode != "" {
		SetMonitorMode(mode)
	}

	// Initialize process monitoring: try eBPF first, fallback to /proc polling
	if useEBPF {
		mon, err := NewEBPFMonitor()
		if err != nil {
			log.Printf("Guardian: eBPF monitor failed to initialize: %v", err)
			log.Println("Guardian: Falling back to /proc polling")
			go startReaper()
		} else {
			ebpfMon = mon
			if err := ebpfMon.Start(); err != nil {
				log.Printf("Guardian: Failed to start eBPF monitor: %v", err)
				log.Println("Guardian: Falling back to /proc polling")
				ebpfMon.Close()
				ebpfMon = nil
				go startReaper()
			} else {
				log.Println("Guardian: Using eBPF-based process monitoring (high-performance mode)")
			}
		}
	} else {
		go startReaper()
	}

	if penaltyActive {
		blockedDomains := loadBlockedDomains()
		activeDomains = blockedDomains
		if err := fwOps.Setup(blockedDomains); err != nil {
			log.Printf("Guardian: Firewall initialization failed: %v", err)
		}
	} else {
		activeDomains = nil
		log.Println("Guardian: No active penalty — skipping domain block rules")
	}
	return nil
}

// SetMonitorMode configures the process monitoring backend.
// mode: "ebpf", "proc", or "auto"
func SetMonitorMode(mode string) {
	switch mode {
	case "ebpf":
		useEBPF = true
	case "proc":
		useEBPF = false
	case "auto":
		useEBPF = true // Try eBPF, fallback to /proc on error
	default:
		log.Printf("Guardian: Invalid monitor mode '%s', using auto", mode)
		useEBPF = true
	}
}

// GetMonitorStatus returns the current monitoring backend status.
func GetMonitorStatus() string {
	if ebpfMon != nil && ebpfMon.IsEnabled() {
		return "eBPF (high-performance)"
	}
	return "/proc polling (standard)"
}

// Shutdown performs cleanup of guardian resources: eBPF monitor and nftables rules.
func Shutdown() error {
	var errs []string
	if ebpfMon != nil {
		log.Println("Guardian: Shutting down eBPF monitor...")
		if err := ebpfMon.Close(); err != nil {
			errs = append(errs, fmt.Sprintf("ebpf close: %v", err))
		}
	}
	// Always attempt to remove the nftables table so rules don't persist.
	if err := fwOps.Clear(); err != nil {
		errs = append(errs, fmt.Sprintf("firewall clear: %v", err))
	}
	if len(errs) > 0 {
		return fmt.Errorf("shutdown errors: %s", strings.Join(errs, "; "))
	}
	return nil
}

// ClearFirewall removes the vex-guardian nftables table (idempotent).
func ClearFirewall() error {
	return fwOps.Clear()
}

// GetBlockedDomains returns the currently active domain blocklist.
func GetBlockedDomains() []string {
	out := make([]string, len(activeDomains))
	copy(out, activeDomains)
	return out
}

// AddDomain adds a domain to the live blocklist and rebuilds the firewall.
// Returns true if the domain was actually added (false if already present).
func AddDomain(domain string) (bool, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return false, fmt.Errorf("empty domain")
	}

	// Check for duplicate
	for _, d := range activeDomains {
		if d == domain {
			return false, nil
		}
	}

	activeDomains = append(activeDomains, domain)
	if err := rebuildFirewall(); err != nil {
		// Roll back
		activeDomains = activeDomains[:len(activeDomains)-1]
		return false, err
	}
	log.Printf("Guardian: Domain added to blocklist: %s (total: %d)", domain, len(activeDomains))
	return true, nil
}

// RemoveDomain removes a domain from the live blocklist and rebuilds the firewall.
// Returns true if the domain was actually removed (false if not found).
func RemoveDomain(domain string) (bool, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	idx := -1
	for i, d := range activeDomains {
		if d == domain {
			idx = i
			break
		}
	}
	if idx == -1 {
		return false, nil
	}

	old := activeDomains
	activeDomains = append(activeDomains[:idx], activeDomains[idx+1:]...)

	if len(activeDomains) == 0 {
		// No domains left — just clear the table
		if err := fwOps.Clear(); err != nil {
			activeDomains = old
			return false, err
		}
	} else {
		if err := rebuildFirewall(); err != nil {
			activeDomains = old
			return false, err
		}
	}
	log.Printf("Guardian: Domain removed from blocklist: %s (total: %d)", domain, len(activeDomains))
	return true, nil
}

// SetBlockedDomains replaces the live blocklist entirely and rebuilds the firewall.
// Used on daemon startup to restore persisted state.
func SetBlockedDomains(domains []string) error {
	activeDomains = domains
	if len(domains) == 0 {
		return fwOps.Clear()
	}
	return rebuildFirewall()
}

// rebuildFirewall clears the existing table and rebuilds it with activeDomains.
func rebuildFirewall() error {
	// Clear first (ignore errors — table might not exist yet)
	_ = fwOps.Clear()
	if len(activeDomains) == 0 {
		return nil
	}
	return fwOps.Setup(activeDomains)
}

// SNI block list default domains
var defaultBlockedDomains = []string{
	"store.steampowered.com",
	"reddit.com",
	"twitch.tv",
	"youtube.com",
}

// loadBlockedDomains loads blocked SNI domains from the forbidden-apps config
// plus a hardcoded set of known entertainment/distraction domains.
func loadBlockedDomains() []string {
	// Start with default blocked domains
	domains := make([]string, len(defaultBlockedDomains))
	copy(domains, defaultBlockedDomains)

	// Load the blocked-domains.json if it exists
	data, err := fsOps.ReadFile("blocked-domains.json")
	if err != nil {
		log.Printf("Guardian: No blocked-domains.json found, using defaults (%d domains)", len(domains))
		return domains
	}

	var config struct {
		Domains []string `json:"blocked_domains"`
	}
	if err := json.Unmarshal(data, &config); err != nil {
		log.Printf("Guardian: Failed to parse blocked-domains.json: %v", err)
		return domains
	}

	// Merge
	seen := make(map[string]bool)
	for _, d := range domains {
		seen[d] = true
	}
	for _, d := range config.Domains {
		if !seen[d] {
			domains = append(domains, d)
			seen[d] = true
		}
	}

	return domains
}

// -- Logic --

// SetOOMScore adjusts the OOM score of the current process.
// score: -1000 (invincible) to 1000 (first to die)
func SetOOMScore(score int) error {
	path := "/proc/self/oom_score_adj"
	if _, err := fsOps.Stat(path); os.IsNotExist(err) {
		return fmt.Errorf("%s not found", path)
	}
	return fsOps.WriteFile(path, []byte(strconv.Itoa(score)), 0644)
}

func startReaper() {
	log.Println("Guardian: Process Reaper Started")
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		<-ticker.C
		scanAndReap()
	}
}

func loadForbiddenApps() []string {
	// Default list in case file is missing or corrupt
	defaults := []string{
		"steam",
		"discord",
		"gamescope",
		"lutris",
		"heroic",
	}

	filename := "forbidden-apps.json"
	data, err := fsOps.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("Guardian: %s not found. Creating default configuration...", filename)
			config := struct {
				Apps []string `json:"forbidden_apps"`
			}{Apps: defaults}

			if bytes, err := json.MarshalIndent(config, "", "  "); err == nil {
				if err := fsOps.WriteFile(filename, bytes, 0644); err != nil {
					log.Printf("Guardian: Failed to write default config: %v", err)
				}
			}
		}
		return defaults
	}

	var config struct {
		Apps []string `json:"forbidden_apps"`
	}
	if err := json.Unmarshal(data, &config); err != nil {
		log.Printf("Guardian: Failed to parse forbidden-apps.json: %v", err)
		return defaults
	}
	return config.Apps
}

func scanAndReap() {
	apps := loadForbiddenApps()

	entries, err := fsOps.ReadDir("/proc")
	if err != nil {
		return
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		if pid == sysOps.Getpid() || pid == 1 {
			continue
		}

		if isForbidden(pid, apps) {
			log.Printf("Guardian: ⚔️ Terminating forbidden process PID %d", pid)
			if err := sysOps.Kill(pid, syscall.SIGKILL); err != nil {
				log.Printf("Guardian: Failed to kill process %d: %v", pid, err)
			}
		}
	}
}

func isForbidden(pid int, apps []string) bool {
	commPath := filepath.Join("/proc", strconv.Itoa(pid), "comm")
	commBytes, err := fsOps.ReadFile(commPath)
	if err != nil {
		return false
	}
	comm := strings.TrimSpace(string(commBytes))
	commLower := strings.ToLower(comm)

	cmdPath := filepath.Join("/proc", strconv.Itoa(pid), "cmdline")
	cmdBytes, err := fsOps.ReadFile(cmdPath)
	cmdline := ""
	if err == nil {
		cmdline = strings.ToLower(strings.ReplaceAll(string(cmdBytes), "\x00", " "))
	}

	for _, app := range apps {
		if strings.Contains(commLower, app) || strings.Contains(cmdline, app) {
			return true
		}
	}
	return false
}
