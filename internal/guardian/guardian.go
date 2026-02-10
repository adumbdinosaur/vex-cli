package guardian

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net"
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
		Name:     "filter-output",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityFilter,
	}
	conn.AddChain(chain)

	// Resolve each blocked domain to IPs and add drop rules per IP.
	// This replaces the previous (broken) SNI payload matching approach
	// which lacked a Cmp expression and dropped ALL port-443 traffic.
	totalRules := 0
	for _, domain := range blockedDomains {
		ips := resolveDomain(domain)
		if len(ips) == 0 {
			log.Printf("Guardian: WARNING — could not resolve %s, skipping", domain)
			continue
		}
		for _, ip := range ips {
			ip4 := ip.To4()
			if ip4 == nil {
				continue // IPv4 table only; skip IPv6 addresses
			}
			conn.AddRule(&nftables.Rule{
				Table: table,
				Chain: chain,
				Exprs: buildIPBlockExprs(ip4),
			})
			totalRules++
		}
		log.Printf("Guardian: Blocked %s (%d IPs resolved)", domain, len(ips))
	}

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("failed to apply firewall rules: %w", err)
	}

	log.Printf("Guardian: NFTables 'vex-guardian' initialized with %d IP block rules for %d domains.", totalRules, len(blockedDomains))
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

// buildIPBlockExprs creates nftables expressions that drop all outbound TCP
// traffic to the given IPv4 address.  This replaces the previous broken SNI
// matching which lacked a comparison expression and dropped all port-443 traffic.
func buildIPBlockExprs(ip4 net.IP) []expr.Any {
	return []expr.Any{
		// meta l4proto tcp
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},

		// Match destination IP address (offset 16 in IPv4 header, 4 bytes)
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       16,
			Len:          4,
		},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte(ip4.To4())},

		// Drop verdict
		&expr.Verdict{Kind: expr.VerdictDrop},
	}
}

// resolveDomain resolves a domain name (and its www. variant) to IP addresses.
func resolveDomain(domain string) []net.IP {
	seen := make(map[string]bool)
	var result []net.IP

	candidates := []string{domain}
	if !strings.HasPrefix(domain, "www.") {
		candidates = append(candidates, "www."+domain)
	}

	for _, d := range candidates {
		addrs, err := net.LookupHost(d)
		if err != nil {
			log.Printf("Guardian: DNS lookup for %s: %v", d, err)
			continue
		}
		for _, addr := range addrs {
			if seen[addr] {
				continue
			}
			seen[addr] = true
			if ip := net.ParseIP(addr); ip != nil {
				result = append(result, ip)
			}
		}
	}

	return result
}

// -- Initialization --

var (
	fsOps  FileSystem  = &RealFileSystem{}
	sysOps SystemOps   = &RealSystemOps{}
	fwOps  FirewallOps = &RealFirewallOps{}

	// Global eBPF monitor instance
	ebpfMon *EBPFMonitor
	useEBPF bool = true // Default to trying eBPF, fallback to /proc on error

	// DNS refresh: periodically re-resolve blocked domains so that
	// IP-based firewall rules stay current when CDN addresses rotate.
	refreshTicker *time.Ticker
	refreshDone   chan struct{}
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
		} else if len(blockedDomains) > 0 {
			startDNSRefresh()
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

// Shutdown performs cleanup of guardian resources: eBPF monitor, DNS refresh, and nftables rules.
func Shutdown() error {
	var errs []string
	stopDNSRefresh()
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
// DNS resolution is performed inside fwOps.Setup to obtain current IPs.
func rebuildFirewall() error {
	// Clear first (ignore errors — table might not exist yet)
	_ = fwOps.Clear()
	if len(activeDomains) == 0 {
		stopDNSRefresh()
		return nil
	}
	if err := fwOps.Setup(activeDomains); err != nil {
		return err
	}
	// Ensure periodic IP re-resolution is running
	if refreshTicker == nil {
		startDNSRefresh()
	}
	return nil
}

// startDNSRefresh begins a background goroutine that periodically re-resolves
// blocked domains and rebuilds the firewall rules so IP changes are tracked.
func startDNSRefresh() {
	stopDNSRefresh()
	refreshDone = make(chan struct{})
	refreshTicker = time.NewTicker(30 * time.Minute)
	go func() {
		for {
			select {
			case <-refreshTicker.C:
				if len(activeDomains) > 0 {
					log.Println("Guardian: Refreshing domain IP resolutions...")
					_ = fwOps.Clear()
					if err := fwOps.Setup(activeDomains); err != nil {
						log.Printf("Guardian: IP refresh failed: %v", err)
					}
				}
			case <-refreshDone:
				return
			}
		}
	}()
	log.Println("Guardian: DNS refresh goroutine started (30m interval)")
}

// stopDNSRefresh tears down the periodic DNS resolution goroutine.
func stopDNSRefresh() {
	if refreshTicker != nil {
		refreshTicker.Stop()
		refreshTicker = nil
	}
	if refreshDone != nil {
		select {
		case <-refreshDone:
			// already closed
		default:
			close(refreshDone)
		}
		refreshDone = nil
	}
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

// saveForbiddenApps persists the forbidden apps list to forbidden-apps.json.
func saveForbiddenApps(apps []string) error {
	config := struct {
		Apps []string `json:"forbidden_apps"`
	}{Apps: apps}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal forbidden apps: %w", err)
	}

	if err := fsOps.WriteFile("forbidden-apps.json", data, 0644); err != nil {
		return fmt.Errorf("failed to write forbidden-apps.json: %w", err)
	}
	return nil
}

// GetForbiddenApps returns the current forbidden apps list.
func GetForbiddenApps() []string {
	return loadForbiddenApps()
}

// AddForbiddenApp adds an application to the forbidden apps list.
// Returns true if the app was actually added (false if already present).
func AddForbiddenApp(app string) (bool, error) {
	app = strings.ToLower(strings.TrimSpace(app))
	if app == "" {
		return false, fmt.Errorf("empty app name")
	}

	apps := loadForbiddenApps()

	// Check for duplicate
	for _, a := range apps {
		if strings.ToLower(a) == app {
			return false, nil
		}
	}

	apps = append(apps, app)
	if err := saveForbiddenApps(apps); err != nil {
		return false, err
	}

	// Update eBPF monitor if active
	if ebpfMon != nil && ebpfMon.IsEnabled() {
		ebpfMon.UpdateForbiddenApps()
	}

	log.Printf("Guardian: App added to forbidden list: %s (total: %d)", app, len(apps))
	return true, nil
}

// RemoveForbiddenApp removes an application from the forbidden apps list.
// Returns true if the app was actually removed (false if not found).
func RemoveForbiddenApp(app string) (bool, error) {
	app = strings.ToLower(strings.TrimSpace(app))
	if app == "" {
		return false, fmt.Errorf("empty app name")
	}

	apps := loadForbiddenApps()

	idx := -1
	for i, a := range apps {
		if strings.ToLower(a) == app {
			idx = i
			break
		}
	}
	if idx == -1 {
		return false, nil
	}

	apps = append(apps[:idx], apps[idx+1:]...)
	if err := saveForbiddenApps(apps); err != nil {
		return false, err
	}

	// Update eBPF monitor if active
	if ebpfMon != nil && ebpfMon.IsEnabled() {
		ebpfMon.UpdateForbiddenApps()
	}

	log.Printf("Guardian: App removed from forbidden list: %s (total: %d)", app, len(apps))
	return true, nil
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
