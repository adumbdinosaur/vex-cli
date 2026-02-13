package surveillance

import (
	"os"
	"log"
	"strings"
	"sync"
	"time"

	evdev "github.com/holoplot/go-evdev"
)

// Metrics holds the surveillance data
type Metrics struct {
	mu             sync.Mutex
	Keystrokes     uint64
	LinesCompleted uint64 // Heuristic: counting 'Enter' keys
	StartTime      time.Time
}

var (
	GlobalMetrics = &Metrics{StartTime: time.Now()}
	activeDevices []InputDevice
)

// Init initializes the surveillance subsystem
func Init() error {
	log.Println("Initializing Surveillance Subsystem...")

	// Check for explicit device path override from environment
	if devicePath := os.Getenv("VEX_DEVICE_PATH"); devicePath != "" {
		log.Printf("Surveillance: Using explicit device path: %s", devicePath)
		if err := listenToDevice(devicePath); err != nil {
			log.Printf("Surveillance: Failed to attach to %s: %v", devicePath, err)
		} else {
			go metricReporter()
			return nil
		}
		// Fall through to auto-detection if explicit path fails
	}

	// 1. Scan for Input Devices
	// Uses wrapper evOps
	devices, err := evOps.ListInputDevices()
	if err != nil {
		log.Printf("Surveillance: Failed to list input devices: %v", err)
		return nil
	}

	for _, dev := range devices {
		if isKeyboard(dev) {
			log.Printf("Surveillance: Attaching to keyboard: %s (%s)", dev.Name(), dev.Fn())
			// Open the device for reading
			if err := listenToDevice(dev.Fn()); err != nil {
				log.Printf("Surveillance: Failed to attach to %s: %v", dev.Fn(), err)
			}
		}
	}

	if len(activeDevices) == 0 {
		log.Println("Surveillance: Warning - No keyboards detected to monitor.")
	}

	// Start metric logger
	go metricReporter()

	return nil
}

func isKeyboard(dev InputDevice) bool {
	// Check capabilities for EV_KEY
	// Helper to access capabilities map
	caps := dev.Capabilities()

	// We need to iterate the map manually since the types are from the external lib
	// CapabilityType is int, CapabilityCode is int
	// But in our wrapper/interface, we expose the map directly from the struct which uses evdev types.

	for capType, codes := range caps {
		if capType == evdev.EV_KEY {
			for _, code := range codes {
				if code == evdev.KEY_A {
					return true
				}
			}
		}
	}

	// Fallback check on name
	if strings.Contains(strings.ToLower(dev.Name()), "keyboard") {
		return true
	}

	return false
}

func listenToDevice(path string) error {
	dev, err := evOps.Open(path)
	if err != nil {
		return err
	}

	activeDevices = append(activeDevices, dev)

	go func(d InputDevice) {
		defer d.Close()
		log.Printf("Surveillance: Started listener for %s", d.Name())

		for {
			event, err := d.ReadOne()
			if err != nil {
				log.Printf("Surveillance: Error reading %s: %v", d.Name(), err)
				return // Device likely disconnected
			}

			if event.Type == evdev.EV_KEY && event.Value == 1 { // Key Press (not hold/release)
				processKey(uint16(event.Code))
			}
		}
	}(dev)

	return nil
}

func processKey(code uint16) {
	// Apply latency injection if configured
	delay := getLatencyDelay()
	if delay > 0 {
		time.Sleep(delay)
	}

	GlobalMetrics.mu.Lock()
	defer GlobalMetrics.mu.Unlock()

	GlobalMetrics.Keystrokes++

	// KEY_ENTER is 28
	if code == evdev.KEY_ENTER {
		GlobalMetrics.LinesCompleted++
	}

	// Zero-Storage Policy: We do NOT log the keycode or create a buffer.
}

func metricReporter() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		GlobalMetrics.mu.Lock()
		kpm := float64(GlobalMetrics.Keystrokes) / time.Since(GlobalMetrics.StartTime).Minutes()
		log.Printf("Surveillance Stats: %d keystrokes total | %.2f KPM | %d lines",
			GlobalMetrics.Keystrokes, kpm, GlobalMetrics.LinesCompleted)
		GlobalMetrics.mu.Unlock()
	}
}

// GetCurrentKPM returns the current keystrokes-per-minute rate
func GetCurrentKPM() float64 {
	GlobalMetrics.mu.Lock()
	defer GlobalMetrics.mu.Unlock()

	elapsed := time.Since(GlobalMetrics.StartTime).Minutes()
	if elapsed <= 0 {
		return 0
	}
	return float64(GlobalMetrics.Keystrokes) / elapsed
}

// GetMetricSnapshot returns a snapshot of current keystrokes and lines completed
func GetMetricSnapshot() (uint64, uint64) {
	GlobalMetrics.mu.Lock()
	defer GlobalMetrics.mu.Unlock()
	return GlobalMetrics.Keystrokes, GlobalMetrics.LinesCompleted
}

// ---------------------------------------------------------------------
// Latency Injection via uinput
// ---------------------------------------------------------------------

var (
	latencyMu    sync.Mutex
	latencyDelay time.Duration
)

// InjectLatency sets the programmable delay for input events.
// When delayMs > 0, the surveillance listener intercepts keyboard events,
// grabs the device, and re-emits them through a uinput virtual device
// after the specified delay. Setting delayMs to 0 disables injection.
func InjectLatency(delayMs int) error {
	latencyMu.Lock()
	defer latencyMu.Unlock()

	if delayMs < 0 {
		delayMs = 0
	}

	latencyDelay = time.Duration(delayMs) * time.Millisecond
	log.Printf("Surveillance: Input latency set to %dms", delayMs)
	return nil
}

// getLatencyDelay returns the current latency delay setting
func getLatencyDelay() time.Duration {
	latencyMu.Lock()
	defer latencyMu.Unlock()
	return latencyDelay
}
