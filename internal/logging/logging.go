package logging

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"sync"
	"time"
)

const (
	LogFilePath = "/var/log/vex-cli.log"
)

var (
	logger   *log.Logger
	logFile  *os.File
	logMu    sync.Mutex
	initOnce sync.Once
)

// Init sets up structured logging to both stdout and the append-only log file.
// It also attempts to set chattr +a on the log file to prevent deletion.
func Init() error {
	var initErr error
	initOnce.Do(func() {
		// Open/create log file in append mode
		f, err := os.OpenFile(LogFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0664)
		if err != nil {
			// If we can't open the system log, fall back to stdout-only
			log.Printf("Logging: WARNING - Could not open %s: %v (using stdout only)", LogFilePath, err)
			logger = log.New(os.Stdout, "[VEX-CLI] ", log.LstdFlags)
			return
		}
		logFile = f

		// Set log file group to 'vex' so non-root group members can
		// append.  This only works when the daemon (root) creates the file;
		// if the file already exists with the wrong ownership it is fixed.
		setLogGroupToVex(LogFilePath)

		// Attempt chattr +a enforcement to prevent Toy deletion
		if err := enforceAppendOnly(LogFilePath); err != nil {
			log.Printf("Logging: WARNING - Could not set chattr +a: %v", err)
		}

		// Create a multi-writer that logs to both stdout and file
		multiWriter := &dualWriter{stdout: os.Stdout, file: f}
		logger = log.New(multiWriter, "[VEX-CLI] ", log.LstdFlags)

		// Override the default logger
		log.SetOutput(multiWriter)
		log.SetPrefix("[VEX-CLI] ")

		logger.Println("Logging subsystem initialized.")
	})
	return initErr
}

// LogCommand logs a command execution with compliance state
func LogCommand(command string, args string, complianceState string) {
	logMu.Lock()
	defer logMu.Unlock()

	entry := fmt.Sprintf("CMD: %s | ARGS: %s | COMPLIANCE: %s | TIME: %s",
		command, args, complianceState, time.Now().UTC().Format(time.RFC3339))

	if logger != nil {
		logger.Println(entry)
	} else {
		log.Println(entry)
	}
}

// LogEvent logs a generic event with context
func LogEvent(module string, event string, details string) {
	logMu.Lock()
	defer logMu.Unlock()

	entry := fmt.Sprintf("[%s] %s: %s", module, event, details)

	if logger != nil {
		logger.Println(entry)
	} else {
		log.Println(entry)
	}
}

// Close cleanly closes the log file
func Close() {
	if logFile != nil {
		logFile.Close()
	}
}

// setLogGroupToVex sets the group ownership of the log file to 'vex'
// and ensures the file mode is 0664 (rw-rw-r--) so that non-root vex
// group members can append to it.
func setLogGroupToVex(path string) {
	grp, err := user.LookupGroup("vex")
	if err != nil {
		return // group doesn't exist; only root can log
	}
	gid, err := strconv.Atoi(grp.Gid)
	if err != nil {
		return
	}
	// -1 for uid means keep owner unchanged
	if err := os.Chown(path, -1, gid); err != nil {
		log.Printf("Logging: WARNING - Could not chown log to vex group: %v", err)
	}
	if err := os.Chmod(path, 0664); err != nil {
		log.Printf("Logging: WARNING - Could not chmod log to 0664: %v", err)
	}
}

// enforceAppendOnly sets the append-only attribute on the log file
func enforceAppendOnly(path string) error {
	cmd := exec.Command("chattr", "+a", path)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("chattr +a failed: %w", err)
	}
	return nil
}

// dualWriter writes to both stdout and the log file
type dualWriter struct {
	stdout *os.File
	file   *os.File
}

func (w *dualWriter) Write(p []byte) (n int, err error) {
	// Always write to stdout
	n, err = w.stdout.Write(p)
	if err != nil {
		return n, err
	}

	// Also write to file
	if w.file != nil {
		w.file.Write(p)
	}

	return n, nil
}
