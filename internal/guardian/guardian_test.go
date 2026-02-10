package guardian

import (
	"io/fs"
	"os"
	"syscall"
	"testing"
)

// -- Mocks --

type MockFileSystem struct {
	ReadDirFunc   func(name string) ([]fs.DirEntry, error)
	ReadFileFunc  func(name string) ([]byte, error)
	WriteFileFunc func(name string, data []byte, perm os.FileMode) error
	StatFunc      func(name string) (os.FileInfo, error)

	WrittenFiles map[string]string
}

func (m *MockFileSystem) ReadDir(name string) ([]fs.DirEntry, error) {
	if m.ReadDirFunc != nil {
		return m.ReadDirFunc(name)
	}
	return nil, nil
}
func (m *MockFileSystem) ReadFile(name string) ([]byte, error) {
	if m.ReadFileFunc != nil {
		return m.ReadFileFunc(name)
	}
	return nil, os.ErrNotExist
}
func (m *MockFileSystem) WriteFile(name string, data []byte, perm os.FileMode) error {
	if m.WrittenFiles == nil {
		m.WrittenFiles = make(map[string]string)
	}
	m.WrittenFiles[name] = string(data)
	if m.WriteFileFunc != nil {
		return m.WriteFileFunc(name, data, perm)
	}
	return nil
}
func (m *MockFileSystem) Stat(name string) (os.FileInfo, error) {
	if m.StatFunc != nil {
		return m.StatFunc(name)
	}
	return nil, nil
}

type MockSystemOps struct {
	GetpidFunc func() int
	KillFunc   func(pid int, sig syscall.Signal) error
	KilledPids []int
}

func (m *MockSystemOps) Getpid() int {
	if m.GetpidFunc != nil {
		return m.GetpidFunc()
	}
	return 1
}
func (m *MockSystemOps) Kill(pid int, sig syscall.Signal) error {
	m.KilledPids = append(m.KilledPids, pid)
	if m.KillFunc != nil {
		return m.KillFunc(pid, sig)
	}
	return nil
}

type MockFirewallOps struct {
	SetupFunc func(blockedDomains []string) error
}

func (m *MockFirewallOps) Setup(blockedDomains []string) error {
	if m.SetupFunc != nil {
		return m.SetupFunc(blockedDomains)
	}
	return nil
}

// -- Helpers --

type mockDirEntry struct {
	name  string
	isDir bool
}

func (m mockDirEntry) Name() string               { return m.name }
func (m mockDirEntry) IsDir() bool                { return m.isDir }
func (m mockDirEntry) Type() fs.FileMode          { return 0 }
func (m mockDirEntry) Info() (fs.FileInfo, error) { return nil, nil }

// -- Tests --

func TestSetOOMScore(t *testing.T) {
	mockFS := &MockFileSystem{}
	fsOps = mockFS

	err := SetOOMScore(-1000)
	if err != nil {
		t.Fatalf("SetOOMScore failed: %v", err)
	}

	content, ok := mockFS.WrittenFiles["/proc/self/oom_score_adj"]
	if !ok {
		t.Fatal("Did not write to oom_score_adj")
	}
	if content != "-1000" {
		t.Errorf("Expected -1000, got %s", content)
	}
}

func TestScanAndReap_KillsForbidden(t *testing.T) {
	// Setup Mocks
	mockFS := &MockFileSystem{
		ReadDirFunc: func(name string) ([]fs.DirEntry, error) {
			return []fs.DirEntry{
				mockDirEntry{name: "100", isDir: true}, // Bad
				mockDirEntry{name: "200", isDir: true}, // Good
			}, nil
		},
		ReadFileFunc: func(name string) ([]byte, error) {
			if name == "forbidden-apps.json" {
				// Return default not found -> uses internal defaults (which contains "steam")
				return nil, os.ErrNotExist
			}
			if name == "/proc/100/comm" {
				return []byte("steam"), nil
			}
			if name == "/proc/100/cmdline" {
				return []byte("steam -silent"), nil
			}
			if name == "/proc/200/comm" {
				return []byte("bash"), nil
			}
			if name == "/proc/200/cmdline" {
				return []byte("/bin/bash"), nil
			}
			return nil, os.ErrNotExist
		},
	}
	mockSys := &MockSystemOps{
		GetpidFunc: func() int { return 999 },
	}

	// Inject
	fsOps = mockFS
	sysOps = mockSys

	scanAndReap()

	// Assertions
	if len(mockSys.KilledPids) != 1 {
		t.Fatalf("Expected 1 killed pid, got %d", len(mockSys.KilledPids))
	}
	if mockSys.KilledPids[0] != 100 {
		t.Errorf("Expected to kill PID 100, killed %d", mockSys.KilledPids[0])
	}
}

func TestIsForbidden_MatchesCmdline(t *testing.T) {
	mockFS := &MockFileSystem{
		ReadFileFunc: func(name string) ([]byte, error) {
			if name == "/proc/500/comm" {
				return []byte("python3"), nil
			}
			if name == "/proc/500/cmdline" {
				// Fake discord hidden in python arg
				return []byte("/usr/bin/python3\x00/opt/discord/Discord"), nil
			}
			return nil, os.ErrNotExist
		},
	}
	fsOps = mockFS

	apps := []string{"discord"}
	if !isForbidden(500, apps) {
		t.Error("PID 500 should be forbidden (cmdline match), was false")
	}
}

func TestScanAndReap_UsesJsonConfig(t *testing.T) {
	// Setup Mocks
	mockFS := &MockFileSystem{
		ReadDirFunc: func(name string) ([]fs.DirEntry, error) {
			return []fs.DirEntry{
				mockDirEntry{name: "300", isDir: true}, // Should be killed by JSON rule
				mockDirEntry{name: "400", isDir: true}, // Should be safe
			}, nil
		},
		ReadFileFunc: func(name string) ([]byte, error) {
			if name == "forbidden-apps.json" {
				return []byte(`{"forbidden_apps": ["malware"]}`), nil
			}
			if name == "/proc/300/comm" {
				return []byte("malware"), nil
			}
			if name == "/proc/300/cmdline" {
				return []byte("./malware"), nil
			}
			if name == "/proc/400/comm" {
				return []byte("safeapp"), nil
			}
			if name == "/proc/400/cmdline" {
				return []byte("./safeapp"), nil
			}
			return nil, os.ErrNotExist
		},
	}
	mockSys := &MockSystemOps{
		GetpidFunc: func() int { return 999 },
	}

	// Inject
	fsOps = mockFS
	sysOps = mockSys

	scanAndReap()

	// Assertions
	if len(mockSys.KilledPids) != 1 {
		t.Fatalf("Expected 1 killed pid, got %d", len(mockSys.KilledPids))
	}
	if mockSys.KilledPids[0] != 300 {
		t.Errorf("Expected to kill PID 300 (malware), killed %v", mockSys.KilledPids)
	}
}

func TestScanAndReap_CreatesDefaultConfig(t *testing.T) {
	mockFS := &MockFileSystem{
		ReadFileFunc: func(name string) ([]byte, error) {
			if name == "forbidden-apps.json" {
				return nil, os.ErrNotExist
			}
			return nil, os.ErrNotExist
		},
		ReadDirFunc: func(name string) ([]fs.DirEntry, error) {
			return []fs.DirEntry{}, nil
		},
	}
	fsOps = mockFS
	sysOps = &MockSystemOps{}

	scanAndReap()

	if _, ok := mockFS.WrittenFiles["forbidden-apps.json"]; !ok {
		t.Error("Expected forbidden-apps.json to be created, but it was not")
	}
}
