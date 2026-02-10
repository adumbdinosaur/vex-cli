package throttler

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
)

// -- Mocks --

type MockNetlinkOps struct {
	LinkByNameFunc  func(name string) (netlink.Link, error)
	QdiscListFunc   func(link netlink.Link) ([]netlink.Qdisc, error)
	QdiscAddFunc    func(qdisc netlink.Qdisc) error
	QdiscDelFunc    func(qdisc netlink.Qdisc) error
	RouteListFunc   func(link netlink.Link, family int) ([]netlink.Route, error)
	LinkByIndexFunc func(index int) (netlink.Link, error)
}

func (m *MockNetlinkOps) LinkByName(name string) (netlink.Link, error) {
	if m.LinkByNameFunc != nil {
		return m.LinkByNameFunc(name)
	}
	return &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: name, Index: 1}}, nil
}
func (m *MockNetlinkOps) QdiscList(link netlink.Link) ([]netlink.Qdisc, error) {
	if m.QdiscListFunc != nil {
		return m.QdiscListFunc(link)
	}
	return []netlink.Qdisc{}, nil
}
func (m *MockNetlinkOps) QdiscAdd(qdisc netlink.Qdisc) error {
	if m.QdiscAddFunc != nil {
		return m.QdiscAddFunc(qdisc)
	}
	return nil
}
func (m *MockNetlinkOps) QdiscDel(qdisc netlink.Qdisc) error {
	if m.QdiscDelFunc != nil {
		return m.QdiscDelFunc(qdisc)
	}
	return nil
}
func (m *MockNetlinkOps) RouteList(link netlink.Link, family int) ([]netlink.Route, error) {
	if m.RouteListFunc != nil {
		return m.RouteListFunc(link, family)
	}
	return []netlink.Route{}, nil
}
func (m *MockNetlinkOps) LinkByIndex(index int) (netlink.Link, error) {
	if m.LinkByIndexFunc != nil {
		return m.LinkByIndexFunc(index)
	}
	return &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: "enp9s0", Index: index}}, nil
}

type MockFileOps struct {
	WriteFileFunc func(filename string, data []byte, perm os.FileMode) error
	StatFunc      func(name string) (os.FileInfo, error)
	WrittenFiles  map[string]string
}

func (m *MockFileOps) WriteFile(filename string, data []byte, perm os.FileMode) error {
	if m.WrittenFiles == nil {
		m.WrittenFiles = make(map[string]string)
	}
	m.WrittenFiles[filename] = string(data)
	if m.WriteFileFunc != nil {
		return m.WriteFileFunc(filename, data, perm)
	}
	return nil
}
func (m *MockFileOps) Stat(name string) (os.FileInfo, error) {
	if m.StatFunc != nil {
		return m.StatFunc(name)
	}
	// Default: everything exists
	return nil, nil
}

// -- Tests --

func TestInit_AutoDetect(t *testing.T) {
	// Setup Mock
	mockNL := &MockNetlinkOps{
		RouteListFunc: func(link netlink.Link, family int) ([]netlink.Route, error) {
			return []netlink.Route{
				{Dst: nil, LinkIndex: 10}, // Default route
			}, nil
		},
		LinkByIndexFunc: func(index int) (netlink.Link, error) {
			if index == 10 {
				return &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: "wlan0", Index: 10}}, nil
			}
			return nil, fmt.Errorf("not found")
		},
	}
	nlOps = mockNL // Inject Mock

	err := Init()
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	if currentConfig.Interface != "wlan0" {
		t.Errorf("Expected interface wlan0, got %s", currentConfig.Interface)
	}
}

func TestApplyNetworkProfile_Choke(t *testing.T) {
	// Setup
	currentConfig.Interface = "enp9s0"
	var addedQdisc netlink.Qdisc
	mockNL := &MockNetlinkOps{
		QdiscAddFunc: func(q netlink.Qdisc) error {
			addedQdisc = q
			return nil
		},
	}
	nlOps = mockNL

	err := ApplyNetworkProfile(ProfileChoke)
	if err != nil {
		t.Fatalf("ApplyNetworkProfile failed: %v", err)
	}

	if addedQdisc == nil {
		t.Fatal("No qdisc added")
	}

	tbf, ok := addedQdisc.(*netlink.Tbf)
	if !ok {
		t.Fatalf("Expected Tbf qdisc, got %T", addedQdisc)
	}

	// 1Mbps = 125,000 bytes/sec
	if tbf.Rate != 125000 {
		t.Errorf("Expected Rate 125000, got %d", tbf.Rate)
	}
}

func TestSetCPULimit_Calculation(t *testing.T) {
	// Setup
	mockFS := &MockFileOps{}
	fsOps = mockFS

	// Test 15%
	err := SetCPULimit(15)
	if err != nil {
		t.Fatalf("SetCPULimit failed: %v", err)
	}

	expectedPath := "/sys/fs/cgroup/cpu.max"
	content, ok := mockFS.WrittenFiles[expectedPath]
	if !ok {
		t.Fatalf("File %s not written", expectedPath)
	}

	// 15% of 100000 = 15000
	expectedValue := "15000 100000"
	if strings.TrimSpace(content) != expectedValue {
		t.Errorf("Expected content '%s', got '%s'", expectedValue, strings.TrimSpace(content))
	}

	// Test 100% (max)
	err = SetCPULimit(100)
	if err != nil {
		t.Fatalf("SetCPULimit 100 failed: %v", err)
	}
	content = mockFS.WrittenFiles[expectedPath]
	expectedValueMax := "max 100000"
	if strings.TrimSpace(content) != expectedValueMax {
		t.Errorf("Expected content '%s', got '%s'", expectedValueMax, strings.TrimSpace(content))
	}
}
