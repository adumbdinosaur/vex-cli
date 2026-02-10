package surveillance

import (
	"fmt"
	"io"
	"testing"
	"time"

	evdev "github.com/holoplot/go-evdev"
)

// -- Mocks --

type MockInputDevice struct {
	NameVal     string
	FnVal       string
	CapsVal     map[evdev.EvType][]evdev.EvCode
	ReadOneFunc func() (*evdev.InputEvent, error)
	CloseFunc   func() error
}

func (m *MockInputDevice) Name() string { return m.NameVal }
func (m *MockInputDevice) Fn() string   { return m.FnVal }
func (m *MockInputDevice) Capabilities() map[evdev.EvType][]evdev.EvCode {
	return m.CapsVal
}
func (m *MockInputDevice) ReadOne() (*evdev.InputEvent, error) {
	if m.ReadOneFunc != nil {
		return m.ReadOneFunc()
	}
	// Blocks forever by default to simulate idle device
	select {}
}
func (m *MockInputDevice) Close() error {
	if m.CloseFunc != nil {
		return m.CloseFunc()
	}
	return nil
}

type MockEvdevOps struct {
	ListFunc func() ([]InputDevice, error)
	OpenFunc func(path string) (InputDevice, error)
}

func (m *MockEvdevOps) ListInputDevices() ([]InputDevice, error) {
	if m.ListFunc != nil {
		return m.ListFunc()
	}
	return nil, nil
}
func (m *MockEvdevOps) Open(path string) (InputDevice, error) {
	if m.OpenFunc != nil {
		return m.OpenFunc(path)
	}
	return nil, fmt.Errorf("mock open failed")
}

// -- Tests --

func TestDetectKeyboard(t *testing.T) {
	// Case 1: Name match
	dev1 := &MockInputDevice{NameVal: "USB Keyboard"}
	if !isKeyboard(dev1) {
		t.Error("Expected to detect 'USB Keyboard' as keyboard")
	}

	// Case 2: Capabilities match (Has KEY_A)
	keyACode := evdev.EvCode(evdev.KEY_A)
	caps := map[evdev.EvType][]evdev.EvCode{
		evdev.EV_KEY: {keyACode},
	}
	dev2 := &MockInputDevice{NameVal: "Unknown Device", CapsVal: caps}
	if !isKeyboard(dev2) {
		t.Error("Expected to detect device with KEY_A as keyboard")
	}

	// Case 3: Not a keyboard
	dev3 := &MockInputDevice{NameVal: "USB Mouse"}
	if isKeyboard(dev3) {
		t.Error("Did not expect to detect 'USB Mouse' as keyboard")
	}
}

func TestKeystrokeProcess(t *testing.T) {
	// Reset metrics
	GlobalMetrics.Keystrokes = 0
	GlobalMetrics.LinesCompleted = 0

	// Create a channel to feed events
	eventChan := make(chan *evdev.InputEvent, 10)

	// Setup Mock Device
	mockDev := &MockInputDevice{
		NameVal: "Test Keyboard",
		FnVal:   "/dev/input/eventTest",
		ReadOneFunc: func() (*evdev.InputEvent, error) {
			ev, ok := <-eventChan
			if !ok {
				return nil, io.EOF
			}
			return ev, nil
		},
	}

	// Setup Mock Ops
	evOps = &MockEvdevOps{
		OpenFunc: func(path string) (InputDevice, error) {
			return mockDev, nil
		},
	}

	// Manually attach (bypassing Init list logic to just test the listener w/ Open)
	err := listenToDevice("/dev/input/eventTest")
	if err != nil {
		t.Fatalf("listenToDevice failed: %v", err)
	}

	// Send Keystroke (Key A press)
	eventChan <- &evdev.InputEvent{Type: evdev.EV_KEY, Code: evdev.KEY_A, Value: 1}

	// Send Enter Press
	eventChan <- &evdev.InputEvent{Type: evdev.EV_KEY, Code: evdev.KEY_ENTER, Value: 1}

	// Send Key Release (Should be ignored)
	eventChan <- &evdev.InputEvent{Type: evdev.EV_KEY, Code: evdev.KEY_A, Value: 0}

	// Wait briefly for goroutine
	time.Sleep(50 * time.Millisecond)
	close(eventChan) // Stop listener

	// Check Metrics
	GlobalMetrics.mu.Lock()
	defer GlobalMetrics.mu.Unlock()

	if GlobalMetrics.Keystrokes != 2 {
		t.Errorf("Expected 2 keystrokes, got %d", GlobalMetrics.Keystrokes)
	}
	if GlobalMetrics.LinesCompleted != 1 {
		t.Errorf("Expected 1 line completed, got %d", GlobalMetrics.LinesCompleted)
	}
}
