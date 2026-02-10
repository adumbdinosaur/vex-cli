package surveillance

import (
	evdev "github.com/holoplot/go-evdev"
)

// InputDevice is an interface wrapper around evdev.InputDevice for testing
type InputDevice interface {
	ReadOne() (*evdev.InputEvent, error)
	Close() error
	Name() string
	Fn() string
	Capabilities() map[evdev.EvType][]evdev.EvCode
}

// RealInputDevice wraps the actual struct
type RealInputDevice struct {
	dev *evdev.InputDevice
}

func (r *RealInputDevice) ReadOne() (*evdev.InputEvent, error) { return r.dev.ReadOne() }
func (r *RealInputDevice) Close() error                        { return r.dev.Close() }
func (r *RealInputDevice) Name() string {
	name, _ := r.dev.Name()
	return name
}
func (r *RealInputDevice) Fn() string { return r.dev.Path() }
func (r *RealInputDevice) Capabilities() map[evdev.EvType][]evdev.EvCode {
	caps := make(map[evdev.EvType][]evdev.EvCode)
	for _, t := range r.dev.CapableTypes() {
		caps[t] = r.dev.CapableEvents(t)
	}
	return caps
}

// EvdevOps interface defines the static functions we use
type EvdevOps interface {
	ListInputDevices() ([]InputDevice, error)
	Open(path string) (InputDevice, error)
}

// RealEvdevOps implementation
type RealEvdevOps struct{}

func (r *RealEvdevOps) ListInputDevices() ([]InputDevice, error) {
	paths, err := evdev.ListDevicePaths()
	if err != nil {
		return nil, err
	}
	var ret []InputDevice
	for _, p := range paths {
		d, err := evdev.Open(p.Path)
		if err != nil {
			continue // Skip unopenable devices
		}
		ret = append(ret, &RealInputDevice{dev: d})
	}
	return ret, nil
}

func (r *RealEvdevOps) Open(path string) (InputDevice, error) {
	dev, err := evdev.Open(path)
	if err != nil {
		return nil, err
	}
	return &RealInputDevice{dev: dev}, nil
}

var evOps EvdevOps = &RealEvdevOps{}
