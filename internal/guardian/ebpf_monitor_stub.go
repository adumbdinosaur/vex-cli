package guardian

import "errors"

type EBPFMonitor struct {
	enabled bool
}

func NewEBPFMonitor() (*EBPFMonitor, error) {
	return nil, errors.New("eBPF monitor not implemented in this build")
}

func (m *EBPFMonitor) Start() error {
	return errors.New("eBPF monitor not implemented in this build")
}

func (m *EBPFMonitor) Close() error {
	return nil
}

func (m *EBPFMonitor) IsEnabled() bool {
	return false
}

func (m *EBPFMonitor) UpdateForbiddenApps() {
}
