package penance

import (
	"os"
	"testing"
)

type MockFileSystem struct {
	ReadFileFunc func(name string) ([]byte, error)
}

func (m *MockFileSystem) ReadFile(name string) ([]byte, error) {
	if m.ReadFileFunc != nil {
		return m.ReadFileFunc(name)
	}
	return nil, os.ErrNotExist
}
func (m *MockFileSystem) WriteFile(name string, data []byte, perm os.FileMode) error { return nil }

func TestLoadManifest(t *testing.T) {
	jsonContent := `{
"manifest_version": "1.06-V",
"active_penance": {
"task_id": "TEST-TASK",
"type": "technical_summary",
"constraints": { "allow_backspace": false }
}
}`

	mockFS := &MockFileSystem{
		ReadFileFunc: func(name string) ([]byte, error) {
			if name == "penance-manifest.json" {
				return []byte(jsonContent), nil
			}
			return nil, os.ErrNotExist
		},
	}
	fsOps = mockFS

	m, err := LoadManifest("penance-manifest.json")
	if err != nil {
		t.Fatalf("LoadManifest failed: %v", err)
	}

	if m.Version != "1.06-V" {
		t.Errorf("Expected version 1.06-V, got %s", m.Version)
	}
	if m.Active.TaskID != "TEST-TASK" {
		t.Errorf("Expected task ID TEST-TASK, got %s", m.Active.TaskID)
	}
	if m.Active.Constraints.AllowBackspace != false {
		t.Error("Expected allow_backspace to be false")
	}
}
