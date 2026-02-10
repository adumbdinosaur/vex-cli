package penance

import (
	"os"
	"testing"
)

type MockFileSystem struct {
	ReadFileFunc  func(name string) ([]byte, error)
	WriteFileFunc func(name string, data []byte, perm os.FileMode) error
}

func (m *MockFileSystem) ReadFile(name string) ([]byte, error) {
	if m.ReadFileFunc != nil {
		return m.ReadFileFunc(name)
	}
	return nil, os.ErrNotExist
}
func (m *MockFileSystem) WriteFile(name string, data []byte, perm os.FileMode) error {
	if m.WriteFileFunc != nil {
		return m.WriteFileFunc(name, data, perm)
	}
	return nil
}

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
			if name == ManifestFile {
				return []byte(jsonContent), nil
			}
			return nil, os.ErrNotExist
		},
	}
	fsOps = mockFS

	m, err := LoadManifest(ManifestFile)
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

func TestMarkInProgress(t *testing.T) {
	// Set up a mock filesystem that returns a "pending" compliance status
	statusJSON := `{"failure_score":0,"active_task":"TEST-TASK","task_status":"pending","locked":true}`
	var savedData []byte

	mockFS := &MockFileSystem{
		ReadFileFunc: func(name string) ([]byte, error) {
			if savedData != nil {
				return savedData, nil
			}
			return []byte(statusJSON), nil
		},
	}
	mockFS.WriteFileFunc = func(name string, data []byte, perm os.FileMode) error {
		savedData = data
		return nil
	}
	fsOps = mockFS

	// First call should transition from "pending" to "in_progress"
	if err := MarkInProgress(); err != nil {
		t.Fatalf("MarkInProgress failed: %v", err)
	}

	cs, err := LoadComplianceStatus()
	if err != nil {
		t.Fatalf("LoadComplianceStatus failed: %v", err)
	}
	if cs.TaskStatus != "in_progress" {
		t.Errorf("Expected task_status 'in_progress', got '%s'", cs.TaskStatus)
	}

	// Second call should be a no-op (already in_progress)
	if err := MarkInProgress(); err != nil {
		t.Fatalf("MarkInProgress (second call) failed: %v", err)
	}
	cs, err = LoadComplianceStatus()
	if err != nil {
		t.Fatalf("LoadComplianceStatus failed: %v", err)
	}
	if cs.TaskStatus != "in_progress" {
		t.Errorf("Expected task_status to remain 'in_progress', got '%s'", cs.TaskStatus)
	}
}

func TestTaskLifecycle_PendingToInProgressToCompleted(t *testing.T) {
	statusJSON := `{"failure_score":0,"active_task":"LINES-TASK","task_status":"pending","locked":true,"total_completed":0}`
	var savedData []byte

	mockFS := &MockFileSystem{
		ReadFileFunc: func(name string) ([]byte, error) {
			if savedData != nil {
				return savedData, nil
			}
			return []byte(statusJSON), nil
		},
	}
	mockFS.WriteFileFunc = func(name string, data []byte, perm os.FileMode) error {
		savedData = data
		return nil
	}
	fsOps = mockFS

	// 1. Start as pending
	cs, err := LoadComplianceStatus()
	if err != nil {
		t.Fatalf("LoadComplianceStatus failed: %v", err)
	}
	if cs.TaskStatus != "pending" {
		t.Fatalf("Expected initial task_status 'pending', got '%s'", cs.TaskStatus)
	}

	// 2. First line accepted → transitions to in_progress
	if err := MarkInProgress(); err != nil {
		t.Fatalf("MarkInProgress failed: %v", err)
	}
	cs, err = LoadComplianceStatus()
	if err != nil {
		t.Fatalf("LoadComplianceStatus failed: %v", err)
	}
	if cs.TaskStatus != "in_progress" {
		t.Errorf("Expected task_status 'in_progress', got '%s'", cs.TaskStatus)
	}
	if !cs.Locked {
		t.Error("Expected system to remain locked during in_progress")
	}

	// 3. Task completed → transitions to completed, unlocked
	if err := RecordCompletion(); err != nil {
		t.Fatalf("RecordCompletion failed: %v", err)
	}
	cs, err = LoadComplianceStatus()
	if err != nil {
		t.Fatalf("LoadComplianceStatus failed: %v", err)
	}
	if cs.TaskStatus != "completed" {
		t.Errorf("Expected task_status 'completed', got '%s'", cs.TaskStatus)
	}
	if cs.Locked {
		t.Error("Expected system to be unlocked after completion")
	}
	if cs.TotalCompleted != 1 {
		t.Errorf("Expected total_completed 1, got %d", cs.TotalCompleted)
	}
}
