package sandbox

import (
	"os"
	"path/filepath"
	"testing"
)

func setupTestDirs(t *testing.T) (reportsDir, workDir string) {
	t.Helper()
	base := t.TempDir()
	reportsDir = filepath.Join(base, "reports")
	workDir = filepath.Join(base, "workspace")
	os.MkdirAll(reportsDir, 0o755)
	os.MkdirAll(workDir, 0o755)
	os.WriteFile(filepath.Join(reportsDir, "q1.csv"), []byte("data"), 0o644)
	os.WriteFile(filepath.Join(workDir, "scratch.txt"), []byte("temp"), 0o644)
	os.WriteFile(filepath.Join(workDir, ".env"), []byte("SECRET=x"), 0o644)
	return reportsDir, workDir
}

func TestSandbox_New_CreatesWorkspace(t *testing.T) {
	reportsDir, workDir := setupTestDirs(t)
	sb, err := New(Config{
		Enabled: true,
		Mounts: []Mount{
			{Source: reportsDir, Target: "reports", Mode: ModeReadOnly},
			{Source: workDir, Target: "workspace", Mode: ModeReadWrite},
		},
	}, "test-run")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer sb.Cleanup()

	if sb.Root() == "" {
		t.Error("sandbox root is empty")
	}

	link, err := os.Readlink(filepath.Join(sb.Root(), "reports"))
	if err != nil {
		t.Fatalf("readlink reports: %v", err)
	}
	resolvedReports, _ := filepath.EvalSymlinks(reportsDir)
	if link != resolvedReports {
		t.Errorf("reports symlink: %q, want %q", link, resolvedReports)
	}
}

func TestSandbox_ReadOnly_AllowsRead(t *testing.T) {
	reportsDir, _ := setupTestDirs(t)
	sb, _ := New(Config{
		Enabled: true,
		Mounts: []Mount{
			{Source: reportsDir, Target: "reports", Mode: ModeReadOnly},
		},
	}, "test-run")
	defer sb.Cleanup()

	if err := sb.ValidatePath("read", filepath.Join(reportsDir, "q1.csv")); err != nil {
		t.Errorf("read should be allowed: %v", err)
	}
}

func TestSandbox_ReadOnly_DeniesWrite(t *testing.T) {
	reportsDir, _ := setupTestDirs(t)
	sb, _ := New(Config{
		Enabled: true,
		Mounts: []Mount{
			{Source: reportsDir, Target: "reports", Mode: ModeReadOnly},
		},
	}, "test-run")
	defer sb.Cleanup()

	if err := sb.ValidatePath("write", filepath.Join(reportsDir, "q1.csv")); err == nil {
		t.Error("write to read-only mount should be denied")
	}
}

func TestSandbox_ReadOnly_DeniesDelete(t *testing.T) {
	reportsDir, _ := setupTestDirs(t)
	sb, _ := New(Config{
		Enabled: true,
		Mounts: []Mount{
			{Source: reportsDir, Target: "reports", Mode: ModeReadOnly},
		},
	}, "test-run")
	defer sb.Cleanup()

	if err := sb.ValidatePath("delete", filepath.Join(reportsDir, "q1.csv")); err == nil {
		t.Error("delete on read-only mount should be denied")
	}
}

func TestSandbox_ReadWrite_AllowsWrite(t *testing.T) {
	_, workDir := setupTestDirs(t)
	sb, _ := New(Config{
		Enabled: true,
		Mounts: []Mount{
			{Source: workDir, Target: "workspace", Mode: ModeReadWrite},
		},
	}, "test-run")
	defer sb.Cleanup()

	if err := sb.ValidatePath("write", filepath.Join(workDir, "new-file.txt")); err != nil {
		t.Errorf("write to rw mount should be allowed: %v", err)
	}
}

func TestSandbox_OutsideMounts_Denied(t *testing.T) {
	reportsDir, _ := setupTestDirs(t)
	sb, _ := New(Config{
		Enabled: true,
		Mounts: []Mount{
			{Source: reportsDir, Target: "reports", Mode: ModeReadOnly},
		},
	}, "test-run")
	defer sb.Cleanup()

	if err := sb.ValidatePath("read", "/etc/passwd"); err == nil {
		t.Error("reading outside mounts should be denied")
	}
}

func TestSandbox_DenyPatterns_BlocksDotEnv(t *testing.T) {
	_, workDir := setupTestDirs(t)
	sb, _ := New(Config{
		Enabled: true,
		Mounts: []Mount{
			{Source: workDir, Target: "workspace", Mode: ModeReadWrite},
		},
		DenyPatterns: []string{"**/.env", "**/credentials*", "**/*.key", "**/*.pem"},
	}, "test-run")
	defer sb.Cleanup()

	if err := sb.ValidatePath("read", filepath.Join(workDir, ".env")); err == nil {
		t.Error("reading .env should be denied by deny pattern")
	}

	if err := sb.ValidatePath("read", filepath.Join(workDir, "scratch.txt")); err != nil {
		t.Errorf("reading scratch.txt should be allowed: %v", err)
	}
}

func TestSandbox_DenyPatterns_BlocksKeyFiles(t *testing.T) {
	_, workDir := setupTestDirs(t)
	os.WriteFile(filepath.Join(workDir, "server.key"), []byte("privkey"), 0o600)

	sb, _ := New(Config{
		Enabled: true,
		Mounts: []Mount{
			{Source: workDir, Target: "workspace", Mode: ModeReadWrite},
		},
		DenyPatterns: []string{"**/*.key", "**/*.pem"},
	}, "test-run")
	defer sb.Cleanup()

	if err := sb.ValidatePath("read", filepath.Join(workDir, "server.key")); err == nil {
		t.Error("reading .key file should be denied")
	}
}

func TestSandbox_NonExistentSource_Error(t *testing.T) {
	_, err := New(Config{
		Enabled: true,
		Mounts: []Mount{
			{Source: "/nonexistent/path/xyz", Target: "data", Mode: ModeReadOnly},
		},
	}, "test-run")
	if err == nil {
		t.Error("expected error for nonexistent source path")
	}
}

func TestSandbox_Cleanup_RemovesWorkspace(t *testing.T) {
	reportsDir, _ := setupTestDirs(t)
	sb, _ := New(Config{
		Enabled: true,
		Mounts: []Mount{
			{Source: reportsDir, Target: "reports", Mode: ModeReadOnly},
		},
	}, "test-run")

	root := sb.Root()
	sb.Cleanup()

	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Error("sandbox root should be removed after cleanup")
	}
}

func TestSandbox_MultipleMounts(t *testing.T) {
	reportsDir, workDir := setupTestDirs(t)
	sb, _ := New(Config{
		Enabled: true,
		Mounts: []Mount{
			{Source: reportsDir, Target: "data/reports", Mode: ModeReadOnly},
			{Source: workDir, Target: "data/work", Mode: ModeReadWrite},
		},
	}, "test-run")
	defer sb.Cleanup()

	if err := sb.ValidatePath("read", filepath.Join(reportsDir, "q1.csv")); err != nil {
		t.Errorf("read reports: %v", err)
	}
	if err := sb.ValidatePath("write", filepath.Join(reportsDir, "new.csv")); err == nil {
		t.Error("write to ro reports should be denied")
	}
	if err := sb.ValidatePath("write", filepath.Join(workDir, "output.txt")); err != nil {
		t.Errorf("write to rw work: %v", err)
	}
}
