package deploy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUserMigrationCannotEscapeHomeAfterAncestorReplacement(t *testing.T) {
	home, outside, backup := t.TempDir(), t.TempDir(), t.TempDir()
	parent := filepath.Join(home, "agent")
	os.Mkdir(parent, 0o700)
	path := filepath.Join(parent, "task.plist")
	writeTestFile(t, path, "original user task")
	other := filepath.Join(outside, "task.plist")
	writeTestFile(t, other, "unrelated protected file")
	u, err := openUserFiles(home, uint32(os.Geteuid()), path)
	if err != nil {
		t.Fatal(err)
	}
	defer u.root.Close()
	record, err := u.snapshot(backup, 0, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(parent, parent+".moved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, parent); err != nil {
		t.Fatal(err)
	}
	if _, err := u.digest(path); err == nil {
		t.Fatal("digest escaped home")
	}
	if err := u.remove(path); err == nil {
		t.Fatal("removal escaped home")
	}
	if err := u.restore(backup, record); err == nil {
		t.Fatal("rollback escaped home")
	}
	data, _ := os.ReadFile(other)
	if string(data) != "unrelated protected file" {
		t.Fatal("unrelated file changed")
	}
	os.Remove(parent)
	os.Rename(parent+".moved", parent)
	writeTestFile(t, path, "changed")
	if err := u.restore(backup, record); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(path)
	if string(data) != "original user task" {
		t.Fatal("rollback did not restore user data")
	}
}

func TestUserMigrationRejectsLinkedFilesAndUnknownTargets(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "task")
	writeTestFile(t, path, "owned data")
	u, err := openUserFiles(home, uint32(os.Geteuid()), path)
	if err != nil {
		t.Fatal(err)
	}
	defer u.root.Close()
	os.Link(path, filepath.Join(home, "hardlink"))
	if _, _, err := u.open(path); err == nil {
		t.Fatal("hard link accepted")
	}
	if err := u.remove(filepath.Join(home, "unreviewed")); err == nil {
		t.Fatal("unknown target accepted")
	}
}
