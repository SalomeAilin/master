package wiredguard

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func testStore(t *testing.T) Store {
	t.Helper()
	path := t.TempDir()
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	return Store{Path: path, Owner: uint32(os.Geteuid())}
}

func TestStatePersistenceRejectsSymlinksHardlinksAndChangedIdentity(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "world-readable", "invalid-identity", "unknown-field"} {
		t.Run(kind, func(t *testing.T) {
			s := testStore(t)
			path := filepath.Join(s.Path, "session.json")
			state := activeState()
			data, _ := json.Marshal(state)
			switch kind {
			case "symlink":
				target := filepath.Join(t.TempDir(), "user-file")
				os.WriteFile(target, data, 0600)
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				target := filepath.Join(s.Path, "original")
				os.WriteFile(target, data, 0600)
				if err := os.Link(target, path); err != nil {
					t.Fatal(err)
				}
			case "world-readable":
				os.WriteFile(path, data, 0644)
			case "invalid-identity":
				state.App.GID = 20
				data, _ = json.Marshal(state)
				os.WriteFile(path, data, 0600)
			case "unknown-field":
				os.WriteFile(path, append(data[:len(data)-1], []byte(",\"unexpected\":true}")...), 0600)
			}
			if _, err := s.Read(); err == nil {
				t.Fatal("unsafe state accepted")
			}
			if err := s.Save(activeState()); err == nil && kind != "invalid-identity" && kind != "unknown-field" {
				t.Fatal("unsafe state overwritten")
			}
		})
	}
}

func TestStateWriteAndReadPreserveReleasePhase(t *testing.T) {
	s := testStore(t)
	state := activeState()
	state.Phase = "cleared"
	if err := s.Save(state); err != nil {
		t.Fatal(err)
	}
	got, err := s.Read()
	if err != nil {
		t.Fatal(err)
	}
	if got.Phase != "cleared" || got.Token != state.Token || !SameProcess(*got.App, *state.App) {
		t.Fatal(got)
	}
	if err = s.Remove(); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Read(); !os.IsNotExist(err) {
		t.Fatal(err)
	}
}
