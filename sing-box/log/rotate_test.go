package log

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestRotatingWriterRetentionAndRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "service.log")
	for batch := 0; batch < 2; batch++ {
		w, err := NewRotatingWriter(context.Background(), path, 64, 3)
		if err != nil {
			t.Fatal(err)
		}
		for index := 0; index < 4; index++ {
			if _, err := w.Write(bytes.Repeat([]byte{byte('a' + batch*4 + index)}, 64)); err != nil {
				t.Fatal(err)
			}
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
	}
	for index, value := range []byte{'h', 'g', 'f', 'e'} {
		name := path
		if index > 0 {
			name += fmt.Sprintf(".%d", index)
		}
		data, err := os.ReadFile(name)
		if err != nil || !bytes.Equal(data, bytes.Repeat([]byte{value}, 64)) {
			t.Fatalf("unexpected retained log %s: %q, %v", name, data, err)
		}
		info, err := os.Stat(name)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("log is not private: %v, %v", info, err)
		}
	}
	if _, err := os.Stat(path + ".4"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unexpected fourth archive", err)
	}
}

func TestRotatingWriterOversizedEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "service.log")
	w, err := NewRotatingWriter(context.Background(), path, 64, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	for index := 0; index < 3; index++ {
		data := bytes.Repeat([]byte("x"), 4096)
		n, err := w.Write(data)
		if n != len(data) || err != nil {
			t.Fatalf("unexpected write: %d, %v", n, err)
		}
		retained, err := os.ReadFile(path)
		if err != nil || len(retained) != 64 || !strings.HasSuffix(string(retained), "[log entry truncated]\n") {
			t.Fatalf("oversized entry escaped cap: %q, %v", retained, err)
		}
	}
	files, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(files) != 1 {
		t.Fatalf("zero-backup mode retained archives: %v, %v", files, err)
	}
}

func TestRotatingWriterConcurrentEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "service.log")
	w, err := NewRotatingWriter(context.Background(), path, 1024, 3)
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		workers.Add(1)
		go func(worker int) {
			defer workers.Done()
			for index := 0; index < 20; index++ {
				if _, err := fmt.Fprintf(w, "worker=%d entry=%02d\n", worker, index); err != nil {
					t.Error(err)
				}
			}
		}(worker)
	}
	workers.Wait()
	w.Close()
	seen := make(map[string]bool)
	files, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		data, err := os.ReadFile(filepath.Join(filepath.Dir(path), file.Name()))
		if err != nil || len(data) > 1024 {
			t.Fatalf("log exceeds cap: %d, %v", len(data), err)
		}
		for _, entry := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
			if seen[entry] || len(entry) != len("worker=0 entry=00") {
				t.Fatalf("interleaved or duplicate entry: %q", entry)
			}
			seen[entry] = true
		}
	}
	if len(seen) != 160 {
		t.Fatalf("entries lost: %d", len(seen))
	}
}

func TestRotatingWriterRefusesUnsafePathAndRotation(t *testing.T) {
	directory := t.TempDir()
	path, target := filepath.Join(directory, "service.log"), filepath.Join(directory, "unrelated")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRotatingWriter(context.Background(), path, 64, 1); err == nil {
		t.Fatal("accepted symlink")
	}
	os.Remove(path)
	w, err := NewRotatingWriter(context.Background(), path, 64, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	w.Write(bytes.Repeat([]byte("a"), 64))
	os.Symlink(target, path+".1")
	if _, err := w.Write([]byte("next")); err == nil {
		t.Fatal("accepted unsafe archive")
	}
	data, _ := os.ReadFile(path)
	if len(data) != 64 {
		t.Fatal("failed rotation grew active log")
	}
	data, _ = os.ReadFile(target)
	if string(data) != "keep" {
		t.Fatal("unrelated file modified")
	}
	os.Remove(path + ".1")
	if _, err := w.Write([]byte("next")); err != nil {
		t.Fatal("could not recover from rotation error", err)
	}
}

func TestRotatingWriterExistingOversizeAndClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "service.log")
	os.WriteFile(path, bytes.Repeat([]byte("old"), 30), 0o600)
	w, err := NewRotatingWriter(context.Background(), path, 64, 1)
	if err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if info.Size() != 0 {
		t.Fatal("oversized active file not rotated at startup")
	}
	old, _ := os.ReadFile(path + ".1")
	if len(old) != 90 {
		t.Fatal("historical log was not preserved")
	}
	w.Close()
	if _, err := w.Write([]byte("after close")); !errors.Is(err, os.ErrClosed) {
		t.Fatal("write after close succeeded", err)
	}
	if err := w.Close(); err != nil {
		t.Fatal("second close failed", err)
	}
	for _, limits := range []struct {
		size    int64
		backups int
	}{{0, 3}, {63, 3}, {64, -1}, {64, 101}} {
		if _, err := NewRotatingWriter(context.Background(), path, limits.size, limits.backups); err == nil {
			t.Fatal("accepted invalid limits", limits)
		}
	}
}
