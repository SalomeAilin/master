package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"
	"time"
)

type privateLog struct {
	mu       sync.Mutex
	path     string
	limit    int64
	archives int
	file     *os.File
	size     int64
}

func openPrivateLog(path string, limit int64, archives int) (*privateLog, error) {
	if limit < 1024 || archives < 0 || archives > 32 {
		return nil, errors.New("invalid log retention")
	}
	l := &privateLog{path: path, limit: limit, archives: archives}
	for i := 0; i <= archives; i++ {
		info, err := os.Lstat(l.name(i))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if err == nil && !info.Mode().IsRegular() {
			return nil, errors.New("log path is not a regular file")
		}
	}
	if err := l.open(); err != nil {
		return nil, err
	}
	if l.size > limit {
		if err := l.rotate(); err != nil {
			l.Close()
			return nil, err
		}
	}
	return l, nil
}

func (l *privateLog) name(index int) string {
	if index == 0 {
		return l.path
	}
	return fmt.Sprintf("%s.%d", l.path, index)
}
func (l *privateLog) open() error {
	fd, err := syscall.Open(l.path, syscall.O_CREAT|syscall.O_WRONLY|syscall.O_APPEND|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), l.path)
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		f.Close()
		return errors.New("unsafe log file")
	}
	if err = f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	l.file = f
	l.size = info.Size()
	return nil
}
func (l *privateLog) rotate() error {
	for i := 0; i <= l.archives; i++ {
		info, err := os.Lstat(l.name(i))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err == nil && !info.Mode().IsRegular() {
			return errors.New("unsafe log archive")
		}
	}
	if l.file != nil {
		if err := l.file.Close(); err != nil {
			return err
		}
		l.file = nil
	}
	if err := os.Remove(l.name(l.archives)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for i := l.archives - 1; i >= 0; i-- {
		if err := os.Rename(l.name(i), l.name(i+1)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return l.open()
}
func (l *privateLog) Write(data []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	original := len(data)
	if l.file == nil {
		return 0, os.ErrClosed
	}
	if int64(len(data)) > l.limit {
		marker := []byte(" [entry truncated]\n")
		data = append(append([]byte{}, data[:int(l.limit)-len(marker)]...), marker...)
	}
	if l.size+int64(len(data)) > l.limit {
		if err := l.rotate(); err != nil {
			return 0, err
		}
	}
	n, err := l.file.Write(data)
	l.size += int64(n)
	if err != nil {
		return n, err
	}
	return original, nil
}
func (l *privateLog) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	err := l.file.Close()
	l.file = nil
	return err
}

type eventLog struct {
	writer io.Writer
	mu     sync.Mutex
}

func (l *eventLog) write(event string, id uint64, fields map[string]any) {
	if fields == nil {
		fields = map[string]any{}
	}
	fields["time"] = time.Now().UTC().Format(time.RFC3339Nano)
	fields["event"] = event
	if id != 0 {
		fields["id"] = id
	}
	data, err := json.Marshal(fields)
	if err != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, err = l.writer.Write(append(data, '\n')); err != nil {
		fmt.Fprintln(os.Stderr, "engine log write failed:", err)
	}
}
