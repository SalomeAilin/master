package log

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"sync"

	"github.com/sagernet/sing/service/filemanager"
)

// RotatingWriter owns one log and a fixed number of numbered archives.
// It must not share its path with another process or an external rotator.
type RotatingWriter struct {
	access     sync.Mutex
	ctx        context.Context
	path       string
	maxSize    int64
	maxBackups int
	file       *os.File
	size       int64
	closed     bool
}

func NewRotatingWriter(ctx context.Context, path string, maxSize int64, maxBackups int) (*RotatingWriter, error) {
	if path == "" || maxSize < 64 || maxBackups < 0 || maxBackups > 100 {
		return nil, errors.New("invalid log rotation path or limits")
	}
	w := &RotatingWriter{ctx: ctx, path: filemanager.BasePath(ctx, path), maxSize: maxSize, maxBackups: maxBackups}
	if err := w.checkPaths(); err != nil {
		return nil, err
	}
	if err := w.open(); err != nil {
		return nil, err
	}
	if w.size > maxSize {
		if err := w.rotate(); err != nil {
			w.Close()
			return nil, err
		}
	}
	return w, nil
}

func (w *RotatingWriter) archive(index int) string {
	return w.path + "." + strconv.Itoa(index)
}

func (w *RotatingWriter) checkPaths() error {
	for index := 0; index <= w.maxBackups; index++ {
		path := w.path
		if index > 0 {
			path = w.archive(index)
		}
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("log path is not a regular file: %s", path)
		}
	}
	return nil
}

func (w *RotatingWriter) open() error {
	if err := w.checkPaths(); err != nil {
		return err
	}
	file, err := filemanager.OpenFile(w.ctx, w.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err == nil {
		var pathInfo os.FileInfo
		pathInfo, err = os.Lstat(w.path)
		if err == nil && (!pathInfo.Mode().IsRegular() || !os.SameFile(info, pathInfo)) {
			err = errors.New("log path changed while opening")
		}
	}
	if err == nil {
		err = file.Chmod(0o600)
	}
	if err != nil {
		file.Close()
		return err
	}
	w.file, w.size = file, info.Size()
	return nil
}

func (w *RotatingWriter) rotate() error {
	if err := w.checkPaths(); err != nil {
		return err
	}
	if err := w.file.Close(); err != nil {
		w.file = nil
		return err
	}
	w.file = nil
	if w.maxBackups == 0 {
		if err := filemanager.Remove(w.ctx, w.path); err != nil {
			return err
		}
	} else {
		if err := filemanager.Remove(w.ctx, w.archive(w.maxBackups)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		for index := w.maxBackups - 1; index >= 1; index-- {
			if err := filemanager.Rename(w.ctx, w.archive(index), w.archive(index+1)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
		if err := filemanager.Rename(w.ctx, w.path, w.archive(1)); err != nil {
			return err
		}
	}
	return w.open()
}

func (w *RotatingWriter) Write(data []byte) (int, error) {
	w.access.Lock()
	defer w.access.Unlock()
	if w.closed {
		return 0, os.ErrClosed
	}
	if w.file == nil {
		if err := w.open(); err != nil {
			return 0, err
		}
	}
	originalSize := len(data)
	if int64(len(data)) > w.maxSize {
		const marker = "... [log entry truncated]\n"
		bounded := make([]byte, int(w.maxSize))
		copy(bounded, data[:len(bounded)-len(marker)])
		copy(bounded[len(bounded)-len(marker):], marker)
		data = bounded
	}
	if w.size > w.maxSize-int64(len(data)) {
		if err := w.rotate(); err != nil {
			return 0, err
		}
	}
	n, err := w.file.Write(data)
	w.size += int64(n)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err == nil {
		return originalSize, nil
	}
	return n, err
}

func (w *RotatingWriter) Close() error {
	w.access.Lock()
	defer w.access.Unlock()
	w.closed = true
	if w.file == nil {
		return nil
	}
	err := w.file.Close()
	w.file = nil
	return err
}
