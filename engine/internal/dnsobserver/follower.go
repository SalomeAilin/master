package dnsobserver

import (
	"bufio"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"strings"
	"syscall"
	"time"
)

const (
	MaxQueryLogBytes = 64 << 20
	maxPartialLine   = 64 << 10
)

// Follower tails dnsmasq's query log from its end, reopening it after rotation
// or truncation, and compacts it once it has been read past MaxBytes. The
// suffix list is reloaded whenever the dnsmasq configuration changes.
type Follower struct {
	LogPath, ConfigPath string
	MaxBytes            int64
	Correlator          *Correlator
	Log                 *Logger
	Sleep               func(time.Duration)

	configTime time.Time
	file       *os.File
	reader     *bufio.Reader
	inode      uint64
	position   int64
	partial    []byte
}

// Run returns only on context cancellation or when the configuration cannot
// be read at startup; later errors are logged and retried.
func (f *Follower) Run(ctx context.Context) error {
	suffixes, err := LoadSuffixes(f.ConfigPath)
	if err != nil {
		return err
	}
	info, err := os.Stat(f.ConfigPath)
	if err != nil {
		return err
	}
	f.Correlator.Suffixes, f.configTime = suffixes, info.ModTime()
	f.Log.Info("started suffixes=%d", len(suffixes))
	defer f.closeLog()
	for ctx.Err() == nil {
		wait, err := f.Step()
		switch {
		case errors.Is(err, fs.ErrNotExist):
			wait = 200 * time.Millisecond
		case err != nil:
			f.Log.Error("observer error=%v", err)
			wait = 200 * time.Millisecond
		}
		if wait > 0 {
			f.Sleep(wait)
		}
	}
	return nil
}

// Step processes at most one complete line and returns how long to wait.
func (f *Follower) Step() (time.Duration, error) {
	info, err := os.Stat(f.ConfigPath)
	if err != nil {
		return 0, err
	}
	if !info.ModTime().Equal(f.configTime) {
		suffixes, err := LoadSuffixes(f.ConfigPath)
		if err != nil {
			return 0, err
		}
		f.Correlator.Suffixes, f.configTime = suffixes, info.ModTime()
		f.Correlator.Clear()
		f.Log.Info("reloaded suffixes=%d", len(suffixes))
	}
	var status syscall.Stat_t
	if err := syscall.Stat(f.LogPath, &status); err != nil {
		return 0, err
	}
	if f.file == nil || f.inode != status.Ino || status.Size < f.position {
		f.Correlator.Clear()
		if err := f.openAtEnd(); err != nil {
			return 0, err
		}
	}
	chunk, err := f.reader.ReadString('\n')
	f.position += int64(len(chunk))
	if err != nil && err != io.EOF {
		f.closeLog()
		return 0, err
	}
	if strings.HasSuffix(chunk, "\n") {
		line := string(f.partial) + chunk
		f.partial = nil
		f.Correlator.ProcessLine(line)
		return 0, nil
	}
	if f.partial = append(f.partial, chunk...); len(f.partial) > maxPartialLine {
		f.partial = nil // never let an unterminated writer grow memory
	}
	if chunk == "" && f.position >= f.MaxBytes {
		f.closeLog()
		if err := os.Truncate(f.LogPath, 0); err != nil {
			return 0, err
		}
		f.Log.Info("query log compacted limit_bytes=%d", f.MaxBytes)
		return 0, nil
	}
	return 50 * time.Millisecond, nil
}

func (f *Follower) openAtEnd() error {
	f.closeLog()
	file, err := os.Open(f.LogPath)
	if err != nil {
		return err
	}
	var status syscall.Stat_t
	if err := syscall.Fstat(int(file.Fd()), &status); err != nil {
		file.Close()
		return err
	}
	position, err := file.Seek(0, io.SeekEnd)
	if err != nil {
		file.Close()
		return err
	}
	f.file, f.reader, f.inode, f.position = file, bufio.NewReader(file), status.Ino, position
	return nil
}

func (f *Follower) closeLog() {
	if f.file != nil {
		f.file.Close()
	}
	f.file, f.reader, f.inode, f.position, f.partial = nil, nil, 0, 0, nil
}
