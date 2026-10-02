package dnsobserver

import (
	"fmt"
	"os"
	"sync"
	"syscall"
	"time"
)

// Logger appends "date time,millis LEVEL message" lines. Like Python's
// WatchedFileHandler, it reopens its path before a write when the file was
// rotated or removed, so newsyslog archives are never written to.
type Logger struct {
	path     string
	now      func() time.Time
	mu       sync.Mutex
	file     *os.File
	dev, ino uint64
}

func NewLogger(path string) *Logger { return &Logger{path: path, now: time.Now} }

func (l *Logger) Info(format string, args ...any)  { l.write("INFO", format, args...) }
func (l *Logger) Error(format string, args ...any) { l.write("ERROR", format, args...) }

func (l *Logger) write(level, format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.reopenIfNeeded()
	t := l.now()
	line := fmt.Sprintf("%s,%03d %s %s\n", t.Format("2006-01-02 15:04:05"), t.Nanosecond()/int(time.Millisecond), level, fmt.Sprintf(format, args...))
	if l.file == nil {
		fmt.Fprint(os.Stderr, line)
		return
	}
	if _, err := l.file.WriteString(line); err != nil {
		fmt.Fprint(os.Stderr, line)
	}
}

func (l *Logger) reopenIfNeeded() {
	var status syscall.Stat_t
	if l.file != nil && syscall.Stat(l.path, &status) == nil && uint64(status.Dev) == l.dev && status.Ino == l.ino {
		return
	}
	if l.file != nil {
		l.file.Close()
		l.file = nil
	}
	file, err := os.OpenFile(l.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
	if err != nil {
		return
	}
	if err := syscall.Fstat(int(file.Fd()), &status); err != nil {
		file.Close()
		return
	}
	l.file, l.dev, l.ino = file, uint64(status.Dev), status.Ino
}

// Close releases the open log file.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	err := l.file.Close()
	l.file = nil
	return err
}
