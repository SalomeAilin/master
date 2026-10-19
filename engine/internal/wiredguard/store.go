package wiredguard

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

type Store struct {
	Path  string
	Owner uint32
}

const stateSizeLimit = 1 << 20

func (s Store) directory(create bool) error {
	if create {
		if err := os.Mkdir(s.Path, 0700); err != nil && !os.IsExist(err) {
			return err
		}
	}
	info, err := os.Lstat(s.Path)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode().Perm() != 0700 || st.Uid != s.Owner {
		return errors.New("unsafe wired state directory")
	}
	return nil
}

func (s Store) open(name string) (*os.File, error) {
	if err := s.directory(false); err != nil {
		return nil, err
	}
	fd, err := syscall.Open(filepath.Join(s.Path, name), syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	st := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || st.Uid != s.Owner || st.Nlink != 1 || info.Size() > stateSizeLimit {
		f.Close()
		return nil, errors.New("unsafe wired state file")
	}
	return f, nil
}

func (s Store) Read() (State, error) {
	var state State
	f, err := s.open("session.json")
	if err != nil {
		return state, err
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, stateSizeLimit+1))
	d.DisallowUnknownFields()
	if err = d.Decode(&state); err != nil {
		return state, err
	}
	if err = d.Decode(new(any)); err != io.EOF {
		return state, errors.New("trailing wired state data")
	}
	return state, state.Validate()
}

func (s Store) Save(state State) error {
	if err := state.Validate(); err != nil {
		return err
	}
	if err := s.directory(false); err != nil {
		return err
	}
	if f, err := s.open("session.json"); err == nil {
		f.Close()
	} else if !os.IsNotExist(err) {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	if len(data)+1 > stateSizeLimit {
		return errors.New("wired state exceeds size limit")
	}
	f, err := os.CreateTemp(s.Path, ".session-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(append(data, '\n'))
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(f.Name(), filepath.Join(s.Path, "session.json"))
	}
	if err == nil {
		dir, e := os.Open(s.Path)
		if e != nil {
			return e
		}
		defer dir.Close()
		err = dir.Sync()
	}
	return err
}

func (s Store) Remove() error {
	f, err := s.open("session.json")
	if err != nil {
		return err
	}
	f.Close()
	return os.Remove(filepath.Join(s.Path, "session.json"))
}

func (s Store) Lock() (func(), error) {
	if err := s.directory(true); err != nil {
		return nil, err
	}
	fd, err := syscall.Open(filepath.Join(s.Path, "lock"), syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "wired session lock")
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	st := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || st.Uid != s.Owner || st.Nlink != 1 {
		f.Close()
		return nil, errors.New("unsafe wired session lock")
	}
	lock := syscall.Flock_t{Type: syscall.F_WRLCK, Whence: 0}
	if err = syscall.FcntlFlock(uintptr(fd), syscall.F_SETLK, &lock); err != nil {
		f.Close()
		return nil, err
	}
	return func() { f.Close() }, nil
}
