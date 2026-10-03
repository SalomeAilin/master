package deploy

import (
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// User-owned ancestor directories can change during an administrator install.
// Keep these two migration targets inside an open home root, including rollback.
type ownedUserFiles struct {
	root  *os.Root
	paths map[string]string
	uid   uint32
}

func openUserFiles(home string, uid uint32, paths ...string) (*ownedUserFiles, error) {
	root, err := os.OpenRoot(home)
	if err != nil {
		return nil, err
	}
	info, err := root.Stat(".")
	if err != nil || info.Sys().(*syscall.Stat_t).Uid != uid {
		root.Close()
		return nil, errors.New("unexpected status home owner")
	}
	u := &ownedUserFiles{root: root, uid: uid, paths: map[string]string{}}
	for _, path := range paths {
		rel, err := filepath.Rel(home, path)
		if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, "../") || filepath.IsAbs(rel) {
			root.Close()
			return nil, errors.New("user migration path escapes home")
		}
		u.paths[path] = rel
	}
	return u, nil
}

func (u *ownedUserFiles) has(path string) bool { _, ok := u.paths[path]; return ok }

func (u *ownedUserFiles) open(path string) (*os.File, os.FileInfo, error) {
	rel, ok := u.paths[path]
	if !ok {
		return nil, nil, errors.New("unknown user target")
	}
	info, err := u.root.Lstat(rel)
	if err != nil {
		return nil, nil, err
	}
	stat := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || stat.Uid != u.uid || stat.Nlink != 1 || info.Size() > 64<<20 {
		return nil, nil, errors.New("unsafe user migration file")
	}
	f, err := u.root.Open(rel)
	if err != nil {
		return nil, nil, err
	}
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		f.Close()
		return nil, nil, errors.New("user file changed while opening")
	}
	return f, info, nil
}

func (u *ownedUserFiles) snapshot(backup string, index int, path string) (Record, error) {
	r := Record{Target: path, Copy: strconv.Itoa(index)}
	f, info, err := u.open(path)
	if os.IsNotExist(err) {
		return r, nil
	}
	if err != nil {
		return r, err
	}
	defer f.Close()
	to, err := os.OpenFile(filepath.Join(backup, r.Copy), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return r, err
	}
	count, err := io.Copy(to, io.LimitReader(f, (64<<20)+1))
	if err == nil && count > 64<<20 {
		err = errors.New("user snapshot grew beyond limit")
	}
	if closeErr := to.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return r, err
	}
	stat := info.Sys().(*syscall.Stat_t)
	r.Present, r.Mode, r.UID, r.GID = true, uint32(stat.Mode&0o7777), stat.Uid, stat.Gid
	return r, nil
}

func (u *ownedUserFiles) remove(path string) error {
	rel, ok := u.paths[path]
	if !ok {
		return errors.New("unknown user target")
	}
	return u.root.Remove(rel)
}

func (u *ownedUserFiles) digest(path string) (string, error) {
	f, _, err := u.open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	digest, _, err := hashFile(f)
	return digest, err
}

func (u *ownedUserFiles) restore(backup string, r Record) error {
	if !u.has(r.Target) {
		return errors.New("unknown user restore target")
	}
	if !r.Present {
		err := u.remove(r.Target)
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if r.UID != u.uid {
		return errors.New("user snapshot identity mismatch")
	}
	rel := u.paths[r.Target]
	parent, err := u.root.OpenRoot(filepath.Dir(rel))
	if err != nil {
		return err
	}
	defer parent.Close()
	name := ".network-restore-" + rand.Text()
	file, err := parent.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer parent.Remove(name)
	input, err := os.Open(filepath.Join(backup, r.Copy))
	if err == nil {
		_, err = io.Copy(file, input)
		input.Close()
	}
	if err == nil {
		err = file.Chmod(unixMode(r.Mode))
	}
	if err == nil {
		err = file.Chown(int(r.UID), int(r.GID))
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return parent.Rename(name, filepath.Base(rel))
}
