//go:build darwin && cgo

package wiredguard

/*
#include <libproc.h>
#include <sys/proc_info.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <errno.h>

struct wired_socket { unsigned int uid; unsigned int gid; unsigned long long handle; };

static int wired_sockets(int pid, struct wired_socket *out, int capacity) {
    errno = 0;
    int bytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
    if (bytes < 0 || (bytes == 0 && errno != 0)) return -1;
    if (bytes == 0) return 0;
    if (bytes > 65536 * (int)sizeof(struct proc_fdinfo)) { errno = EOVERFLOW; return -1; }
    int allocated = bytes + 32 * sizeof(struct proc_fdinfo);
    struct proc_fdinfo *fds = malloc(allocated);
    if (!fds) { errno = ENOMEM; return -1; }
    bytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds, allocated);
    if (bytes <= 0 || bytes == allocated) { free(fds); errno = EAGAIN; return -1; }
    int used = 0;
    for (int i = 0; i < bytes / (int)sizeof(struct proc_fdinfo); i++) {
        if (fds[i].proc_fdtype != PROX_FDTYPE_SOCKET) continue;
        struct socket_fdinfo info;
        errno = 0;
        int n = proc_pidfdinfo(pid, fds[i].proc_fd, PROC_PIDFDSOCKETINFO, &info, sizeof(info));
        if (n != sizeof(info)) { if (errno == EBADF || errno == ENOENT) continue; free(fds); return -1; }
        if (info.psi.soi_family != AF_INET && info.psi.soi_family != AF_INET6) continue;
        if (used == capacity) { free(fds); errno = EOVERFLOW; return -1; }
        out[used].uid = info.psi.soi_stat.vst_uid;
        out[used].gid = info.psi.soi_stat.vst_gid;
        out[used].handle = info.psi.soi_so;
        used++;
    }
    free(fds);
    return used;
}
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func nativeSnapshot(ctx context.Context, uid uint32) (Snapshot, error) {
	var result Snapshot
	processes, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return result, err
	}
	if len(processes) > 32768 {
		return result, errors.New("process inventory exceeds limit")
	}
	for _, p := range processes {
		if err = ctx.Err(); err != nil {
			return result, err
		}
		pid := int(p.Proc.P_pid)
		if pid <= 0 || p.Proc.P_stat == 5 {
			continue
		} // zombies have no open descriptors
		if p.Eproc.Ucred.Uid != uid {
			nameBytes := make([]byte, 0, len(p.Proc.P_comm))
			for _, c := range p.Proc.P_comm {
				if c == 0 {
					break
				}
				nameBytes = append(nameBytes, byte(c))
			}
			name := strings.ToLower(string(nameBytes))
			gid := p.Eproc.Ucred.Groups[0]
			if (gid >= 62000 && gid <= 62127) || (p.Eproc.Pcred.P_rgid >= 62000 && p.Eproc.Pcred.P_rgid <= 62127) || (p.Eproc.Pcred.P_svgid >= 62000 && p.Eproc.Pcred.P_svgid <= 62127) || strings.Contains(name, "baidu") || strings.Contains(name, "netdisk") {
				identity, err := nativeIdentity(pid)
				if err != nil {
					if os.IsNotExist(err) {
						continue
					}
					return result, err
				}
				result.Processes = append(result.Processes, identity)
			}
		} else {
			identity, err := nativeIdentity(pid)
			if err != nil {
				if os.IsNotExist(err) {
					continue
				}
				return result, err
			}
			result.Processes = append(result.Processes, identity)
		}
		// A descriptor can be passed to another UID without changing the socket's
		// original credentials. Inspect every process, not just the app account.
		var sockets [4096]C.struct_wired_socket
		count, callErr := C.wired_sockets(C.int(pid), &sockets[0], C.int(len(sockets)))
		if count < 0 {
			if gone(pid) {
				continue
			}
			return result, fmt.Errorf("cannot inspect socket ownership for process %d: %v", pid, callErr)
		}
		for i := 0; i < int(count); i++ {
			result.Sockets = append(result.Sockets, Socket{UID: uint32(sockets[i].uid), GID: uint32(sockets[i].gid), Handle: uint64(sockets[i].handle)})
		}
		current, e := unix.SysctlKinfoProc("kern.proc.pid", pid)
		if e == nil && (current.Proc.P_starttime != p.Proc.P_starttime || current.Eproc.Ucred.Uid != p.Eproc.Ucred.Uid) {
			return result, errors.New("process identity changed during socket scan")
		}
		if e != nil && !gone(pid) {
			return result, e
		}
		if len(result.Sockets) > 65536 {
			return result, errors.New("socket inventory exceeds limit")
		}
	}
	return result, nil
}

func gone(pid int) bool {
	_, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	return errors.Is(err, syscall.ESRCH) || errors.Is(err, syscall.EIO)
}

func nativeIdentity(pid int) (Identity, error) {
	p, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		if gone(pid) {
			return Identity{}, os.ErrNotExist
		}
		return Identity{}, err
	}
	if p.Proc.P_stat == 5 {
		return Identity{}, os.ErrNotExist
	}
	var path [4096]C.char
	n, err := C.proc_pidpath(C.int(pid), unsafe.Pointer(&path[0]), C.uint32_t(len(path)))
	if n <= 0 {
		if gone(pid) {
			return Identity{}, os.ErrNotExist
		}
		return Identity{}, fmt.Errorf("cannot identify process %d: %v", pid, err)
	}
	return Identity{PID: pid, Started: p.Proc.P_starttime.Sec*1000000 + int64(p.Proc.P_starttime.Usec), Path: C.GoString(&path[0]), UID: p.Eproc.Ucred.Uid, GID: p.Eproc.Ucred.Groups[0], RealGID: p.Eproc.Pcred.P_rgid, SavedGID: p.Eproc.Pcred.P_svgid}, nil
}
