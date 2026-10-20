//go:build darwin && cgo

package wiredguard

/*
#include <libproc.h>
#include <sys/proc_info.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <errno.h>

struct wired_socket {
    unsigned long long handle, pcb, generation;
    int family, protocol;
};

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
        out[used].handle = info.psi.soi_so;
        out[used].pcb = info.psi.soi_pcb;
        out[used].generation = 0;
        out[used].family = info.psi.soi_family;
        out[used].protocol = info.psi.soi_protocol;
        if (info.psi.soi_kind == SOCKINFO_TCP)
            out[used].generation = info.psi.soi_proto.pri_tcp.tcpsi_ini.insi_gencnt;
        else if (info.psi.soi_kind == SOCKINFO_IN)
            out[used].generation = info.psi.soi_proto.pri_in.insi_gencnt;
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
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func nativeSnapshot(ctx context.Context, uid uint32, state *State) (Snapshot, error) {
	return processSnapshot(ctx, uid, state, snapshotOperations{list: nativeProcessList, identity: nativeIdentity, sockets: nativeSockets, current: nativeProcess, gone: gone})
}

func nativeProcessList() ([]kernelProcess, error) {
	processes, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return nil, err
	}
	if len(processes) > 32768 {
		return nil, errors.New("process inventory exceeds limit")
	}
	result := make([]kernelProcess, 0, len(processes))
	for _, p := range processes {
		result = append(result, kernelIdentity(p))
	}
	return result, nil
}

func nativeProcess(pid int) (kernelProcess, error) {
	p, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return kernelProcess{}, err
	}
	return kernelIdentity(*p), nil
}

func kernelIdentity(p unix.KinfoProc) kernelProcess {
	name := make([]byte, 0, len(p.Proc.P_comm))
	for _, c := range p.Proc.P_comm {
		if c == 0 {
			break
		}
		name = append(name, byte(c))
	}
	return kernelProcess{Identity: processCredentials(p), Comm: string(name), Zombie: p.Proc.P_stat == 5}
}

func nativeSockets(pid int) ([]SocketKey, error) {
	var sockets [4096]C.struct_wired_socket
	count, err := C.wired_sockets(C.int(pid), &sockets[0], C.int(len(sockets)))
	if count < 0 {
		if err == nil {
			err = errors.New("libproc returned an incomplete socket inventory")
		}
		return nil, err
	}
	keys := make([]SocketKey, 0, int(count))
	for i := 0; i < int(count); i++ {
		keys = append(keys, SocketKey{Handle: uint64(sockets[i].handle), PCB: uint64(sockets[i].pcb), Generation: uint64(sockets[i].generation), Family: int(sockets[i].family), Protocol: int(sockets[i].protocol)})
	}
	return keys, nil
}

func processCredentials(p unix.KinfoProc) Identity {
	return Identity{PID: int(p.Proc.P_pid), Started: p.Proc.P_starttime.Sec*1000000 + int64(p.Proc.P_starttime.Usec), UID: p.Eproc.Ucred.Uid, GID: p.Eproc.Ucred.Groups[0], RealGID: p.Eproc.Pcred.P_rgid, SavedGID: p.Eproc.Pcred.P_svgid}
}

func gone(pid int) bool {
	_, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	return errors.Is(err, syscall.ESRCH) || errors.Is(err, syscall.EIO)
}

func nativeIdentity(pid int) (Identity, error) {
	return readProcessIdentity(pid, nativeProcess, nativeProcessPath, gone)
}

func nativeProcessPath(pid int) (string, error) {
	var path [4096]C.char
	n, err := C.proc_pidpath(C.int(pid), unsafe.Pointer(&path[0]), C.uint32_t(len(path)))
	if n <= 0 {
		if err == nil {
			err = errors.New("proc_pidpath returned no executable path")
		}
		return "", err
	}
	return C.GoString(&path[0]), nil
}
