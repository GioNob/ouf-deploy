"""Bounded /proc observer of the selected container's runc-init / Python pair."""
import runpy
import sys
import time
from pathlib import Path

globals().update({k: v for k, v in runpy.run_path(str(Path(__file__).with_name('r3_common.py'))).items() if not k.startswith('__')})


def member(pid, cid):
    # Match complete Docker/containerd cgroup components, never a CID substring.
    rows = read(PROC / str(pid) / 'cgroup').decode('ascii').splitlines()
    return any(part in (cid, 'docker-' + cid + '.scope', 'cri-containerd-' + cid + '.scope')
               for line in rows for part in line.split(':', 2)[-1].split('/'))


def processes(cid):
    found = []
    for path in PROC.iterdir():
        if not path.name.isascii() or not path.name.isdecimal() or int(path.name) < 1:
            continue
        pid = int(path.name)
        try:
            if not member(pid, cid):
                continue
            comm = read(path / 'comm').decode().strip()
            argv = read(path / 'cmdline').split(b'\0')
            if comm.startswith('python') or (comm == 'runc' and b'init' in argv) or comm == 'runc:[2:INIT]':
                found.append((pid, ticks(pid), 'python' if comm.startswith('python') else 'runc-init'))
        except (OSError, ValueError):
            continue
    return sorted(found)


def port_for(cfg, role):
    ids = candidates(cfg)
    own = bound(cfg['admissionConfigurations'][ids[role]])
    own_transport = bound(own['transportBinding'])
    addresses = {n['ipv4'] for n in own_transport['networkBindings']}
    ports = set()
    for cid in ids.values():
        broker = bound(cfg['admissionConfigurations'][cid])
        transport = bound(broker['transportBinding'])
        for flow in transport['transport']:
            if flow['destination'] in addresses and flow['protocol'] == 'tcp':
                port = flow['port']
                if type(port) is not int or not 1 <= port <= 65535:
                    raise ValueError('PORT_INVALID')
                ports.add(port)
    if len(ports) != 1:
        raise ValueError('ROLE_LISTEN_PORT_AMBIGUOUS')
    return ports.pop()


def same(pid, start, cid):
    return ticks(pid) == start and member(pid, cid)


def snapshot(pid, start, cid, port, deadline=None):
    if not same(pid, start, cid):
        raise FileNotFoundError()
    base = PROC / str(pid)
    limits = []
    for line in read(base / 'limits').decode().splitlines():
        if line.startswith(('Max open files ', 'Max processes ', 'Max address space ')):
            limits.append(line[:160])
    # Report descriptors by kind, not private path names or file contents.
    fds = {}
    for fd in (base / 'fd').iterdir():
        try:
            target = os.readlink(fd)
            kind = next((k for k in ('socket:', 'pipe:', 'anon_inode:') if target.startswith(k)), 'file')
            fds[kind] = fds.get(kind, 0) + 1
        except FileNotFoundError:
            pass
    listen = False
    for name in ('tcp', 'tcp6'):
        for line in read(base / 'net' / name).decode().splitlines()[1:]:
            columns = line.split()
            if columns[3] == '0A' and int(columns[1].rsplit(':', 1)[1], 16) == port:
                listen = True
    networks = {}
    for kind in ('link', 'addr'):
        if not same(pid, start, cid):
            raise FileNotFoundError()
        remaining = 10 if deadline is None else min(10, deadline - time.monotonic())
        if remaining <= 0:
            raise TimeoutError()
        text = command(['/usr/bin/nsenter', '--net=/proc/%d/ns/net' % pid,
                        '/usr/bin/ip', '-br', kind], timeout=remaining)
        networks[kind] = [line[:300] for line in text.splitlines() if not SENSITIVE.search(line)]
    if not same(pid, start, cid):
        raise FileNotFoundError()
    return dict(pid=pid, limits=limits, fds=fds, port=port, LISTEN=listen, network=networks)


def main():
    role = arguments(sys.argv[1:], ROLES)
    cfg = configuration()
    cid = candidates(cfg)[role]
    port = port_for(cfg, role)
    deadline = time.monotonic() + 25 * 60
    first = None
    tracked = None
    while time.monotonic() < deadline:
        pair = processes(cid)
        if pair:
            if tracked is None:
                tracked = pair[0][:2]
                first = time.monotonic()
            try:
                if not same(*tracked, cid):
                    raise FileNotFoundError()
                emit(role=role, pair=[dict(kind=kind, **snapshot(pid, start, cid, port, deadline))
                                     for pid, start, kind in pair])
            except (TimeoutError, subprocess.TimeoutExpired):
                if time.monotonic() < deadline:
                    raise
                emit(role=role, state='TIMEOUT_25M')
                return 1
            except FileNotFoundError:
                emit(role=role, state='GONE')
                return 0
            if time.monotonic() - first >= 20:
                emit(role=role, state='STILL_UP_20S')
                return 0
        elif tracked is not None:
            emit(role=role, state='GONE')
            return 0
        time.sleep(min(1, max(0, deadline - time.monotonic())))
    emit(role=role, state='TIMEOUT_25M')
    return 1


if __name__ == '__main__':
    raise SystemExit(entry(main))
