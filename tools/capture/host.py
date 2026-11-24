"""Local, projected Engine reads. No container environment or inspect payload is logged."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import stat
import subprocess

from .contract import CHUNK, custody, digest_file, require

DB_LIST = (
    "SELECT json_agg(json_build_array(datname, datallowconn, pg_database_size(oid)) "
    "ORDER BY datname) FROM pg_catalog.pg_database"
)
CONTAINER = (
    '[{{json .Id}},{{json .Name}},{{json .Image}},{{json .Mounts}}]'
    '{{range $n,$e := .NetworkSettings.Networks}}{{println}}'
    '[{{json $n}},{{json $e.IPAddress}},{{json (index $e "Aliases")}}]{{end}}'
)
# The container owns its etcdctl authentication settings. Keep the snapshot on tmpfs.
# The fixed directory is exclusively reserved to capture on this member.
SNAP_DIR = "/dev/shm/.ouf-capture-etcd-v1"
SNAPSHOT = """
set -eu
umask 077
d="$1"
test "$(stat -f -c %T /dev/shm)" = tmpfs
exec 9< /dev/shm
flock -w 30 9
test ! -e "$d"
mkdir -m 700 "$d"
trap 'rm -f "$d/db" "$d/db.part"; rmdir "$d"' EXIT
ulimit -f "$2"
etcdctl snapshot save "$d/db" >&2
cat "$d/db"
"""
CLEAN = """
set -eu
d="$1"
exec 9< /dev/shm
flock -w 30 9
if test -d "$d" && test ! -L "$d"; then
    rm -f "$d/db" "$d/db.part"
    rmdir "$d"
    printf cleaned
fi
"""


class Host:
    unit_dirs = tuple(Path(p) for p in ("/etc/systemd/system", "/run/systemd/system",
                                        "/usr/local/lib/systemd/system", "/usr/lib/systemd/system"))
    sudoers = Path("/etc/sudoers.d")

    def __init__(self, cfg):
        self.cfg = cfg

    def boot_id(self):
        return Path("/proc/sys/kernel/random/boot_id").read_text().strip()

    def binary(self, key):
        binding = self.cfg[key]
        path = Path(binding["path"])
        custody(path)
        require(os.access(path, os.X_OK) and digest_file(path) == binding["sha256"],
                "EXECUTABLE_PIN_CHANGED")
        return str(path)

    def args(self, key, args):
        argv = [self.binary("nice"), "-n", "19", self.binary(key)]
        if key == "docker":
            custody(self.cfg["dockerSocket"], stat.S_ISSOCK)
            argv += ["--host", "unix://" + self.cfg["dockerSocket"]]
        return argv + list(args)

    def process(self, key, args, **streams):
        return subprocess.Popen(self.args(key, args), stderr=subprocess.DEVNULL,
                                env={"LC_ALL": "C", "PATH": os.defpath, "HOME": "/nonexistent",
                                     "DOCKER_CONFIG": "/nonexistent"}, **streams)

    def read(self, *args):
        with self.process("docker", args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE) as p:
            try:
                raw = p.communicate(timeout=120)[0]
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()
                raise
            require(p.returncode == 0, "DOCKER_READ_FAILED")
            return raw.decode("utf-8")

    def ids(self, *args):
        return sorted(self.read(*args).splitlines())

    def inventory(self):
        pg, etcd = self.cfg["postgres"], self.cfg["etcd"]
        volumes = []
        for name in self.ids("volume", "ls", "--format", "{{.Name}}"):
            volumes.append(json.loads(self.read("volume", "inspect", "--format",
                           '[{{json .Name}},{{json .Driver}},{{json .Scope}},{{json .Mountpoint}}]', name)))
        networks = []
        for nid in self.ids("network", "ls", "--no-trunc", "--format", "{{.ID}}"):
            networks.append(json.loads(self.read("network", "inspect", "--format",
                '[{{json .Id}},{{json .Name}},{{json .Driver}},{{json .IPAM.Config}}]', nid)))
        containers, images = [], {}
        for cid in self.ids("ps", "--no-trunc", "--format", "{{.ID}}"):
            lines = self.read("container", "inspect", "--format", CONTAINER, cid).splitlines()
            header, *endpoints = map(json.loads, lines)
            found, name, image, mounts = header
            require(found == cid, "INVENTORY_CHANGED")
            mounts = sorted(([m["Type"], m.get("Name") or m.get("Source"), m["Destination"],
                              m["RW"]] for m in mounts), key=lambda m: m[2])
            containers.append(dict(cid=cid, name=name.lstrip("/"), image=image, mounts=mounts,
                networks={n: [ip, aliases] for n, ip, aliases in endpoints}))
            if image not in images:
                ident, size, digests = json.loads(self.read("image", "inspect", "--format",
                    '[{{json .Id}},{{json .Size}},{{json .RepoDigests}}]', image))
                require(ident == image and type(size) is int and size >= 0, "INVALID_IMAGE")
                images[image] = dict(size=size, digests=sorted(digests or []))
        cids = {c["name"]: c["cid"] for c in containers}
        require(pg["container"] in cids and etcd["container"] in cids, "SOURCE_CONTAINER_MISSING")
        databases = json.loads(self.read("exec", "-e", "PGOPTIONS=-c default_transaction_read_only=on",
            cids[pg["container"]], "psql", "-XAtw", "-v", "ON_ERROR_STOP=1", "-U", pg["user"],
            "-d", pg["database"], "-c", DB_LIST))
        status = json.loads(self.read("exec", cids[etcd["container"]], "etcdctl", "endpoint",
                                      "status", "-w", "json"))
        require(len(status) == 1 and type(status[0]["Status"]["dbSize"]) is int, "INVALID_ETCD_STATUS")
        return dict(volumes=volumes, networks=networks, containers=containers, images=images,
                    databases=databases, etcdBytes=status[0]["Status"]["dbSize"])

    def clean_snapshot(self, cid, digest):
        return bool(self.read("exec", cid, "sh", "-c", CLEAN, "cleanup", SNAP_DIR + "-" + digest))

    def stream(self, args, sink):
        with self.process("docker", args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE) as p:
            try:
                while chunk := p.stdout.read(CHUNK):
                    sink.write(chunk)
                require(p.wait() == 0, "DOCKER_STREAM_FAILED")
            finally:
                p.stdout.close()
                if p.poll() is None:
                    p.kill()

    @contextmanager
    def lock(self, output):
        import fcntl
        fd = os.open(output, os.O_DIRECTORY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        finally:
            os.close(fd)
