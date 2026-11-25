"""Offline command doubles. All input/output files live in the test's private directory."""
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile

root = Path(sys.argv[1])
role, *args = sys.argv[2:]


def output(value):
    print(json.dumps(value))


if role == "nice":
    assert args[:2] == ["-n", "19"]
    role, *args = args[2:]

if role == "psql":
    assert "-XAtw" in args and "pg_catalog.pg_database" in args[-1]
    output([["example", True, 100], ["template0", False, 12], ["template1", True, 12]])
elif role == "age":
    assert "-r" in args
    raw = sys.stdin.buffer.read()
    sys.stdout.buffer.write(b"fixture-age\n" + bytes(b ^ 17 for b in raw))
elif role == "decrypt":
    assert args[:2] == ["-d", "-i"] and Path(args[2]).is_file()
    raw = Path(args[3]).read_bytes()
    prefix, body = raw.split(b"\n", 1)
    assert prefix == b"fixture-age"
    sys.stdout.buffer.write(bytes(b ^ 17 for b in body))
elif role == "docker":
    assert args[:2] == ["--host", "unix://" + str(root / "engine.sock")]
    args = args[2:]
    if args[:2] == ["volume", "ls"]:
        print("fixture-volume")
    elif args[:2] == ["volume", "inspect"]:
        output(["fixture-volume", "local", "local", str(root / "volumes/fixture-volume")])
    elif args[:2] == ["network", "ls"]:
        print("isolated")
    elif args[:2] == ["network", "inspect"]:
        output(["isolated", "example-net", "bridge", []])
    elif args[0] == "ps":
        print("fixture-pg\nfixture-kv")
    elif args[:2] == ["container", "inspect"]:
        assert "Config.Env" not in args[-2]
        mount = dict(Type="bind", Source=str(root / "sources"), Destination="/config", RW=False)
        output([args[-1], "/" + args[-1], "image-1", [mount]])
    elif args[:2] == ["image", "inspect"]:
        output(["image-1", 10240, []])
    elif args[:2] == ["image", "save"]:
        layer = bytes(10240)  # A valid empty tar layer.
        config = dict(architecture="amd64", os="linux", rootfs=dict(type="layers",
                      diff_ids=["sha256:" + hashlib.sha256(layer).hexdigest()]))
        with tarfile.open(fileobj=sys.stdout.buffer, mode="w|") as tar:
            for name, data in [("manifest.json", b'[{"Config":"cfg","Layers":["layer"]}]'),
                               ("cfg", json.dumps(config).encode()), ("layer", layer)]:
                member = tarfile.TarInfo(name)
                member.size = len(data)
                tar.addfile(member, io.BytesIO(data))
    elif args[0] == "exec" and "psql" in args:
        assert "PGOPTIONS=-c default_transaction_read_only=on" in args
        subprocess.run([sys.executable, "-I", "-B", __file__, str(root), "psql",
                        *args[args.index("psql")+1:]], check=True)
    elif "pg_dumpall" in args:
        count = 1 if '--exclude-database="example"' in args else 2
        print("-- PostgreSQL database dump complete\n" * count + "-- PostgreSQL database cluster dump complete")
    elif "pg_dump" in args:
        assert '--exclude-table-data="fixture"."sessions"' in args
        print("-- PostgreSQL database dump complete")
    elif "etcdctl" in args:
        output([{"Status": {"dbSize": 8192}}])
    elif "snapshot" in args:
        sys.stdout.buffer.write(bytes(16) + bytes.fromhex("edda0ced02000000") + bytes(8168))
    elif "cleanup" in args:
        stale = root / "etcd-private" / "db"
        if stale.exists():
            stale.unlink()
            print("cleaned")
    else:
        sys.exit(1)
else:
    sys.exit(1)
