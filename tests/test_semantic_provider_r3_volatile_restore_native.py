"""D-047 real overlay/runc gate, offline and isolated from the host Docker daemon.

OUF_R3_VOLATILE_NATIVE=1 must fail (never skip) when prerequisites are missing.
The equivalent snapshot uses the same v3 binding and NodeObservation.observe.
Only unrelated signed transport/live-profile assertions are synthetic.
"""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.semantic_provider_r3 import volatile_restore as V

NATIVE = os.environ.get("OUF_R3_VOLATILE_NATIVE") == "1"
if NATIVE and (sys.platform != "linux" or os.geteuid() != 0 or os.getegid() != 0
               or not sys.flags.isolated or not sys.dont_write_bytecode):
    raise RuntimeError("OUF_R3_VOLATILE_NATIVE requires Linux root:root and python -I -B")


def run(*argv):
    return subprocess.run([str(a) for a in argv], stdin=subprocess.DEVNULL, capture_output=True,
                          check=True, timeout=30).stdout


def run_detached(*argv):
    """runc create: the container init inherits stdio, so pipes would never reach EOF."""
    with tempfile.TemporaryFile() as err:
        p = subprocess.run([str(a) for a in argv], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=err, timeout=30)
        if p.returncode:
            err.seek(0)
            raise RuntimeError("runc create failed: " + err.read().decode("utf-8", "replace")[-2000:])


def native_child():
    os.umask(0o077)
    run("mount", "--make-rprivate", "/")
    H = V.historical()
    limits = dict(maxEntries=100000, maxBytes=8589934592, maxDepth=64)
    with tempfile.TemporaryDirectory(prefix="ouf-r3-volatile-", dir="/var/lib") as directory:
        base = Path(directory); base.chmod(0o700)
        source = base / "source"
        shutil.copytree(ROOT / "tools/semantic_cohort_admission/cohort-draft", source)
        for p in [source, *source.rglob("*")]: p.chmod(0o700 if p.is_dir() else 0o600)
        with V.I.module_scope():
            sealer = H.load_sealer(source, V.sha((source / "sources.json").read_bytes()))
            node = sys.modules["tools.semantic_provider_node_observation"]

        docker_root = base / "docker"
        snapshots = docker_root / "containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots"
        upper, lower, work = snapshots / "1/fs", snapshots / "2/fs", snapshots / "1/work"
        cid = "a" * 64
        root = docker_root / "rootfs/overlayfs" / cid
        for path in (upper, lower, work, root): path.mkdir(mode=0o700, parents=True)
        for p in V.COPYUPS: (lower / p).mkdir(mode=0o755, parents=True, exist_ok=True)
        (lower / "usr/local/apisix/conf/config-default.yaml").write_bytes(b"synthetic image entry\n")
        # Locally available process and libraries: no registry or download.
        sleep = Path(shutil.which("sleep")).resolve()
        shutil.copy2(sleep, lower / "sleep")
        libraries = set(re.findall(r"/[^\s()]+", run("ldd", sleep).decode()))
        assert libraries, "dynamic sleep libraries required"
        for value in libraries:
            dest = lower / value.lstrip("/"); dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(value, dest)
        options = "lowerdir="+str(lower)+",upperdir="+str(upper)+",workdir="+str(work)
        mounted = False

        @contextmanager
        def view(*_):
            nonlocal mounted
            assert not mounted
            run("mount", "-t", "overlay", "overlay", "-o", options, root); mounted = True
            try:
                yield root
            finally:
                run("umount", root); mounted = False

        bundle = base / "bundles/fixture"; bundle.mkdir(parents=True, mode=0o700)
        runtime_root = base / "runtime/owned"; runtime_root.parent.mkdir(mode=0o700)
        runc = str(Path(shutil.which("runc")).resolve())
        run(runc, "spec", "--bundle", bundle)
        oci = json.loads((bundle / "config.json").read_bytes())
        oci["root"].update(path=str(root), readonly=False)
        oci["process"].update(terminal=False, args=["/sleep", "300"], cwd="/")
        oci["process"]["user"] = dict(uid=0, gid=0)
        (bundle / "config.json").write_bytes(V.canonical(oci))
        (bundle / "config.json").chmod(0o600)

        def binding(name):
            p = Path(shutil.which(name)).resolve()
            return dict(path=str(p), sha256=V.sha(p.read_bytes()))

        def node_observe():
            created = False
            try:
                run_detached(runc, "--root", runtime_root, "create", "--bundle", bundle, cid); created = True
                state = json.loads(run(runc, "--root", runtime_root, "state", cid))
                generation = node.NativeBackend.generation(None, state["pid"])
                application = node.application_hash(oci)
                cfg = dict(runtimeRootParents=[str(runtime_root.parent)], bundleParents=[str(bundle.parent)],
                    runtimeBinding=binding("runc"), rootfsLimits=limits,
                    commands={n: binding(n) for n in ("ip", "nsenter")},
                    candidate=dict(networkBindings=[], transport={}))
                class Budget(H.Budget):
                    def remaining(self, *_): return super().remaining()
                request = dict(containerId=cid, generation=generation, applicationHash=application,
                               transportHash="fixture", transactionId="fixture")
                with patch.object(node, "transport_hash", return_value="fixture"), \
                        patch.object(node, "declarations", return_value=[]), patch.object(node, "live_profile"):
                    return node.NodeObservation(cfg, Budget()).observe(request,
                        dict(runtimeRoot=str(runtime_root), bundleHash=application), lambda p: p.read_bytes())["rootfsSeal"]
            finally:
                if created: run(runc, "--root", runtime_root, "delete", "--force", cid)

        try:
            with view():
                baseline = node_observe()  # post-create, same sealer and actual created runc task
                assert baseline == sealer(root, limits, H.Budget())
                snapshot = H.overlay_binding(root, docker_root)
            expected_upper = sealer(upper, limits, H.Budget())
            image = H.entries(sealer, lower, limits)[1]
            with view():
                for p in V.TEMPS:
                    (root / p / "sub").mkdir(parents=True)
                    (root / p / "sub/payload").write_bytes(b"synthetic volatile data")
                os.link(root / V.TEMPS[0] / "sub/payload", root / V.TEMPS[0] / "sub/hardlink")
                for p in V.FILES: (root / p).write_bytes(b"synthetic volatile data")
                (root / V.LINK).symlink_to(V.TARGET)
            context = dict(historical=H, sealer=sealer, limits=limits, image=image,
                user=oci["process"]["user"], expected=baseline, cid=cid, dockerRoot=str(docker_root), sourceRoot=str(source),
                comparison=dict(snapshot=snapshot, expectedUpperSeal=expected_upper))
            output = base / "evidence"
            args = type("Args", (), dict(output_directory=str(output), docker=runc,
                        docker_sha256=binding("runc")["sha256"], docker_socket="unix:///fixture"))()
            with view():
                current = H.overlay_binding(root, docker_root)
            if current != snapshot:
                print("R3_VOLATILE_NATIVE_BINDING_DIFF=" + json.dumps(
                    {k: [snapshot.get(k), current.get(k)] for k in set(snapshot) | set(current)
                     if snapshot.get(k) != current.get(k)}, sort_keys=True), flush=True)
            with patch.object(H.V1, "stopped_export_view", side_effect=view):
                V.confirm_snapshot(args, context)
            seal, records = V.inspect_upper(context)
            context["beforeSeal"] = seal
            rows = V.removals(records, image, context["user"], expected_upper,
                              sealer.__globals__["encoded"], H.physical)
            assert rows and seal != expected_upper
            output.mkdir(mode=0o700)
            report = dict(volatileEntriesRemoved=0)
            V.remove(context, rows, output, report)
            assert report["volatileEntriesRemoved"] == len(rows)
            # The equivalent overlay supplies the same held view as export.
            # All binding checks, physical upper and merged seal checks stay real.
            with patch.object(H.V1, "stopped_export_view", side_effect=view):
                verified = V.verify(args, context)
            assert verified == dict(upperSeal=expected_upper, effectiveSeal=baseline)
            with view():
                recreated = node_observe()
                assert recreated == baseline == sealer(root, limits, H.Budget())
            final_seal, final_records = V.inspect_upper(context)
            assert final_seal == expected_upper
            assert V.removals(final_records, image, context["user"], expected_upper,
                              sealer.__globals__["encoded"], H.physical) == []
            print("R3_VOLATILE_NATIVE_OVERLAY_NODE_SEAL_MATCH=" + baseline["sha256"], flush=True)
        finally:
            if mounted: run("umount", root)


@unittest.skipUnless(NATIVE, "set OUF_R3_VOLATILE_NATIVE=1 under Linux root:root and python -I -B")
class NativeTests(unittest.TestCase):
    def test_real_overlay_restore_matches_recreated_node_observation(self):
        for name in ("unshare", "mount", "umount", "runc", "sleep", "ldd", "ip", "nsenter"):
            self.assertIsNotNone(shutil.which(name), "native prerequisite: " + name)
        result = subprocess.run([shutil.which("unshare"), "--mount", "--net", "--fork", sys.executable,
            "-I", "-B", str(Path(__file__).resolve()), "--native-child"], capture_output=True, timeout=180)
        self.assertEqual(result.returncode, 0, result.stdout.decode()+result.stderr.decode())
        self.assertIn(b"R3_VOLATILE_NATIVE_OVERLAY_NODE_SEAL_MATCH=", result.stdout)
        print(result.stdout.decode(), end="")


if __name__ == "__main__":
    if sys.argv[1:] == ["--native-child"]:
        if not NATIVE: raise RuntimeError("disabled native scenario")
        native_child()
    else:
        unittest.main()
