"""Portable D-047 proofs, including descriptor-relative apply and partial evidence."""
from contextlib import contextmanager
import copy
import io
import json
from pathlib import Path, PurePosixPath
import stat
import sys
import types
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.semantic_provider_r3 import volatile_restore as V
from tools.semantic_provider_r3 import operate as O

encoded = V.canonical


def sealer(*_):
    """Portable record fixture; native gate uses the unchanged historical walker."""


def retained_binding(root, _):
    return RETAINED_BINDINGS[str(root)]  # supplied only by the portable loader fixture


def entry(path, kind="directory", uid=123, gid=456, mode=0o755, **fields):
    value = dict(path=path, kind=kind, uid=uid, gid=gid, mode=mode, links=2 if kind == "directory" else 1)
    if kind != "symlink": value["xattrs"] = {}
    if kind == "file": value.update(size=7, sha256=V.sha(b"payload"))
    if kind == "symlink": value.update(target=V.TARGET, mode=0o777)
    return {**value, **fields}


class Tree:
    """Small descriptor model; mutation APIs reject absolute paths and links."""
    def __init__(self, dirty=True):
        self.records = {"": entry("", uid=0, gid=0), "run": entry("run", uid=0, gid=0),
                        "run/runtime": entry("run/runtime", "file", uid=0, gid=0)}
        self.image = {p: entry(p, uid=0, gid=0) for p in V.COPYUPS}
        self.relink()
        self.expected = self.read()[0]
        if dirty:
            self.records.update(copy.deepcopy(self.image))
            for p in V.TEMPS:
                self.records[p] = entry(p)
                self.records[p + "/sub"] = entry(p + "/sub")
                self.records[p + "/sub/file"] = entry(p + "/sub/file", "file")
            for p in V.FILES: self.records[p] = entry(p, "file")
            self.records[V.LINK] = entry(V.LINK, "symlink")
        self.relink()
        self.inodes = {p: n+1 for n, p in enumerate(self.records)}
        self.fd_paths = {}; self.calls = []; self.nextfd = 10
        self.snapshot = dict(root="/docker/rootfs/overlayfs/cid", upper="/snapshots/1/fs", lowers=["/snapshots/2/fs"], work="/snapshots/1/work")
        self.H = SimpleNamespace(entries=self.read, directory_fd=self.directory, mount_rows=lambda: [], physical=V.historical().physical)
        self.context = dict(historical=self.H, sealer=sealer, comparison=dict(snapshot=self.snapshot, expectedUpperSeal=self.expected),
                            image=self.image, user=dict(uid=123, gid=456), expected=self.expected,
                            limits={}, beforeSeal=self.read()[0], cid="1"*64, sourceRoot="/source", dockerRoot="/docker")

    def relink(self):
        for p, value in self.records.items():
            if value["kind"] == "directory":
                value["links"] = 2 + sum(q != p and v["kind"] == "directory" and
                    str(PurePosixPath(q).parent) == (p or ".") for q, v in self.records.items() if q)

    def read(self, *_):
        def walk(p):
            yield p
            for q in sorted(self.records):
                if q and str(PurePosixPath(q).parent) == (p or "."):
                    yield from walk(q)
        records = {p: copy.deepcopy(self.records[p]) for p in walk("")}
        return V.predicted_seal(records, encoded), records

    def info(self, path):
        e = self.records[path]
        typ = dict(directory=stat.S_IFDIR, file=stat.S_IFREG, symlink=stat.S_IFLNK)[e["kind"]]
        return SimpleNamespace(st_dev=1, st_ino=self.inodes[path], st_mode=typ | e["mode"], st_uid=e["uid"],
            st_gid=e["gid"], st_nlink=e["links"], st_size=e.get("size", 0), st_mtime_ns=0, st_ctime_ns=0)

    def open(self, name, flags, dir_fd=None):
        assert not name.startswith("/") and flags & V.os.O_NOFOLLOW and flags & V.os.O_DIRECTORY
        path = self.fd_paths[dir_fd] + "/" + name if self.fd_paths[dir_fd] else name
        assert self.records[path]["kind"] == "directory"
        self.nextfd += 1; self.fd_paths[self.nextfd] = path
        return self.nextfd

    @contextmanager
    def directory(self, _):
        self.nextfd += 1; fd = self.nextfd; self.fd_paths[fd] = ""
        yield fd

    def remove(self, name, *, dir_fd):
        assert not name.startswith("/") and "/" not in name
        path = self.fd_paths[dir_fd] + "/" + name if self.fd_paths[dir_fd] else name
        assert not any(p.startswith(path + "/") for p in self.records)
        self.calls.append(path)
        for p in self.records:
            if p != path and self.inodes[p] == self.inodes[path]: self.records[p]["links"] -= 1
        del self.records[path]; self.relink()

    @contextmanager
    def descriptors(self):
        with patch.object(V.os, "O_NOFOLLOW", getattr(V.os, "O_NOFOLLOW", 0x100000), create=True), \
             patch.object(V.os, "O_DIRECTORY", getattr(V.os, "O_DIRECTORY", 0x200000), create=True), \
             patch.object(V.os, "open", side_effect=self.open), patch.object(V.os, "close"), \
             patch.object(V.os, "fstat", side_effect=lambda fd: self.info(self.fd_paths[fd])), \
             patch.object(V.os, "stat", side_effect=lambda name, dir_fd, follow_symlinks: self.info(
                 (self.fd_paths[dir_fd] + "/" if self.fd_paths[dir_fd] else "") + name)), \
             patch.object(V.os, "listdir", side_effect=lambda fd: [PurePosixPath(p).name for p in self.records
                 if p and str(PurePosixPath(p).parent) == (self.fd_paths[fd] or ".")]), \
             patch.object(V.os, "rmdir", side_effect=self.remove), patch.object(V.os, "unlink", side_effect=self.remove), \
             patch.object(V.os, "listxattr", side_effect=lambda fd: list(self.records[self.fd_paths[fd]]["xattrs"]),
                          create=True), \
             patch.object(V.os, "removexattr", side_effect=lambda fd, name: self.records[self.fd_paths[fd]]["xattrs"].pop(name),
                          create=True), \
             patch.object(V.os, "fsync"):
            yield

    def plan(self):
        return V.removals(self.read()[1], self.image, self.context["user"], self.expected, encoded, self.H.physical)


class PortableTests(unittest.TestCase):
    def test_loader_binds_result_oci_user_image_and_installed_seal(self):
        from test_semantic_provider_r3_operate import observation
        tree = Tree(False); docs = {}; bindings = {}; cfg = dict(admissionConfigurations={})
        def put(path, value):
            raw = V.canonical(value); docs[str(Path(path))] = raw
            return dict(path=str(Path(path)), sha256=V.sha(raw))
        result = dict(status="PREPARED", rule="D-042", sourceManifestSha256="a"*64,
                      engine=dict(dockerSocket="unix:///docker.sock", dockerRoot="/docker"), roles={})
        for role, row in observation()["candidates"].items():
            cid = row["cid"]
            root = str(Path("/docker") / "rootfs/overlayfs" / cid)
            snapshot = dict(tree.snapshot, root=root, options=[])
            bindings[root] = snapshot
            oci = dict(root=dict(path=root), process=dict(user=dict(uid=987, gid=654)))
            policy = put("/inputs/"+role+"-policy.json", dict(expectedOci=oci))
            oci_binding = put("/inputs/"+role+"-oci.json", oci)
            accepted = put("/install/"+role+"-seal.json", tree.expected)
            broker = put("/install/"+role+"-broker.json", dict(framePolicyBinding=policy, rootfsSealBinding=accepted, rootfsLimits={}))
            cfg["admissionConfigurations"][cid] = broker
            comparison = put("/inputs/"+role+"-comparison.json", dict(containerId=cid, imageId="sha256:"+"b"*64,
                rule="D-042", ociConfig=oci_binding, effectiveSeal=tree.expected, expectedSeal=tree.expected, snapshot=snapshot))
            receipt = put("/offline/"+role+"/receipt.json", dict(rootfsLimits={}, rootfsSeal=tree.expected))
            result["roles"][role] = dict(containerId=cid, imageId="sha256:"+"b"*64, effectiveSeal=tree.expected,
                                         comparison=comparison, offlineDockerReceipt=receipt)
        configuration = put("/install/runtime-configuration.json", cfg)
        rootfs = put("/inputs/rootfs-result.json", result)
        class Reader:
            def __init__(self): self.hashes = {}
            def read(self, path, expected):
                raw = docs[str(Path(path))]
                V.require(V.sha(raw) == expected, "R3_INPUT_HASH_DRIFT")
                self.hashes[str(path)] = expected
                return raw
            def bound(self, binding): return self.read(binding["path"], binding["sha256"])
            def verify(self):
                for path, digest in list(self.hashes.items()): self.read(path, digest)
        H = SimpleNamespace(decode=json.loads, PREPARED="PREPARED", mount_rows=lambda: [],
            load_sealer=lambda *_: sealer, entries=tree.read,
            overlay_binding=types.FunctionType(retained_binding.__code__, {"RETAINED_BINDINGS": bindings}))
        args = SimpleNamespace(volatile_rootfs_result=rootfs["path"], volatile_rootfs_result_sha256=rootfs["sha256"],
            volatile_source="/source", install_root="/install", wrapper="/wrapper", wrapper_sha256=V.sha(b"wrapper"),
            docker_socket="unix:///docker.sock")
        obs = observation(); obs["configurationSha256"] = configuration["sha256"]
        with patch.object(V, "historical", return_value=H), patch.object(V.I, "Reader", Reader), \
                patch.object(V, "confirm_snapshot") as confirm, \
                patch.object(V.I, "native_switch", return_value=SimpleNamespace(custody=lambda *_: (b"wrapper", None))), \
                patch.object(V.I, "wrapper_code_root", return_value=Path("/install")):
            contexts, _ = V.load(args, obs)
            self.assertEqual(contexts["southbound"]["user"], dict(uid=987, gid=654))
            self.assertEqual(confirm.call_count, 2)
            # Preserve the user-provided hash while replacing the linked OCI bytes.
            docs[str(Path("/inputs/southbound-oci.json"))] = V.canonical(dict(process=dict(user=dict(uid=636, gid=636))))
            with self.assertRaisesRegex(O.A.OperationDenied, "R3_INPUT_HASH_DRIFT"): V.load(args, obs)

    def test_allowlist_complete_apply_and_exclusive_metadata_evidence(self):
        tree = Tree(); rows = tree.plan(); report = dict(volatileEntriesRemoved=0)
        self.assertEqual(len(rows), 22)
        with tree.descriptors(), patch.object(V.I, "write_once") as write:
            V.remove(tree.context, rows, Path("/output"), report)
        self.assertEqual(tree.read()[0], tree.expected)
        self.assertEqual(report["volatileEntriesRemoved"], len(rows))
        self.assertEqual(report["volatileRemovals"], rows)
        self.assertEqual(write.call_count, len(rows))
        for call in write.call_args_list:
            self.assertEqual(set(O.decode(call.args[1])), {"path", "kind"})

    def test_copy_up_impure_marker_cleared_only_without_remaining_origin(self):
        # Copy-up of usr marks the upper root impure (kernel bookkeeping, hidden in the merged view).
        tree = Tree(); tree.records[""]["xattrs"] = {V.IMPURE: "79"}
        tree.context["beforeSeal"] = tree.read()[0]
        rows = tree.plan()
        self.assertEqual(rows[-1], {"path": "", "kind": V.IMPURE_ROW})
        report = dict(volatileEntriesRemoved=0)
        with tree.descriptors(), patch.object(V.I, "write_once"):
            V.remove(tree.context, rows, Path("/output"), report)
        self.assertEqual(tree.read()[0], tree.expected)
        self.assertEqual(report["volatileEntriesRemoved"], len(rows))
        # A remaining copied-up child keeps the marker legitimate: no clearing, exact proof denies.
        tree = Tree(); tree.records[""]["xattrs"] = {V.IMPURE: "79"}
        tree.records["run"]["xattrs"] = {"trusted.overlay.origin": "00"}
        with self.assertRaisesRegex(O.A.OperationDenied, V.DENIED):
            tree.plan()

    def test_already_sealed_zero_removals(self):
        tree = Tree(False)
        self.assertEqual(tree.plan(), [])

    def test_regular_temp_hardlinks_removed_without_following(self):
        tree = Tree()
        p = V.TEMPS[0] + "/sub/file"
        q = V.TEMPS[1] + "/sub/file"
        tree.inodes[q] = tree.inodes[p]
        tree.records[p]["links"] = tree.records[q]["links"] = 2
        tree.context["beforeSeal"] = tree.read()[0]
        report = dict(volatileEntriesRemoved=0)
        with tree.descriptors(), patch.object(V.I, "write_once"):
            V.remove(tree.context, tree.plan(), Path("/output"), report)
        self.assertEqual(tree.read()[0], tree.expected)

    def test_unknown_paths_metadata_link_and_types_denied_without_mutations(self):
        changes = [lambda t: t.records.update({"etc": entry("etc"), "etc/passwd": entry("etc/passwd", "file")}),
            lambda t: t.records.update({"usr/local/apisix/logs": entry("usr/local/apisix/logs"),
                                        "usr/local/apisix/logs/x": entry("usr/local/apisix/logs/x", "file")}),
            lambda t: t.records[V.LINK].update(target="/etc/passwd"),
            lambda t: t.records[V.TEMPS[0]].update(kind="symlink", target="/elsewhere"),
            lambda t: t.records[V.TEMPS[0]+"/sub/file"].update(kind="symlink", target="/elsewhere"),
            lambda t: t.records[V.TEMPS[0]+"/sub/file"].update(kind="fifo"),
            lambda t: t.records[V.TEMPS[0]+"/sub/file"].update(kind="socket"),
            lambda t: t.records[V.TEMPS[0]+"/sub/file"].update(kind="device"),
            lambda t: t.records[V.FILES[0]].update(uid=636),
            lambda t: t.records[V.FILES[0]].update(gid=636),
            lambda t: t.records[V.FILES[0]].update(mode=0o1644),
            lambda t: t.records[V.FILES[0]].update(links=2),
            lambda t: t.records[V.FILES[0]].update(size=1048577),
            lambda t: t.records[V.FILES[0]].update(xattrs={"security.capability": "00"}),
            lambda t: t.records[V.COPYUPS[-1]].update(mode=0o700),
            lambda t: t.records[V.COPYUPS[-1]].update(uid=123),
            lambda t: t.records[V.COPYUPS[-1]].update(links=99),
            lambda t: t.records[V.COPYUPS[-1]].update(xattrs={"trusted.overlay.opaque": "79"}),
            lambda t: t.records[V.TEMPS[0]].update(xattrs={"trusted.overlay.metacopy": "79"}),
            lambda t: t.records["run/runtime"].update(sha256="0"*64),
            lambda t: t.records[""].update(xattrs={"trusted.overlay.redirect": "00"})]
        for change in changes:
            tree = Tree(); change(tree); before = copy.deepcopy(tree.records)
            from contextlib import redirect_stderr
            with self.subTest(change=changes.index(change)), redirect_stderr(io.StringIO()), self.assertRaisesRegex(O.A.OperationDenied, V.DENIED):
                tree.plan()
            self.assertEqual(tree.records, before); self.assertEqual(tree.calls, [])

    def test_overlay_xattrs_and_temp_limits(self):
        tree = Tree()
        tree.records[V.TEMPS[0]]["xattrs"] = {"trusted.overlay.opaque": "79"}
        tree.plan()  # exactly physical(new=True), not an arbitrary overlay exclusion
        def deep(t):
            for depth in range(1, 10):
                p = V.TEMPS[0]+"/"+"/".join(["x"]*depth)
                t.records[p] = entry(p)
        for mutation in (lambda t: t.records[V.TEMPS[0]+"/sub/file"].update(size=V.MAX_BYTES+1), deep):
            tree = Tree(); mutation(tree)
            with self.assertRaisesRegex(O.A.OperationDenied, V.DENIED): tree.plan()
        with patch.object(V, "MAX_ENTRIES", 2), self.assertRaisesRegex(O.A.OperationDenied, V.DENIED): Tree().plan()

    def test_mount_and_running_or_live_epoch_denials(self):
        from test_semantic_provider_r3_operate import observation
        V.idle(observation())
        with self.assertRaisesRegex(O.A.OperationDenied, "IDLE_REQUIRED"): V.idle(observation(True))
        before = observation(); before["candidates"]["adapter"]["epoch"] = dict(state="DELETED", live=True)
        with self.assertRaisesRegex(O.A.OperationDenied, "IDLE_REQUIRED"): V.idle(before)
        snapshot = Tree().snapshot
        for target, super_ in ((snapshot["root"], []), (snapshot["upper"]+"/temp", []),
                               ("/else", ["upperdir="+snapshot["upper"]]),
                               ("/else", ["lowerdir="+snapshot["upper"]+":/lower"])):
            with self.assertRaisesRegex(O.A.OperationDenied, "OVERLAY_MOUNTED"):
                V.unmounted(snapshot, [dict(target=target, super=super_)])

    def test_post_restore_seal_mismatch_keeps_removals(self):
        tree = Tree(); report = dict(volatileEntriesRemoved=0)
        with tree.descriptors(), patch.object(V.I, "write_once"):
            V.remove(tree.context, tree.plan(), Path("/output"), report)
        tree.context["comparison"]["expectedUpperSeal"] = {**tree.expected, "sha256": "0"*64}
        with self.assertRaisesRegex(O.A.OperationDenied, V.MISMATCH): V.verify(SimpleNamespace(), tree.context)
        self.assertEqual(report["volatileEntriesRemoved"], 22)
        self.assertEqual(len(report["volatileRemovals"]), 22)

    def test_descriptor_preflight_link_and_mount_denied_before_unlink(self):
        for bad in ("link", "mount"):
            tree = Tree(); rows = tree.plan()
            if bad == "link": tree.records[V.TEMPS[0]].update(kind="symlink", target="/outside")
            else: tree.H.mount_rows = lambda: [dict(target=tree.snapshot["upper"]+"/sub", super=[])]
            with tree.descriptors(), patch.object(V.I, "write_once"), self.assertRaises(O.A.OperationDenied):
                V.remove(tree.context, rows, Path("/output"), dict(volatileEntriesRemoved=0))
            self.assertEqual(tree.calls, [])

    def test_adapter_unexpected_entry_denied(self):
        tree = Tree()
        with patch.object(V, "inspect_upper", return_value=tree.read()):
            with self.assertRaisesRegex(O.A.OperationDenied, V.DENIED):
                V.describe({"adapter": tree.context}, SimpleNamespace(verify=lambda: None, hashes={}))

    def test_full_apply_revalidates_both_roles_then_verifies_under_locks(self):
        from test_semantic_provider_r3_operate import observation
        for dirty in (True, False):
            southbound, adapter = Tree(dirty), Tree(False)
            contexts = dict(adapter=adapter.context, southbound=southbound.context)
            reader = SimpleNamespace(verify=lambda: None, hashes={})
            @contextmanager
            def locks(*_):
                events.append("lock")
                try: yield
                finally: events.append("unlock")
            def inspect(context):
                return (adapter if context is adapter.context else southbound).read()
            def verify(args, context):
                events.append("verify")
                tree = adapter if context is adapter.context else southbound
                self.assertEqual(tree.read()[0], tree.expected)
                return dict(upperSeal=tree.expected, effectiveSeal=tree.expected)
            events = []
            with patch.object(V, "inspect_upper", side_effect=inspect):
                plan = V.describe(contexts, reader)
            report = dict(volatileEntriesRemoved=0)
            args = SimpleNamespace(install_root="/install", output_directory="/output")
            with southbound.descriptors(), patch.object(V.I, "operation_locks", side_effect=locks), \
                    patch.object(V, "load", return_value=(contexts, reader)), \
                    patch.object(V, "inspect_upper", side_effect=inspect), patch.object(V, "verify", side_effect=verify), \
                    patch.object(V.I, "write_once"):
                V.apply(args, observation(), plan, report, observation)
            self.assertEqual(events, ["lock", "verify", "verify", "unlock"])
            self.assertEqual(report["volatileEntriesRemoved"], 22 if dirty else 0)

    def test_adapter_drift_during_apply_denies_before_southbound_mutation(self):
        from test_semantic_provider_r3_operate import observation
        southbound, adapter = Tree(), Tree(False)
        contexts = dict(adapter=adapter.context, southbound=southbound.context)
        reader = SimpleNamespace(verify=lambda: None, hashes={})
        def inspect(context): return (adapter if context is adapter.context else southbound).read()
        with patch.object(V, "inspect_upper", side_effect=inspect): plan = V.describe(contexts, reader)
        adapter.records["run/runtime"]["sha256"] = "0"*64
        @contextmanager
        def locks(*_): yield
        with patch.object(V.I, "operation_locks", side_effect=locks), \
                patch.object(V, "load", return_value=(contexts, reader)), \
                patch.object(V, "inspect_upper", side_effect=inspect), patch.object(V, "remove") as remove:
            with self.assertRaisesRegex(O.A.OperationDenied, V.DENIED):
                V.apply(SimpleNamespace(install_root="/install"), observation(), plan,
                        dict(volatileEntriesRemoved=0), observation)
        remove.assert_not_called()

    def test_merged_seal_mismatch_retains_completed_removals(self):
        tree = Tree(); report = dict(volatileEntriesRemoved=0)
        with tree.descriptors(), patch.object(V.I, "write_once"):
            V.remove(tree.context, tree.plan(), Path("/output"), report)
        @contextmanager
        def export(*_): yield Path(tree.snapshot["root"])
        tree.H.V1 = SimpleNamespace(stopped_export_view=export)
        tree.H.overlay_binding = lambda *_: tree.snapshot
        tree.context["expected"] = {**tree.expected, "sha256": "0"*64}
        args = SimpleNamespace(output_directory="/output", docker="/docker", docker_sha256="a"*64, docker_socket="unix:///sock")
        with self.assertRaisesRegex(O.A.OperationDenied, V.MISMATCH): V.verify(args, tree.context)
        self.assertEqual(report["volatileEntriesRemoved"], 22)

    def test_current_snapshot_drift_denied_before_removals(self):
        tree = Tree()
        @contextmanager
        def export(*_): yield Path(tree.snapshot["root"])
        tree.H.V1 = SimpleNamespace(stopped_export_view=export)
        tree.H.overlay_binding = lambda *_: {**tree.snapshot, "upper": "/snapshots/99/fs"}
        args = SimpleNamespace(output_directory="/output", docker="/docker", docker_sha256="a"*64, docker_socket="unix:///sock")
        before = copy.deepcopy(tree.records)
        with self.assertRaisesRegex(O.A.OperationDenied, "R3_VOLATILE_SNAPSHOT_DRIFT"):
            V.confirm_snapshot(args, tree.context)
        self.assertEqual(tree.records, before); self.assertEqual(tree.calls, [])

    def test_evidence_or_sync_error_keeps_completed_removal_in_report(self):
        tree = Tree(); report = dict(volatileEntriesRemoved=0)
        with tree.descriptors(), patch.object(V.I, "write_once", side_effect=OSError(5, "fixture")):
            with self.assertRaises(OSError): V.remove(tree.context, tree.plan(), Path("/output"), report)
        self.assertEqual(report["volatileEntriesRemoved"], 1)
        self.assertEqual(len(report["volatileRemovals"]), 1)
        self.assertEqual(tree.calls, [report["volatileRemovals"][0]["path"]])


if __name__ == "__main__":
    unittest.main()
