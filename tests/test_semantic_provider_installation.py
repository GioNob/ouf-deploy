"""Tests for the installation/transaction split and exact profile publication."""

from contextlib import redirect_stderr, redirect_stdout
import io
import copy
import json
import os
from pathlib import Path
import runpy
import select
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch
import uuid


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/prepare-semantic-provider-installation.py"
if not SCRIPT.exists():
    SCRIPT = Path(__file__).with_name(SCRIPT.name)
P = runpy.run_path(str(SCRIPT))
MODULE = P["main"].__globals__


class ProfileTests(unittest.TestCase):
    def test_binary_default_rejects_privileged_and_writable_modes(self):
        reader = P["Reader"]()
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "executable"
            path.write_bytes(b"fixture")
            with patch.object(Path, "lstat") as lstat, patch.object(reader, "read") as read:
                for mode in (0o4755, 0o4555, 0o2755, 0o1755, 0o775, 0o777):
                    with self.subTest(mode=oct(mode)):
                        lstat.return_value = types.SimpleNamespace(st_mode=stat.S_IFREG | mode)
                        with self.assertRaisesRegex(P["Held"], "^EXECUTABLE_CUSTODY_UNPROVEN$"):
                            reader.binary(str(path))
                read.assert_not_called()

    def test_binary_mount_modes_are_exact_and_preserve_read_bindings(self):
        reader = P["Reader"]()
        allowed_modes = {0o555, 0o755, 0o4755, 0o4555}
        with tempfile.TemporaryDirectory() as temp:
            path = (Path(temp) / "executable").resolve()
            path.write_bytes(b"fixture")
            with patch.object(Path, "lstat") as lstat, patch.object(reader, "read") as read:
                for mode in sorted(allowed_modes):
                    with self.subTest(mode=oct(mode)):
                        lstat.return_value = types.SimpleNamespace(st_mode=stat.S_IFREG | mode)
                        self.assertEqual(reader.binary(str(path), "a" * 64, allowed_modes=allowed_modes,
                                                       maximum=4096), str(path))
                        read.assert_called_with(path, "a" * 64, mode=mode, maximum=4096, hash_only=True)
                read.reset_mock()
                for mode in (0o4775, 0o4777, 0o6755, 0o2755, 0o1755):
                    with self.subTest(mode=oct(mode)):
                        lstat.return_value = types.SimpleNamespace(st_mode=stat.S_IFREG | mode)
                        with self.assertRaisesRegex(P["Held"], "^EXECUTABLE_CUSTODY_UNPROVEN$"):
                            reader.binary(str(path), allowed_modes=allowed_modes)
                read.assert_not_called()

    def test_observe_scopes_mount_modes_and_binds_dockerd_hash_only_in_plan(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            commands = {name: str(root / name) for name in
                        ("ip", "nft", "systemctl", "nsenter", "unshare", "mount", "umount", "docker", "openssl", "dockerd")}
            for name, path in commands.items():
                Path(path).write_bytes(name.encode())
                Path(path).chmod(0o755)
            guard_file, drop_in = root / "guard.service", root / "docker.conf"
            guard_file.write_bytes(b"guard unit")
            drop_in.write_bytes(b"docker drop-in")
            reader = P["Reader"]()
            binary = Mock(wraps=reader.binary)
            # Simulate root-owned executable reads; binary() and verify() remain real.
            def read(path, expected=None, **options):
                info = path.lstat()
                pin = P["digest"](path.read_bytes())
                self.assertTrue(expected is None or expected == pin)
                reader.inputs[path] = (P["identity"](info), pin)
            hashes = {name: P["digest"](Path(path).read_bytes()) for name, path in commands.items()}
            args = types.SimpleNamespace(installation_ref="fixture", a_root=str(root / "a"), a_plan_sha256="a" * 64,
                                         authority_profile=str(root / "authority.json"), trust_policy=str(root / "trust.json"),
                                         docker_socket=str(root / "docker.sock"), docker_socket_activation="daemon",
                                         docker_socket_unit="fixture.service", docker_service_unit="fixture.service",
                                         docker_socket_owner="root", docker_socket_group="root", docker_socket_mode="0660",
                                         dockerd=commands["dockerd"], guard_service_unit="guard.service",
                                         guard_service_file=str(guard_file), docker_drop_in_file=str(drop_in))
            socket_info = types.SimpleNamespace(st_mode=stat.S_IFSOCK | 0o660, st_uid=0, st_gid=0, st_nlink=1,
                                                st_dev=1, st_ino=2, st_size=0, st_mtime_ns=0, st_ctime_ns=0)
            lstat = Path.lstat
            def observed_stat(path):
                return socket_info if str(path) == args.docker_socket else lstat(path)
            templates = {role: {"commands": commands, "commandHashes": hashes,
                                "candidate": {"networkBindings": [], "tableName": role}}
                         for role in ("adapter", "southbound")}
            owner = {"nftPath": commands["nft"], "nftSha256": hashes["nft"], "kernel": {"tableName": "guard"}}
            docs = {role: {} for role in ("semantic", "adapter", "southbound")}
            roles = {role: {"networks": {}} for role in docs}
            guard = {"snapshotRoot": str(root)}
            plans = []
            canonical = P["canonical"]
            def capture_plan(value):
                if "inputHashes" in value:
                    plans.append(value)
                return canonical(value)
            with patch.dict(MODULE, Reader=lambda: reader, directory=lambda _: None,
                            output_plan=lambda _: (root / "profile.json", [], None), authority=lambda *_: ("entity", {}),
                            receipt_a=lambda *_: ({}, {"southboundCertificate": {"sni": "gate"}}),
                            boot_guard=lambda *_: (owner, {}, guard.copy()), historical_templates=lambda *_: templates,
                            read_roles=lambda *_: docs, verify_peer=lambda *_: None, observed_networks=lambda *_: {},
                            role_profiles=lambda *_: roles, mounted_configuration=lambda *_: {"apisix": {"ssl": {"listen": [{}]}}},
                            stable_transport=lambda *_: ({}, {}), runtime=lambda *_: {}, empty_nft=lambda *_: None,
                            canonical=capture_plan), patch.object(reader, "binary", binary), patch.object(
                reader, "read", side_effect=read
            ), patch.object(Path, "lstat", observed_stat), patch.object(
                P["shutil"], "which", side_effect=lambda name, **_: commands[name]
            ), patch.object(P["Docker"], "get", return_value={}), patch.object(reader, "command", side_effect=
                lambda executable, *args: (
                    f"LoadState=loaded\nType=oneshot\nFragmentPath={guard_file}\nRequiredBy=fixture.service\nBefore=fixture.service\n"
                    if args[-1] == "guard.service" else
                    f"DropInPaths={drop_in} /unread/99-extra.conf\nRequires=guard.service\nAfter=guard.service\n"
                ).encode()
            ):
                result = P["observe"](args)
                self.assertEqual(result["profile"]["dockerdExecutable"], {"path": commands["dockerd"]})
                self.assertEqual(plans[0]["inputHashes"][commands["dockerd"]], hashes["dockerd"])
                self.assertEqual(result["profile"]["guardServiceUnit"], "guard.service")
                self.assertEqual(result["profile"]["paths"]["guard"]["unitFiles"], {
                    "guardService": str(guard_file), "dockerDropIn": str(drop_in)})
                for path in (guard_file, drop_in):
                    pin = P["digest"](path.read_bytes())
                    self.assertEqual(plans[0]["inputHashes"][str(path)], pin)
                    self.assertNotIn(pin, canonical(result["profile"]).decode())
                self.assertEqual(result["planSha256"], P["digest"](canonical(plans[0])))
                original = result
                Path(commands["dockerd"]).write_bytes(b"updated dockerd")
                reader.inputs.clear()
                result = P["observe"](args)
                self.assertEqual(result["profileSha256"], original["profileSha256"])
                self.assertNotEqual(result["planSha256"], original["planSha256"])
                self.assertEqual(plans[1]["inputHashes"][commands["dockerd"]], P["digest"](b"updated dockerd"))
                guard_file.write_bytes(b"updated guard")
                drop_in.write_bytes(b"updated drop-in")
                reader.inputs.clear()
                updated = P["observe"](args)
                self.assertEqual(updated["profileSha256"], result["profileSha256"])
                self.assertNotEqual(updated["planSha256"], result["planSha256"])
                for path in (guard_file, drop_in):
                    self.assertEqual(plans[2]["inputHashes"][str(path)], P["digest"](path.read_bytes()))
                previous = copy.deepcopy(updated["profile"])
                del previous["guardServiceUnit"]
                del previous["paths"]["guard"]["unitFiles"]
                binding = {"previousProfileSha256": "b" * 64,
                           "previousProfileIdentity": {"dev": 1, "inode": 2, "size": 100, "mtime_ns": 3}}
                with patch.dict(MODULE, output_plan=lambda _: (root / "profile.json", [], (previous, binding))):
                    reader.inputs.clear()
                    revised = P["observe"](args)
                self.assertEqual(revised["profileSha256"], updated["profileSha256"])
                self.assertNotEqual(revised["planSha256"], updated["planSha256"])
                self.assertEqual(plans[3]["projection"]["profileDiff"], revised["profileDiff"])
                self.assertEqual(plans[3]["projection"]["previousProfileIdentity"], binding["previousProfileIdentity"])
                self.assertEqual(revised["planSha256"], P["digest"](canonical(plans[3])))
            self.assertEqual([call.args[0] for call in binary.call_args_list], [commands[name] for name in (
                "systemctl", "ip", "nft", "dockerd", "nsenter", "unshare", "mount", "umount", "docker", "openssl"
            )] * 4)
            for call in binary.call_args_list:
                expected = {"allowed_modes": {0o555, 0o755, 0o4755, 0o4555}} if call.args[0] in (
                    commands["mount"], commands["umount"]
                ) else ({"maximum": 268435456} if call.args[0] == commands["dockerd"] else {})
                self.assertEqual(call.kwargs, expected)

    def test_role_projection_excludes_engine_identifiers_and_aliases(self):
        network_id = "a" * 64
        networks = {"back": (network_id, {"bridge": "ouf-test", "internal": False, "subnets": ["10.15.0.0/24"]})}
        endpoint = {"NetworkID": network_id, "IPAddress": "10.15.0.2", "MacAddress": "02:00:00:00:00:02",
                    "Aliases": ["semantic", "a123456789ab"], "DNSNames": ["semantic", "b123456789ab"],
                    "EndpointID": "c" * 64}
        docs = {"semantic": {"Name": "/semantic", "Id": "d" * 64,
                             "NetworkSettings": {"Networks": {"back": endpoint}}}}
        profile = P["role_profiles"](docs, networks)
        self.assertEqual(profile["semantic"]["networks"]["back"], {
            "ipv4": "10.15.0.2", "mac": "02:00:00:00:00:02", "aliases": ["semantic"], "dnsNames": ["semantic"],
        })
        endpoint["NetworkID"] = "e" * 64
        with self.assertRaisesRegex(P["Held"], "^SEMANTIC_NETWORK_ID_CHANGED$"):
            P["role_profiles"](docs, networks)

    def test_explicit_ports_come_from_matching_observations(self):
        def role(addresses, names):
            return {"networks": {str(index): {"ipv4": addr, "dnsNames": names}
                                 for index, addr in enumerate(addresses)}}
        roles = {"semantic": role(["10.15.0.2"], []), "southbound": role(["10.15.0.3", "10.16.0.3"], ["gate"]),
                 "adapter": role(["10.16.0.4"], [])}
        docs = {"semantic": {"Config": {"Env": [
            "OUF_SCHEMA_GOV_GATEWAY_BASE_URL=https://gate:15443",
            "OUF_SCHEMA_GOV_TOKEN_ENDPOINT=https://identity.example:1443/token",
            "UNRELATED_SECRET=ignore",
        ]}}}
        workload = {"purpose": "WORKLOAD_GATEWAY", "source": "10.15.0.2", "destination": "10.15.0.3",
                    "protocol": "tcp", "port": 15443, "peerIngress": {"ifindex": 971}}
        relay = {"purpose": "GATEWAY_ADAPTER", "source": "10.16.0.3", "destination": "10.16.0.4",
                 "protocol": "tcp", "port": 19443}
        templates = {"southbound": {"candidate": {"transport": [workload, relay]}},
                     "adapter": {"candidate": {"transport": [relay]}}}
        owner = {"kernel": {"providerFlows": [
            {"source": "10.16.0.4", "endpoint": "https://public.example:2443/"},
            {"source": "10.16.0.3", "endpoint": "https://identity.example:1443/keys"},
        ]}}
        peer = {"proposedIngress": {"sourceIpv4": "10.15.0.2", "destinationIpv4": "10.15.0.3",
                                    "destinationPort": 15443}}
        adapter = {"listenAddress": "10.16.0.4", "listenPort": 19443,
                   "provider": {"endpoint": "https://public.example:2443/query"}}
        listener = {"ip": "0.0.0.0", "port": 15443}
        ports, endpoints = P["stable_transport"](docs, roles, templates, owner, peer, "gate", adapter, listener)
        self.assertEqual(ports, {"southbound": 15443, "adapter": 19443})
        self.assertEqual(endpoints, {"provider": {"host": "public.example", "port": 2443, "sourceRole": "adapter"},
                                     "iam": {"host": "identity.example", "port": 1443, "sourceRole": "southbound"}})
        with self.assertRaisesRegex(P["Held"], "^OBSERVED_LISTENER_OR_SERVICE_ENDPOINT_CHANGED$"):
            P["stable_transport"](docs, roles, templates, owner, peer, "gate", adapter, listener | {"port": 15444})

    def test_bound_guard_and_empty_lock(self):
        pointer = {"schema": "ouf.semantic-coordinated-boot-pointer.v1", "receiptFile": "/etc/site/receipt.json",
                   "receiptHash": "a" * 64, "observerFile": "/etc/site/observer.py", "observerHash": "b" * 64}
        receipt = {"schema": "ouf.discovery-successor-boot-installation.v1", "state": "INSTALLED",
                   "leaseAuthorized": False, "startAuthorized": False, "observerHash": "b" * 64,
                   "stageDirectory": "/etc/site/stage", "bootProfileHash": "c" * 64, "configurationHash": "d" * 64}
        profile = {"coordinatedConfiguration": "/etc/site/owner.json", "coordinatedConfigurationHash": "d" * 64,
                   "bootConfiguration": "/etc/site/boot.json", "bootConfigurationHash": "e" * 64}
        owner = {"kernel": {"tableName": "site_guard"}, "commonLockFile": "/etc/site/lock",
                 "journalFile": "/etc/site/journal.json", "binding": {"configurationHash": "f" * 64}}
        boot = {"kernel": owner["kernel"], "lockFile": owner["commonLockFile"], "journalFile": "/etc/site/boot-journal.json"}
        journal = {"state": "QUIESCED", "leaseAuthorized": False, "startAuthorized": False,
                   "leaseAddresses": [[], []], **owner["binding"]}
        documents = {"/etc/site/pointer.json": pointer, "/etc/site/receipt.json": receipt,
                     "/etc/site/stage/boot-profile.json": profile, "/etc/site/owner.json": owner,
                     "/etc/site/boot.json": boot, "/etc/site/journal.json": journal}
        def read(path, expected=None, **kwargs):
            if str(path) == "/etc/site/lock":
                self.assertEqual(kwargs["minimum"], 0)
                return b""
            return b"fixture"
        reader = types.SimpleNamespace(document=lambda path, *args: documents[str(path)], read=read)
        args = types.SimpleNamespace(guard_pointer="/etc/site/pointer.json")
        self.assertEqual(P["boot_guard"](reader, args)[2]["lock"], "/etc/site/lock")
        journal["leaseAddresses"] = [["203.0.113.19"], []]
        with self.assertRaisesRegex(P["Held"], "^QUIESCED_COORDINATION_JOURNAL_REQUIRED$"):
            P["boot_guard"](reader, args)

    def test_file_publication_does_not_replace_existing_file(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "ouf" / "fixture"
            target = path / "semantic-provider.json"
            writes = {"profileFile": str(target), "directoriesIfMissing": [str(path.parent), str(path)]}
            with patch.dict(MODULE, directory=lambda _: None), patch.object(os, "fchown", wraps=os.fchown if os.geteuid() == 0 else lambda *args: None):
                P["publish"](writes, b'{"profile":1}\n')
                with self.assertRaises(FileExistsError):
                    P["publish"](writes | {"directoriesIfMissing": []}, b'{"profile":2}\n')
            self.assertEqual(target.read_bytes(), b'{"profile":1}\n')
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            self.assertEqual(list(path.iterdir()), [target])
            if os.geteuid() == 0:
                self.assertEqual((target.stat().st_uid, target.stat().st_gid), (0, 0))

    def test_plan_outputs_canonical_profile_and_mismatch_cannot_publish(self):
        profile = {"schema": P["SCHEMA"], "installationRef": "test"}
        proposal = {"profile": profile, "profileSha256": P["digest"](P["canonical"](profile) + b"\n"),
                    "planSha256": "a" * 64, "writes": {}}
        flags = {"installation-ref": "test", **{name: "/fixture" for name in (
            "installation-root", "a-root", "guard-pointer", "docker-socket", "generation-receipt", "authority-profile", "trust-policy",
            "dockerd", "docker-socket-unit", "docker-service-unit", "docker-socket-owner", "docker-socket-group", "docker-socket-mode",
            "guard-service-unit", "guard-service-file", "docker-drop-in-file"
        )}, **{name: "a" * 64 for name in (
            "a-plan-sha256", "generation-receipt-sha256", "authority-sha256", "trust-policy-sha256"
        )}, "docker-socket-activation": "daemon"}
        common = [part for name, value in flags.items() for part in ("--" + name, value)]
        def forbidden(*args):
            self.fail("publication was attempted")
        with patch.dict(MODULE, observe=lambda _: proposal, publish=forbidden), patch.object(
            os, "geteuid", return_value=0
        ), patch.object(os, "getegid", return_value=0):
            for arguments, code, expected in (
                (["--plan"], 0, "PLAN_READY"),
                (["--apply", "--plan-sha256", "b" * 64], 1, "HELD"),
            ):
                stdout = io.StringIO()
                with patch.object(sys, "argv", ["profile", *common, *arguments]), redirect_stdout(stdout):
                    self.assertEqual(P["main"](), code)
                report = json.loads(stdout.getvalue())
                self.assertEqual(report["status"], expected)
                self.assertEqual(report["profile"], profile)
                self.assertEqual(stdout.getvalue().encode(), P["canonical"](report) + b"\n")

    def test_listener_requires_the_exact_listening_inode_among_dockerd_fds(self):
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory)
            (proc / "net").mkdir()
            (proc / "fd").mkdir()
            path = "/run/fixture.sock"
            (proc / "net/unix").write_text("Num RefCount Protocol Flags Type St Inode Path\n"
                                          f"0: 00000002 00000000 00010000 0001 01 431 {path}\n"
                                          f"0: 00000003 00000000 00000000 0001 03 432 {path}\n")
            (proc / "fd/3").symlink_to("socket:[432]")
            with self.assertRaisesRegex(P["Held"], "^DOCKER_LISTENER_FD_UNPROVEN$"):
                P["require_listener_fd"](proc, path)
            (proc / "fd/4").symlink_to("socket:[431]")
            self.assertEqual(P["require_listener_fd"](proc, path), 431)


class GuardUnitTests(unittest.TestCase):
    def setUp(self):
        self.args = types.SimpleNamespace(guard_service_unit="site-guard.service", docker_service_unit="engine.service",
                                         guard_service_file="/etc/site/guard.service",
                                         docker_drop_in_file="/etc/site/docker.conf")
        self.properties = {
            "site-guard.service": {"LoadState": "loaded", "Type": "oneshot", "FragmentPath": self.args.guard_service_file,
                                   "RequiredBy": "unrelated.service engine.service", "Before": "engine.service other.service"},
            "engine.service": {"DropInPaths": "/not/read/99-ouf-boot-lock.conf " + self.args.docker_drop_in_file
                               + " /not/read/99-ouf-journal-state.conf",
                               "Requires": "site-guard.service other.service", "After": "other.service site-guard.service"}}
        self.reader = Mock()
        self.reader.command.side_effect = self.command

    def command(self, executable, *args):
        self.assertEqual(executable, "/verified/systemctl")
        self.assertEqual(args[:3], ("show", "--all", "--no-pager"))
        names = args[3].removeprefix("--property=").split(",")
        return "".join(f"{name}={self.properties[args[-1]][name]}\n" for name in names
                       if name in self.properties[args[-1]]).encode()

    def observe(self):
        return P["guard_units"](self.reader, self.args, "/verified/systemctl")

    def test_verifies_only_selected_unit_files_and_accepts_other_drop_ins(self):
        self.assertEqual(self.observe(), {"guardService": self.args.guard_service_file,
                                         "dockerDropIn": self.args.docker_drop_in_file})
        self.assertEqual([str(call.args[0]) for call in self.reader.read.call_args_list],
                         [self.args.guard_service_file, self.args.docker_drop_in_file])
        for call in self.reader.read.call_args_list:
            self.assertEqual(call.kwargs, {})  # Reader's strict root:root/0600/nlink=1 defaults.

    def test_each_wrong_systemd_property_is_held(self):
        for unit, key, wrong, reason in (
            ("site-guard.service", "LoadState", "not-found", "GUARD_UNIT_UNPROVEN"),
            ("site-guard.service", "Type", "simple", "GUARD_UNIT_UNPROVEN"),
            ("site-guard.service", "FragmentPath", "/etc/another.service", "GUARD_UNIT_FILE_UNPROVEN"),
            ("site-guard.service", "RequiredBy", "engine.service.other", "GUARD_UNIT_UNPROVEN"),
            ("site-guard.service", "Before", "", "GUARD_UNIT_UNPROVEN"),
            ("engine.service", "DropInPaths", "/etc/site/docker.conf.other", "DOCKER_DROP_IN_UNPROVEN"),
            ("engine.service", "Requires", "", "DOCKER_DROP_IN_UNPROVEN"),
            ("engine.service", "After", "site-guard.service.other", "DOCKER_DROP_IN_UNPROVEN"),
        ):
            with self.subTest(property=key), patch.dict(self.properties[unit], {key: wrong}):
                with self.assertRaisesRegex(P["Held"], "^" + reason + "$"):
                    self.observe()

    def test_missing_properties_and_failed_commands_are_held(self):
        for unit, reason in (("site-guard.service", "GUARD_UNIT_UNPROVEN"),
                              ("engine.service", "DOCKER_DROP_IN_UNPROVEN")):
            with self.subTest(unit=unit), patch.dict(self.properties, {unit: {}}):
                with self.assertRaisesRegex(P["Held"], "^" + reason + "$"):
                    self.observe()
        self.reader.command.side_effect = P["Held"]("NATIVE_READ_UNPROVEN")
        with self.assertRaisesRegex(P["Held"], "^GUARD_UNIT_UNPROVEN$"):
            self.observe()

    def test_invalid_unit_names_and_relative_paths_are_held(self):
        for unit in ("../guard.service", "guard.socket", ".service", "/guard.service", "guard service"):
            with self.subTest(unit=unit), patch.object(self.args, "guard_service_unit", unit):
                with self.assertRaisesRegex(P["Held"], "^GUARD_UNIT_UNPROVEN$"):
                    self.observe()
        for name, reason in (("guard_service_file", "GUARD_UNIT_FILE_UNPROVEN"),
                             ("docker_drop_in_file", "DOCKER_DROP_IN_UNPROVEN")):
            with self.subTest(argument=name), patch.object(self.args, name, "relative"):
                with self.assertRaisesRegex(P["Held"], "^" + reason + "$"):
                    self.observe()


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "requires native Linux root filesystem")
class RevisionTests(unittest.TestCase):
    def setUp(self):
        work = tempfile.TemporaryDirectory(prefix="ouf-p-revision-", dir="/run")
        self.addCleanup(work.cleanup)
        self.root = Path(work.name)
        self.parent = self.root / "fixture"
        self.parent.mkdir(mode=0o700)
        self.target = self.parent / "semantic-provider.json"
        self.previous = {"schema": P["SCHEMA"], "installationRef": "fixture", "dockerServiceUnit": "engine.service",
                         "paths": {"guard": {"pointer": "/etc/site/pointer"}}}
        # Bind exact old bytes, including noncanonical whitespace and CRLF.
        self.old_raw = (json.dumps(self.previous, indent=2) + "\n").replace("\n", "\r\n").encode()
        self.target.write_bytes(self.old_raw)
        self.target.chmod(0o600)
        self.old_pin = P["digest"](self.old_raw)
        self.args = types.SimpleNamespace(installation_root=str(self.root), installation_ref="fixture",
                                         revise_from_sha256=self.old_pin)
        self.current = copy.deepcopy(self.previous)
        self.current["guardServiceUnit"] = "site-guard.service"
        self.current["paths"]["guard"]["unitFiles"] = {"guardService": "/etc/site/guard.service",
                                                       "dockerDropIn": "/etc/site/docker.conf"}
        self.raw = P["canonical"](self.current) + b"\n"
        self.backup = self.target.with_name(self.target.name + ".superseded-" + self.old_pin)

    def proposal(self):
        destination, absent, (previous, binding) = P["output_plan"](self.args)
        return {"profile": self.current, "profileSha256": P["digest"](self.raw),
                "writes": {"profileFile": str(destination), "directoriesIfMissing": absent},
                **P["revision_plan"](previous, self.current, binding)}

    def argv(self, *mode):
        flags = {name: "/fixture" for name in (
            "installation-root", "a-root", "guard-pointer", "docker-socket", "generation-receipt", "authority-profile",
            "trust-policy", "dockerd", "docker-socket-unit", "docker-service-unit", "docker-socket-owner",
            "docker-socket-group", "docker-socket-mode", "guard-service-unit", "guard-service-file", "docker-drop-in-file")}
        flags.update({name: "a" * 64 for name in (
            "a-plan-sha256", "generation-receipt-sha256", "authority-sha256", "trust-policy-sha256")})
        flags.update({"installation-ref": "fixture", "docker-socket-activation": "daemon",
                      "revise-from-sha256": self.old_pin})
        return ["profile", *[part for name, value in flags.items() for part in ("--" + name, value)], *mode]

    def run_main(self, proposal, *mode):
        stdout = io.StringIO()
        with patch.dict(MODULE, observe=Mock(return_value=proposal)), patch.object(
                sys, "argv", self.argv(*mode)), redirect_stdout(stdout):
            code = P["main"]()
        return code, json.loads(stdout.getvalue())

    def test_base_missing_or_wrong_raw_hash_is_held(self):
        self.args.revise_from_sha256 = P["digest"](P["canonical"](self.previous) + b"\n")
        with self.assertRaisesRegex(P["Held"], "^REVISION_BASE_PROFILE_UNPROVEN$"):
            P["output_plan"](self.args)
        self.target.unlink()
        with self.assertRaisesRegex(P["Held"], "^REVISION_BASE_PROFILE_UNPROVEN$"):
            P["output_plan"](self.args)

    def test_initial_publication_still_requires_absence(self):
        self.args.revise_from_sha256 = None
        with self.assertRaisesRegex(P["Held"], "^INSTALLATION_PROFILE_ALREADY_EXISTS$"):
            P["output_plan"](self.args)
        self.target.unlink()
        self.assertEqual(P["output_plan"](self.args), (self.target, [], None))

    def test_expected_diff_plan_and_final_report(self):
        proposal = self.proposal()
        expected = [{"path": path, "change": "added"} for path in (
            "/guardServiceUnit", "/paths/guard/unitFiles/dockerDropIn", "/paths/guard/unitFiles/guardService")]
        self.assertEqual(proposal["profileDiff"], expected)
        info = self.target.stat()
        self.assertEqual(proposal["previousProfileIdentity"], {
            "dev": info.st_dev, "inode": info.st_ino, "size": len(self.old_raw), "mtime_ns": info.st_mtime_ns})
        self.assertEqual(proposal["previousProfileSha256"], self.old_pin)
        proposal["planSha256"] = "a" * 64
        code, report = self.run_main(proposal, "--plan")
        self.assertEqual((code, report["status"], report["profileDiff"]), (0, "PLAN_READY", expected))
        self.assertEqual(list(self.parent.iterdir()), [self.target])
        code, report = self.run_main(proposal, "--apply", "--plan-sha256", "a" * 64)
        self.assertEqual((code, report["status"]), (0, "SEMANTIC_PROVIDER_INSTALLATION_PROFILE_REVISED"))
        self.assertEqual(report["privateKeysRead"], 0)
        self.assertEqual(report["previousProfileSha256"], self.old_pin)
        self.assertEqual(report["profileSha256"], P["digest"](self.raw))
        self.assertEqual(report["supersededFile"], str(self.backup))
        self.assertEqual(report["revisionOutcome"], {"supersededFile": str(self.backup), "supersededLinked": True,
            "renamed": True, "directorySynced": True, "readbackVerified": True, "temporaryFile": None})
        self.assertEqual(self.target.read_bytes(), self.raw)
        self.assertEqual(self.backup.read_bytes(), self.old_raw)
        self.assertEqual(set(self.parent.iterdir()), {self.target, self.backup})
        for path in (self.target, self.backup):
            info = path.stat()
            self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), info.st_nlink), (0, 0, 0o600, 1))

    def test_other_deltas_are_held_and_report_only_paths(self):
        variants = []
        changed = copy.deepcopy(self.current)
        changed["dockerServiceUnit"] = "PRIVATE_VALUE"
        variants.append((self.previous, changed, "/dockerServiceUnit"))
        removed = copy.deepcopy(self.current)
        del removed["installationRef"]
        variants.append((self.previous, removed, "/installationRef"))
        variants.append((self.current, self.current, None))  # An already revised base is not another revision.
        partial = self.previous | {"guardServiceUnit": "old-guard.service"}
        variants.append((partial, self.current, "/guardServiceUnit"))
        variants.append((self.previous | {"number": True}, self.current | {"number": 1}, "/number"))
        for before, after, path in variants:
            with self.subTest(path=path), self.assertRaises(P["Held"]) as caught:
                P["revision_plan"](before, after, {})
            self.assertEqual(str(caught.exception), "PROFILE_REVISION_UNEXPECTED_DELTA")
            self.assertNotIn("PRIVATE_VALUE", json.dumps(caught.exception.details))
            self.assertTrue(all(isinstance(item, str) for item in caught.exception.details["profileDiff"]))
            if path:
                self.assertIn(path, caught.exception.details["profileDiff"])
        with patch.dict(MODULE, observe=Mock(side_effect=P["Held"](
                "PROFILE_REVISION_UNEXPECTED_DELTA", profileDiff=["/dockerServiceUnit"]))), patch.object(
                sys, "argv", self.argv("--plan")), redirect_stdout(io.StringIO()) as stdout:
            self.assertEqual(P["main"](), 1)
        self.assertEqual(json.loads(stdout.getvalue())["profileDiff"], ["/dockerServiceUnit"])

    def test_apply_rechecks_hash_and_identity_before_any_write(self):
        proposal = self.proposal() | {"planSha256": "a" * 64}
        for change in ("bytes", "inode", "mtime"):
            with self.subTest(change=change):
                self.target.write_bytes(self.old_raw)
                proposal = self.proposal() | {"planSha256": "a" * 64}
                if change == "bytes":
                    self.target.write_bytes(b"changed")
                elif change == "inode":
                    other = self.parent / "replacement"
                    other.write_bytes(self.old_raw)
                    other.chmod(0o600)
                    os.utime(other, ns=(self.target.stat().st_atime_ns, self.target.stat().st_mtime_ns))
                    other.replace(self.target)
                else:
                    info = self.target.stat()
                    os.utime(self.target, ns=(info.st_atime_ns, info.st_mtime_ns + 1000000))
                before = self.target.read_bytes()
                code, report = self.run_main(proposal, "--apply", "--plan-sha256", "a" * 64)
                self.assertEqual((code, report["reason"]), (1, "REVISION_BASE_PROFILE_UNPROVEN"))
                self.assertEqual(self.target.read_bytes(), before)
                self.assertEqual(list(self.parent.iterdir()), [self.target])

    def test_digest_mismatch_and_existing_superseded_prevent_writes(self):
        proposal = self.proposal() | {"planSha256": "a" * 64}
        code, report = self.run_main(proposal, "--apply", "--plan-sha256", "b" * 64)
        self.assertEqual((code, report["reason"]), (1, "PLAN_DIGEST_CHANGED"))
        self.assertEqual(list(self.parent.iterdir()), [self.target])
        self.backup.write_bytes(b"preserved")
        code, report = self.run_main(proposal, "--apply", "--plan-sha256", "a" * 64)
        self.assertEqual((code, report["reason"]), (1, "REVISION_SUPERSEDED_ALREADY_EXISTS"))
        self.assertEqual(self.target.read_bytes(), self.old_raw)
        self.assertEqual(self.backup.read_bytes(), b"preserved")
        self.assertFalse(report["revisionOutcome"]["supersededLinked"])

    def test_base_replaced_after_link_is_not_overwritten(self):
        proposal = self.proposal() | {"planSha256": "a" * 64}
        fsync = os.fsync
        replaced = False
        def replace_after_temporary_fsync(fd):
            nonlocal replaced
            result = fsync(fd)
            if not replaced and stat.S_ISREG(os.fstat(fd).st_mode):
                other = self.parent / "replacement"
                other.write_bytes(b"third-party content")
                other.chmod(0o600)
                other.replace(self.target)
                replaced = True
            return result
        with patch.object(os, "fsync", side_effect=replace_after_temporary_fsync):
            code, report = self.run_main(proposal, "--apply", "--plan-sha256", "a" * 64)
        self.assertEqual((code, report["reason"]), (1, "REVISION_BASE_PROFILE_UNPROVEN"))
        self.assertTrue(report["revisionOutcome"]["supersededLinked"])
        self.assertFalse(report["revisionOutcome"]["renamed"])
        self.assertEqual(self.target.read_bytes(), b"third-party content")
        self.assertEqual(self.backup.read_bytes(), self.old_raw)
        self.assertEqual(set(self.parent.iterdir()), {self.target, self.backup})

    def test_failures_after_link_and_after_rename_report_exact_stage_without_rollback(self):
        for stage in ("write", "rename", "directory-fsync", "readback"):
            with self.subTest(stage=stage):
                if self.backup.exists():
                    self.backup.unlink()
                self.target.write_bytes(self.old_raw)
                proposal = self.proposal() | {"planSha256": "a" * 64}
                fsync = os.fsync
                rename = os.rename
                renamed = False
                def do_rename(*args, **kwargs):
                    nonlocal renamed
                    rename(*args, **kwargs)
                    renamed = True
                def do_fsync(fd):
                    if stage == "directory-fsync" and renamed:
                        raise OSError(5, "injected fsync failure")
                    return fsync(fd)
                def readback(reader, path, *args, **kwargs):
                    if stage == "readback" and renamed and path == self.target:
                        raise P["Held"]("REVISION_READBACK_UNPROVEN")
                    return original_read(reader, path, *args, **kwargs)
                original_read = P["Reader"].read
                with patch.object(os, "fchown", side_effect=OSError(5, "injected write failure") if stage == "write" else os.fchown), patch.object(
                        os, "rename", side_effect=OSError(5, "injected rename failure") if stage == "rename" else do_rename), patch.object(
                        os, "fsync", side_effect=do_fsync), patch.object(P["Reader"], "read", autospec=True, side_effect=readback):
                    code, report = self.run_main(proposal, "--apply", "--plan-sha256", "a" * 64)
                self.assertEqual((code, report["status"]), (1, "HELD"))
                outcome = report["revisionOutcome"]
                self.assertTrue(outcome["supersededLinked"])
                self.assertEqual(outcome["renamed"], stage in ("directory-fsync", "readback"))
                self.assertEqual(outcome["directorySynced"], stage == "readback")
                self.assertFalse(outcome["readbackVerified"])
                self.assertIsNone(outcome["temporaryFile"])
                self.assertEqual(self.target.read_bytes(), self.raw if outcome["renamed"] else self.old_raw)
                self.assertEqual(self.backup.read_bytes(), self.old_raw)
                self.assertEqual(set(self.parent.iterdir()), {self.target, self.backup})

    def test_base_custody_and_guard_files_reject_modes_owners_links_and_symlinks(self):
        guard = GuardUnitTests()
        guard.setUp()
        guard.args.guard_service_file = str(self.target)
        drop_in_dir = self.parent / "dropins"
        drop_in_dir.mkdir(mode=0o700)
        drop_in = drop_in_dir / "docker.conf"
        drop_in.write_bytes(b"drop-in")
        drop_in.chmod(0o600)
        guard.args.docker_drop_in_file = str(drop_in)
        guard.properties["site-guard.service"]["FragmentPath"] = str(self.target)
        guard.properties["engine.service"]["DropInPaths"] = str(drop_in) + " /not/read/99-extra.conf"
        guard.reader = P["Reader"]()
        with patch.object(guard.reader, "command", side_effect=guard.command):
            guard.observe()
        self.assertEqual(guard.reader.verify(), {
            str(self.target): self.old_pin, str(drop_in): P["digest"](b"drop-in")})
        for target, reason in ((self.target, "GUARD_UNIT_FILE_UNPROVEN"), (drop_in, "DOCKER_DROP_IN_UNPROVEN")):
            for defect in ("mode", "uid", "gid", "hardlink", "symlink", "ancestor", "directory"):
                with self.subTest(target=target.name, defect=defect):
                    saved = target.parent / "saved"
                    if defect == "mode":
                        target.chmod(0o644)
                    elif defect in ("uid", "gid"):
                        os.chown(target, 1 if defect == "uid" else 0, 1 if defect == "gid" else 0)
                    elif defect == "hardlink":
                        os.link(target, saved)
                    elif defect in ("symlink", "directory"):
                        target.rename(saved)
                        if defect == "symlink":
                            target.symlink_to(saved)
                        else:
                            target.mkdir()
                    else:
                        target.parent.chmod(0o777)
                    try:
                        if target == self.target:
                            with self.assertRaisesRegex(P["Held"], "^REVISION_BASE_PROFILE_UNPROVEN$"):
                                P["output_plan"](self.args)
                        guard.reader = P["Reader"]()
                        with patch.object(guard.reader, "command", side_effect=guard.command):
                            with self.assertRaisesRegex(P["Held"], "^" + reason + "$"):
                                guard.observe()
                    finally:
                        target.parent.chmod(0o700)
                        if defect in ("symlink", "directory"):
                            target.rmdir() if defect == "directory" else target.unlink()
                            saved.rename(target)
                        elif defect == "hardlink":
                            saved.unlink()
                        os.chown(target, 0, 0)
                        target.chmod(0o600)

    def test_required_new_arguments_and_revision_hash_syntax(self):
        for name in ("guard-service-unit", "guard-service-file", "docker-drop-in-file"):
            argv = self.argv("--plan")
            index = argv.index("--" + name)
            del argv[index:index + 2]
            with self.subTest(argument=name), patch.object(sys, "argv", argv), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as caught:
                    P["main"]()
                self.assertEqual(caught.exception.code, 2)
        for bad in ("A" * 64, "a" * 63, "../hash"):
            argv = self.argv("--plan")
            argv[argv.index("--revise-from-sha256") + 1] = bad
            with self.subTest(hash=bad), patch.object(sys, "argv", argv), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as caught:
                    P["main"]()
                self.assertEqual(caught.exception.code, 2)


@unittest.skipUnless(os.environ.get("OUF_P_NATIVE") == "1", "requires hosted root and systemd")
class NativeDockerPeerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        work = tempfile.TemporaryDirectory(prefix="ouf-p-peer-", dir="/run")
        cls.addClassCleanup(work.cleanup)
        cls.root = Path(work.name)
        cls.dockerd = cls.root / "dockerd"
        source = cls.root / "fixture.c"
        source.write_text(r'''
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

int main(int argc, char **argv) {
    int listener = 3;
    if (argc == 2) {
        struct sockaddr_un address = {.sun_family = AF_UNIX};
        if (strlen(argv[1]) >= sizeof(address.sun_path)) return 2;
        strcpy(address.sun_path, argv[1]);
        listener = socket(AF_UNIX, SOCK_STREAM, 0);
        if (listener < 0 || bind(listener, (struct sockaddr *)&address, sizeof(address)) < 0 ||
            chmod(argv[1], 0660) < 0 || listen(listener, 8) < 0) return 3;
    }
    signal(SIGPIPE, SIG_IGN);
    puts("ready");
    fflush(stdout);
    for (;;) {
        int client = accept(listener, NULL, NULL);
        if (client < 0) return 4;
        char request[4096];
        const char body[] = "{\"peerFixture\":true}";
        if (read(client, request, sizeof(request)) > 0) {
            dprintf(client, "HTTP/1.1 200 OK\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
                    sizeof(body) - 1, body);
        }
        close(client);
    }
}
''')
        subprocess.run(("cc", "-O2", "-o", str(cls.dockerd), str(source)), check=True, capture_output=True, timeout=15)
        cls.dockerd.chmod(0o755)

    def args(self, path, mode, unit, service):
        return types.SimpleNamespace(docker_socket=str(path), docker_socket_activation=mode,
                                     docker_socket_unit=unit, docker_service_unit=service,
                                     docker_socket_owner="root", docker_socket_group="root",
                                     docker_socket_mode="0660", dockerd=str(self.dockerd))

    def test_direct_daemon_checks_kernel_peer_executable_and_socket_custody(self):
        path = self.root / "direct.sock"
        with subprocess.Popen((str(self.dockerd), str(path)), stdout=subprocess.PIPE) as proc:
            try:
                self.assertTrue(select.select([proc.stdout], [], [], 5)[0])
                self.assertEqual(proc.stdout.readline(), b"ready\n")
                args = self.args(path, "daemon", "fixture.service", "fixture.service")
                reader = P["Reader"]()
                docker = P["Docker"](reader, args, None)
                self.assertEqual(docker.get("/info"), {"peerFixture": True})
                self.assertEqual(docker.proof["pid"], proc.pid)
                self.assertEqual(docker.profile["dockerdExecutable"], {"path": str(self.dockerd)})
                self.assertEqual(reader.verify()[str(self.dockerd)], P["digest"](self.dockerd.read_bytes()))
                self.assertEqual(docker.profile["dockerSocketOwnership"]["mode"], "0660")
                args.docker_socket_mode = "0600"
                with self.assertRaisesRegex(P["Held"], "^DOCKER_SOCKET_CUSTODY_UNPROVEN$"):
                    P["Docker"](P["Reader"](), args, None)
                args.docker_socket_mode = "0660"
                args.dockerd = sys.executable
                with self.assertRaisesRegex(P["Held"], "^DOCKER_EXECUTABLE_UNPROVEN$"):
                    P["Docker"](P["Reader"](), args, None).get("/info")
            finally:
                proc.terminate()

    def test_systemd_activation_requires_active_unit_and_owned_listener(self):
        prefix = "ouf-p-peer-" + uuid.uuid4().hex[:10]
        socket_unit, service = prefix + ".socket", prefix + ".service"
        inactive = prefix + "-inactive.socket"
        path = self.root / "activated.sock"
        def systemctl(*args, check=True):
            return subprocess.run(("systemctl", *args), capture_output=True, check=check, timeout=12)
        units = Path("/run/systemd/system")
        def cleanup():
            systemctl("stop", socket_unit, service, inactive, check=False)
            for name in (socket_unit, service, inactive):
                (units / name).unlink(missing_ok=True)
            systemctl("daemon-reload")
        self.addCleanup(cleanup)
        socket_definition = f"[Socket]\nListenStream={path}\nSocketUser=root\nSocketGroup=root\nSocketMode=0660\n"
        (units / socket_unit).write_text(socket_definition)
        (units / inactive).write_text(socket_definition + f"Service={service}\n")
        (units / service).write_text(f"[Service]\nType=exec\nExecStart={self.dockerd} -H fd://\n")
        systemctl("daemon-reload")
        systemctl("start", socket_unit, service)
        args = self.args(path, "systemd-socket", socket_unit, service)
        docker = P["Docker"](P["Reader"](), args, "/usr/bin/systemctl")
        self.assertEqual(docker.get("/info"), {"peerFixture": True})
        self.assertGreater(docker.proof["pid"], 1)
        self.assertNotEqual(docker.proof["listenerInode"], path.stat().st_ino)
        args.docker_socket_unit = inactive
        with self.assertRaisesRegex(P["Held"], "^DOCKER_SOCKET_UNIT_UNPROVEN$"):
            P["Docker"](P["Reader"](), args, "/usr/bin/systemctl").get("/info")
