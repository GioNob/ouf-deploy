"""B1 contract and opt-in Linux root fixture; never a VPS/Docker qualification."""
import ast
from contextlib import ExitStack, redirect_stdout
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


C = module(ROOT / "scripts/install-semantic-provider-b1.py", "b1_contract")
NATIVE = os.environ.get("OUF_B1_INSTALL_NATIVE") == "1"
if NATIVE and (sys.platform != "linux" or os.geteuid() != 0 or os.getegid() != 0):
    raise RuntimeError("OUF_B1_INSTALL_NATIVE requires native Linux root:root; refusing to skip")


class Contract(unittest.TestCase):
    def test_wrapper_exact_bytes_and_p_regex(self):
        wrapper = C.proposed_wrapper({"pythonPath": "/usr/bin/python3.13"}, PurePosixPath("/etc/b1"))
        raw = wrapper["text"].encode()
        import base64
        self.assertEqual(base64.b64decode(wrapper["base64"]), raw)
        self.assertEqual((wrapper["byteLength"], wrapper["sha256"]), (len(raw), C.sha(raw)))
        tree = ast.parse((ROOT / "scripts/prepare-semantic-provider-installation.py").read_text())
        runtime = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "runtime")
        regex = next(node.args[0].value for node in ast.walk(runtime)
                     if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                     and node.func.attr == "fullmatch" and isinstance(node.args[0], ast.Constant))
        self.assertIsNotNone(re.fullmatch(regex, raw))
        self.assertEqual(C.WRAPPER.pattern, regex)

    def test_delivery_closure_closes_all_nonstdlib_imports(self):
        files = set(C.DEPENDENCIES)
        self.assertEqual(len(files), len(C.DEPENDENCIES))
        for name in files:
            tree = ast.parse((ROOT / name).read_bytes())
            for node in ast.walk(tree):
                imported = []
                if isinstance(node, ast.Import):
                    imported = [item.name for item in node.names]
                elif isinstance(node, ast.ImportFrom):
                    imported = [node.module or ""]
                    if node.module in ("tools.semantic_b1_acceptance", "tools.semantic_b1b2_authority"):
                        imported = [node.module + "." + item.name for item in node.names]
                for item in imported:
                    if item.split(".")[0] in sys.stdlib_module_names:
                        continue
                    candidates = [item.replace(".", "/") + ".py",
                                  "tools/semantic_transaction_profiles/" + item + ".py",
                                  "tools/semantic_frame_compiler/" + item + ".py",
                                  C.COHORT + "/" + item.replace(".", "/") + ".py"]
                    self.assertTrue(any(path in files for path in candidates), (name, item))

    def test_closure_pins_are_exact_git_blobs(self):
        for name, pin in C.CLOSURE.items():
            raw = subprocess.check_output(["git", "show", C.CLOSURE_COMMIT + ":" + name], cwd=ROOT)
            self.assertEqual(C.sha(raw), pin)

    def test_launcher_pins_and_paths_match_delivery(self):
        launcher = (ROOT / "scripts/deliver-semantic-provider-b1-install.sh").read_text()
        # Exactly two states: unpinned (both placeholders) or pinned to the current controller.
        placeholders = ("__PIN_COMMIT__" in launcher, "__PIN_CONTROLLER_SHA256__" in launcher)
        self.assertIn(placeholders, ((True, True), (False, False)))
        if not any(placeholders):
            self.assertNotIn("__PIN_", launcher)
            self.assertEqual(len(re.findall(r"^commit='[0-9a-f]{40}'$", launcher, re.M)), 1)
            pins = re.findall(r"^controller_sha='([0-9a-f]{64})'$", launcher, re.M)
            controller = subprocess.check_output(
                ["git", "show", "HEAD:scripts/install-semantic-provider-b1.py"], cwd=ROOT)
            self.assertEqual(pins, [C.sha(controller)])
        rows = re.findall(r"^fetch (\S+) (\S+) (\S+)$", launcher, re.M)
        self.assertEqual({row[0] for row in rows}, set(C.DEPENDENCIES))
        for name, pin, commit in rows:
            if name == "scripts/install-semantic-provider-b1.py":
                self.assertEqual(pin, '"$controller_sha"')
            elif name == "scripts/prepare-semantic-provider-installation.py":
                self.assertEqual(pin, C.sha((ROOT / name).read_bytes().replace(b"\r\n", b"\n")))
            else:
                revision = C.CLOSURE_COMMIT if name in C.CLOSURE else "HEAD"
                self.assertEqual(pin, C.sha(subprocess.check_output(["git", "show", revision + ":" + name], cwd=ROOT)))
            self.assertEqual(commit, '"$closure_commit"' if name in C.CLOSURE else '"$commit"')

    def test_p_observation_has_no_publication_mode(self):
        tree = ast.parse((ROOT / "scripts/prepare-semantic-provider-installation.py").read_text())
        fn = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "observe_profile")
        names = {node.id for node in ast.walk(fn) if isinstance(node, ast.Name)}
        self.assertNotIn("output_plan", names)
        self.assertNotIn("publish", names)

    def test_cli_no_implicit_input_or_path_defaults(self):
        argv = ["--plan", "--docker-socket-activation", "daemon"]
        names = (*C.P_ARGUMENTS, "p-profile-sha256", "acceptance-manifest", "acceptance-manifest-sha256",
                 "acceptance-signature", "acceptance-signature-sha256", "b1b2-trust-policy",
                 "b1b2-trust-policy-sha256", "openssl", "openssl-sha256", "openssl-version",
                 "arming-issuer-ref", "bundle-parent", "output-root", "output-name")
        for name in names:
            argv += ["--" + name, "a" * 64 if name.endswith("sha256") else "/explicit"]
        self.assertTrue(C.arguments(argv).plan)
        for name in names:
            changed = argv.copy()
            at = changed.index("--" + name)
            del changed[at:at+2]
            with self.subTest(missing=name), patch("sys.stderr", new=io.StringIO()), self.assertRaises(SystemExit):
                C.arguments(changed)


@unittest.skipUnless(NATIVE, "set OUF_B1_INSTALL_NATIVE=1 under native Linux root")
class Native(unittest.TestCase):
    """Real custody, signatures, fsync, flock, CAS and real v5 child processes.

    P's Docker/peer/systemd/network/nft read boundaries are synthetic. The full
    observe_profile composition, A reader, P.runtime and switch are unchanged.
    The fixture never creates a container or pretends to be a real Engine test.
    """
    def setUp(self):
        self.addCleanup(os.umask, os.umask(0o077))
        work = tempfile.TemporaryDirectory(prefix="ouf-b1-install-", dir="/run")
        self.addCleanup(work.cleanup)
        self.root = Path(work.name)
        self.delivery = self.root / "delivery"
        for name in C.DEPENDENCIES:
            self.write(self.delivery / name, (ROOT / name).read_bytes())
        self.c = module(self.delivery / "scripts/install-semantic-provider-b1.py", "b1_native_controller")
        self.d = self.c.dependencies()
        self.p, self.a, self.b = self.d.P, self.d.A, self.d.B
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.commands = {}
        for name in ("ip", "nft", "systemctl", "nsenter", "unshare", "mount", "umount", "docker", "openssl", "dockerd"):
            path = self.root / "bin" / name
            self.write(path, b"#!/bin/sh\nexit 0\n", 0o755)
            self.commands[name] = str(path)
        self.python = Path(sys.executable).resolve()
        self.openssl = Path("/usr/bin/openssl").resolve()
        self.runc = self.root / "runc"
        self.write(self.runc, b'#!/bin/sh\n[ "$1" = "--version" ] && exit 0\nexit 91\n', 0o755)
        self.wrapper = self.root / "wrapper"
        self.old_source = self.root / "v4.py"
        self.write(self.old_source, b"# unchanged fixture v4 source\n")
        self.driver, self.broker = self.root / "driver.py", self.root / "broker.py"
        self.write(self.driver, b"# fake driver\n")
        self.write(self.broker, b"# fake broker\n")
        self.registry = self.root / "registry"
        self.registry.mkdir(mode=0o700)
        self.old_config = {
            "schema": "ouf.semantic-docker-runtime-adapter.v4", "sourceHash": self.pin(self.old_source)["sha256"],
            **{key: value for prefix, path in (("runtime", self.runc), ("python", self.python),
                                             ("driver", self.driver), ("admission", self.broker))
               for key, value in ((prefix + "Path", str(path)), (prefix + "Sha256", self.pin(path)["sha256"]))},
            "registryRoot": str(self.registry), "runtimeStateRoot": str(self.root / "runtime-state"), "candidates": {}}
        self.old_config_path = self.root / "old-config.json"
        self.write(self.old_config_path, self.old_config)
        self.old_wrapper = (f'#!/bin/sh\nexec {self.python} -I -B {self.old_source} '
                            f'--configuration {self.old_config_path} "$@"\n').encode()
        self.write(self.wrapper, self.old_wrapper, 0o755)
        self.lock = self.root / "guard.lock"
        self.write(self.lock, b"")
        self.nft = self.root / "nft-sets.json"
        self.write(self.nft, {"sets": []})
        self.guard_service, self.drop_in = self.root / "guard.service", self.root / "docker.conf"
        self.write(self.guard_service, b"fixture guard\n")
        self.write(self.drop_in, b"fixture drop-in\n")
        self.key = self.root / "PRIVATE-EPHEMERAL-TEST-KEY.pem"
        self.native("genpkey", "-algorithm", "Ed25519", "-out", str(self.key))
        self.key.chmod(0o600)
        public = self.native("pkey", "-in", str(self.key), "-pubout", "-outform", "DER")[12:].hex()
        self.authority_path = self.root / "authority.json"
        self.base_policy = self.root / "base-policy.json"
        self.write(self.base_policy, {"fixture": "base-policy"})
        authority = {"authorities": {"installationRef": "fixture", "entityRef": "fixture-entity",
                                      "approvalIssuerRef": "fixture-issuer"},
                     "keyBindings": {"installer": {"path": str(self.key), "sha256": "a" * 64},
                                     "attestor": {"path": str(self.root / "UNOPENED-ATTESTOR"), "sha256": "b" * 64}}}
        self.write(self.authority_path, authority)
        self.policy_path = self.root / "b1b2-policy.json"
        self.policy = {"schema": self.a.POLICY_SCHEMA, "installationRef": "fixture", "entityRef": "fixture-entity",
                       "basePolicy": self.pin(self.base_policy), "authorityProfile": self.pin(self.authority_path),
                       "keys": [{"keyRef": "fixture-key", "issuerRef": "fixture-issuer",
                                 "roles": ["ARTIFACT_ACCEPTANCE", "RUNTIME_ARMING"], "publicKey": public,
                                 "notBefore": 0, "expiresAt": 4102444800, "state": "ACTIVE"}]}
        self.write(self.policy_path, self.policy)
        self.docs = {}
        for index, role in enumerate(("adapter", "southbound", "semantic"), 1):
            endpoint = {"NetworkID": "n" * 64 if role == "semantic" else "", "IPAMConfig": {"IPv4Address": f"10.0.0.{index}"},
                        "IPAddress": f"10.0.0.{index}" if role == "semantic" else "", "EndpointID": "",
                        "MacAddress": f"02:00:00:00:00:0{index}", "Aliases": [role], "DNSNames": [role]}
            doc = {"Id": str(index) * 64, "Name": "/" + role, "Image": "sha256:" + str(index + 3) * 64,
                   "State": {"Running": role == "semantic", "Pid": 42 if role == "semantic" else 0,
                             "Status": "running" if role == "semantic" else "created",
                             "StartedAt": "2026-01-01T00:00:00Z" if role == "semantic" else "0001-01-01T00:00:00Z"},
                   "RestartCount": 0, "Config": {}, "HostConfig": {"Runtime": "fixture-runtime"},
                   "Mounts": [], "NetworkSettings": {"Networks": {"fixture-net": endpoint}}}
            if role == "adapter":
                doc["Config"]["MacAddress"] = endpoint["MacAddress"]
            self.docs[role] = doc
        self.a_root = self.root / "a2"
        self.a_root.mkdir(mode=0o700)
        self.recreation = self.root / "recreation.json"
        self.write(self.recreation, {"fixture": "A2 lineage receipt"})
        self.successors = {"containers": [
            {"containerId": doc["Id"], "image": doc["Image"], "name": doc["Name"], "status": "created",
             "runtime": "fixture-runtime", "transaction": str(index) * 32, "dockerFrameSha256": self.p.frame(doc)}
            for index, doc in enumerate((self.docs["adapter"], self.docs["southbound"]), 1)],
            "southboundCertificate": {"sni": "southbound", "configuredDerMatches": True},
            "transactions": {self.docs[role]["Id"]: str(index) * 32 for index, role in enumerate(("adapter", "southbound"), 1)},
            "lineage": {"recreation": self.pin(self.recreation)}}
        peer = {"containerId": self.docs["semantic"]["Id"], "generation": {"pid": 42},
                "startedAt": self.docs["semantic"]["State"]["StartedAt"], "dockerFrameSha256": self.p.frame(self.docs["semantic"])}
        self.write(self.a_root / "successors.json", self.successors)
        self.write(self.a_root / "semantic-peer.json", peer)
        body = {"schema": "ouf.semantic-provider-preparation-a.manifest.v1", "directory": {"path": str(self.a_root)},
                "successors": self.successors, "semanticPeer": peer,
                "filesCreated": [self.pin(self.a_root / name) for name in ("successors.json", "semantic-peer.json")]}
        envelope = {"manifest": body, "planSha256": "c" * 64}
        self.write(self.a_root / "manifest.json", envelope)
        self.write(self.a_root / "result.json", envelope | {"status": "SEMANTIC_PROVIDER_PREPARATION_A_STAGED", "replayAllowed": False})
        self.output = self.root / "snapshots"
        self.output.mkdir(mode=0o700)
        self.installations = self.root / "installations"
        self.args = types.SimpleNamespace(**{name.replace("-", "_"): "/explicit" for name in C.P_ARGUMENTS},
            revise_from_sha256=None, plan=True, apply=False, plan_sha256=None,
            docker_socket_activation="daemon", p_profile_sha256="a" * 64,
            acceptance_manifest=str(self.root / "acceptance.json"), acceptance_manifest_sha256="a" * 64,
            acceptance_signature=str(self.root / "acceptance-signature.json"), acceptance_signature_sha256="a" * 64,
            b1b2_trust_policy=str(self.policy_path), b1b2_trust_policy_sha256=self.pin(self.policy_path)["sha256"],
            openssl=str(self.openssl), openssl_sha256=self.pin(self.openssl)["sha256"],
            openssl_version=self.native("version").decode().split()[1], arming_issuer_ref="fixture-issuer",
            bundle_parent=str(self.root / "bundles"), output_root=str(self.output), output_name="b1")
        vars(self.args).update(installation_ref="fixture", installation_root=str(self.installations),
            a_root=str(self.a_root), a_plan_sha256="c" * 64, authority_profile=str(self.authority_path),
            authority_sha256=self.pin(self.authority_path)["sha256"], trust_policy=str(self.base_policy),
            trust_policy_sha256=self.pin(self.base_policy)["sha256"], guard_service_unit="fixture-guard.service",
            generation_receipt_sha256="d" * 64)
        self.configure_p_boundaries()
        self.profile_path = self.installations / "fixture/semantic-provider.json"
        profile = self.p.observe_profile(self.args)["profile"]
        self.write(self.profile_path, profile)
        self.args.p_profile_sha256 = self.pin(self.profile_path)["sha256"]
        prep = {"root": str(self.a_root), "planSha256": self.args.a_plan_sha256,
                "files": {field: self.pin(self.a_root / name) for field, name in
                          (("manifest", "manifest.json"), ("result", "result.json"),
                           ("semanticPeer", "semantic-peer.json"), ("successors", "successors.json"))}}
        dummy = {"path": str(self.root / "public-synthetic-rootfs-evidence.json"), "sha256": "e" * 64}
        roles = {role: {"containerId": self.docs[role]["Id"], "imageId": self.docs[role]["Image"],
                       "recipe": {part: dummy for part in self.b.RECIPE_PARTS},
                       "rootfs": {**{field: dummy for field in ("offlineImageReceipt", "offlineDockerReceipt", "comparison")},
                                  "effectiveSeal": {"schema": self.b.SEAL_SCHEMA, "sha256": "d" * 64, "entries": 1, "bytes": 1}}}
                 for role in ("adapter", "southbound")}
        self.manifest = {"schema": self.b.SCHEMA, "installationRef": "fixture", "entityRef": "fixture-entity",
                         "generation": 1, "profile": self.pin(self.profile_path), "preparationA": prep,
                         "creation": {"evidence": "PREPARATION_A2", "roles": {role: {"transactionRef": str(i) * 32}
                                      for i, role in enumerate(("adapter", "southbound"), 1)},
                                      "recreation": self.pin(self.recreation), "declaredGaps": []},
                         "roles": roles, "softwareClosure": {"sourceCommit": C.CLOSURE_COMMIT, "files": C.CLOSURE},
                         "trustPolicy": self.pin(self.policy_path), "startAuthorized": False, "leaseAuthorized": False, "issuedAt": 1}
        self.sign_acceptance()

    def configure_p_boundaries(self):
        owner = {"nftPath": self.commands["nft"], "nftSha256": self.pin(Path(self.commands["nft"]))["sha256"],
                 "kernel": {"tableName": "guard"}}
        templates = {role: {"commands": self.commands, "commandHashes": {name: self.pin(Path(path))["sha256"]
                          for name, path in self.commands.items()}, "candidate": {"tableName": role,
                          "networkBindings": [{"bridge": "br-fixture", "ipv4": f"10.0.0.{i}", "mac": f"02:00:00:00:00:0{i}"}]}}
                     for i, role in enumerate(("adapter", "southbound"), 1)}
        fixture = self
        class Docker:
            def __init__(self, reader, args, systemctl):
                self.path = fixture.root / "docker.sock"
                self.proof = {"fixturePeerGeneration": 7}
                self.profile = {"fixtureDocker": True}

            def get(self, resource):
                fixture.assertEqual(resource, "/info")
                return {"Runtimes": {"fixture-runtime": {"path": str(fixture.wrapper)}}, "DockerRootDir": str(fixture.root / "docker")}

            def inspect(self, cid):
                return copy.deepcopy(next(doc for doc in fixture.docs.values() if doc["Id"] == cid))

        def guard(reader, args):
            reader.read(self.lock, minimum=0)
            return owner, {}, {"snapshotRoot": str(self.output), "lock": str(self.lock)}

        def units(reader, *args):
            reader.read(self.guard_service)
            reader.read(self.drop_in)
            return {"guardService": str(self.guard_service), "dockerDropIn": str(self.drop_in)}

        def empty(reader, *args):
            self.p.require(reader.document(self.nft)["sets"] == [], "NFT_EGRESS_SETS_NOT_EMPTY")

        replacements = {"Docker": Docker, "boot_guard": guard, "guard_units": units,
                        "historical_templates": lambda *_: templates, "verify_peer": lambda *_: None,
                        "observed_networks": lambda *_: {"fixture-net": ("n" * 64, {"bridge": "br-fixture", "internal": True, "subnets": ["10.0.0.0/24"]})},
                        "mounted_configuration": lambda *_: {"apisix": {"ssl": {"listen": [{}]}}},
                        "stable_transport": lambda *_: ({"southbound": 10443, "adapter": 9443}, {}), "empty_nft": empty}
        for name, value in replacements.items():
            self.stack.enter_context(patch.object(self.p, name, value))
        self.stack.enter_context(patch.object(self.p.shutil, "which", side_effect=lambda name, **_: self.commands[name]))

    def write(self, path, value, mode=0o600):
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(value if isinstance(value, bytes) else C.encoded(value) + b"\n")
        path.chmod(mode)

    def pin(self, path):
        return {"path": str(path), "sha256": C.sha(path.read_bytes())}

    def native(self, *args):
        return subprocess.run([str(self.openssl), *args], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, check=True, timeout=5,
                              env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "OPENSSL_CONF": "/dev/null"}).stdout

    def sign_acceptance(self):
        raw = self.b.build_acceptance(**self.manifest)
        header = {"schema": self.a.SIGNATURE_SCHEMA, "algorithm": "Ed25519", "keyRef": "fixture-key",
                  "role": "ARTIFACT_ACCEPTANCE", "issuerRef": "fixture-issuer", "installationRef": "fixture",
                  "entityRef": "fixture-entity", "payloadHash": C.sha(raw)}
        frame = self.root / "PUBLIC-signing-frame"
        self.write(frame, self.a.signing_bytes(raw, header))
        signature = self.native("pkeyutl", "-sign", "-rawin", "-inkey", str(self.key), "-in", str(frame)).hex()
        self.write(Path(self.args.acceptance_manifest), raw)
        self.write(Path(self.args.acceptance_signature), header | {"signature": signature})
        self.args.acceptance_manifest_sha256 = C.sha(raw)
        self.args.acceptance_signature_sha256 = self.pin(Path(self.args.acceptance_signature))["sha256"]

    def proposal(self):
        return self.c.plan(self.args, self.d)

    def apply(self, proposal=None):
        proposal = proposal or self.proposal()
        self.args.plan_sha256 = proposal["planSha256"]
        report = {"schema": C.SCHEMA, "status": "HELD", "switchOutcome": "UNCHANGED", **C.COUNTERS}
        self.c.apply(self.args, self.d, proposal, report)
        return report

    def run_controller(self, mode, digest=None):
        argv = [mode, "--docker-socket-activation", "daemon"]
        names = (*C.P_ARGUMENTS, "p-profile-sha256", "acceptance-manifest", "acceptance-manifest-sha256",
                 "acceptance-signature", "acceptance-signature-sha256", "b1b2-trust-policy",
                 "b1b2-trust-policy-sha256", "openssl", "openssl-sha256", "openssl-version",
                 "arming-issuer-ref", "bundle-parent", "output-root", "output-name")
        for name in names:
            argv += ["--" + name, getattr(self.args, name.replace("-", "_"))]
        if digest is not None:
            argv += ["--plan-sha256", digest]
        output = io.StringIO()
        with patch.object(self.c, "dependencies", return_value=self.d), redirect_stdout(output):
            code = self.c.main(argv)
        return code, json.loads(output.getvalue())

    def snapshot(self):
        return {str(p.relative_to(self.root)): (p.lstat().st_mode, p.lstat().st_ino, p.lstat().st_size,
                    p.lstat().st_mtime_ns, p.lstat().st_ctime_ns, C.sha(p.read_bytes()) if p.is_file() else None)
                for p in self.root.rglob("*")}

    def test_plan_deterministic_no_persistent_writes_or_private_key_reads(self):
        before = self.snapshot()
        temporary_before = set(Path(tempfile.gettempdir()).glob("ouf-b1b2-verification-*"))
        opened = []
        original = os.open
        def checked(path, flags, *args, **kwargs):
            self.assertNotEqual(str(path), str(self.key))
            opened.append(str(path))
            self.assertFalse(flags & (os.O_CREAT | os.O_TRUNC | os.O_WRONLY | os.O_RDWR)
                             and str(path).startswith(str(self.root)))
            return original(path, flags, *args, **kwargs)
        import fcntl
        with patch.object(os, "open", side_effect=checked), patch.object(fcntl, "flock", side_effect=AssertionError("plan acquired lock")):
            first, second = self.proposal(), self.proposal()
        self.assertEqual(first, second)
        self.assertEqual(before, self.snapshot())
        self.assertEqual(temporary_before, set(Path(tempfile.gettempdir()).glob("ouf-b1b2-verification-*")))
        self.assertIn(str(self.authority_path), opened)
        self.assertFalse((self.output / "b1").exists())

    def test_real_native_apply_p_identical_and_create_denied_without_arming(self):
        p_before = self.profile_path.read_bytes()
        frames_before = copy.deepcopy(self.docs)
        opened = []
        original = os.open
        def checked(path, flags, *args, **kwargs):
            self.assertNotEqual(str(path), str(self.key))
            opened.append(str(path))
            return original(path, flags, *args, **kwargs)
        with patch.object(os, "open", side_effect=checked):
            plan_code, cli_plan = self.run_controller("--plan")
            self.assertEqual(plan_code, 0, cli_plan)
            proposal = self.proposal()
            self.assertEqual(cli_plan["planSha256"], proposal["planSha256"])
            code, report = self.run_controller("--apply", proposal["planSha256"])
        self.assertEqual(code, 0, report)
        self.assertEqual(report["status"], "SEMANTIC_PROVIDER_B1_INSTALLED_INACTIVE")
        root = self.output / "b1"
        actual, raw = self.d.V.load_configuration(root / "runtime-configuration.json")
        self.assertEqual(actual, proposal["configuration"])
        self.assertEqual(set(actual), self.d.V.CONFIG_FIELDS)
        self.assertTrue(all(row == {"phase": "INACTIVE", "bundleParents": [self.args.bundle_parent]}
                            for row in actual["candidates"].values()))
        self.assertEqual(list((root / "arming").iterdir()), [])
        self.assertEqual(p_before, self.profile_path.read_bytes())
        self.assertEqual(p_before, self.p.observe_profile(self.args)["profileBytes"])
        self.assertEqual(frames_before, self.docs)
        self.assertEqual((root / "switch/prior-runtime-wrapper.sh").read_bytes(), self.old_wrapper)
        self.assertEqual(json.loads((root / "result.json").read_bytes()), report)
        for key, value in C.COUNTERS.items():
            self.assertEqual(report[key], value)
        state_root = self.root / "runtime-state/moby"
        denied = subprocess.run([str(self.wrapper), "--root", str(state_root), "create", "--bundle",
                                 str(self.root / "bundles" / self.docs["adapter"]["Id"]), self.docs["adapter"]["Id"]],
                                capture_output=True, env=C.ENV, timeout=12)
        self.assertNotEqual(denied.returncode, 0)
        self.assertIn(b"RUNTIME_PHASE_INACTIVE", denied.stderr)
        for cid in actual["candidates"]:
            denied = subprocess.run([str(self.wrapper), "--root", str(state_root), "start", cid],
                                    capture_output=True, env=C.ENV, timeout=12)
            self.assertNotEqual(denied.returncode, 0)
            self.assertIn(b"RUNTIME_PHASE_INACTIVE", denied.stderr)
        self.assertEqual(list(self.registry.iterdir()), [])
        self.assertFalse(state_root.exists())
        self.assertEqual(list((root / "arming").iterdir()), [])

    def test_replica_and_real_loader_accept_and_reject_same_shapes(self):
        config = self.proposal()["configuration"]
        config_path = self.root / "replica-test.json"
        Path(config["armingRoot"]).mkdir(mode=0o700, parents=True)
        mutations = [lambda c: None, lambda c: c.update(extra=True), lambda c: c.pop("runtimeSha256"),
                     lambda c: c.update(armingRoot="relative"), lambda c: c.update(sourceHash="bad"),
                     lambda c: c["opensslBinding"].update(version="latest"),
                     lambda c: c.update(armingIssuerRef="bad issuer"),
                     lambda c: c["acceptance"].update(extra=True),
                     lambda c: c["candidates"][self.docs["adapter"]["Id"]].update(phase="ACTIVE"),
                     lambda c: c["candidates"].pop(self.docs["adapter"]["Id"]),
                     lambda c: c["candidates"][self.docs["adapter"]["Id"]].update(bundleParents=[])]
        for mutate in mutations:
            value = copy.deepcopy(config)
            mutate(value)
            self.write(config_path, value)
            outcomes = []
            for call in (lambda: self.c.syntax_configuration(value, self.d.V),
                         lambda: self.d.V.load_configuration(config_path)):
                try:
                    call()
                    outcomes.append(True)
                except RuntimeError:
                    outcomes.append(False)
            self.assertEqual(outcomes[0], outcomes[1])

    def test_profile_drift_held_before_output(self):
        self.write(self.profile_path, {"drift": True})
        with self.assertRaisesRegex(self.c.Held, "B1_PROFILE_DRIFT"):
            self.proposal()
        self.assertFalse((self.output / "b1").exists())

    def test_reobserved_profile_drift_held(self):
        roles = self.p.role_profiles
        def changed(*args):
            value = roles(*args)
            value["adapter"]["containerName"] = "changed"
            return value
        with patch.object(self.p, "role_profiles", side_effect=changed), self.assertRaisesRegex(self.c.Held, "B1_PROFILE_DRIFT"):
            self.proposal()

    def test_acceptance_signature_and_mandate_drift_before_claim(self):
        signature = Path(self.args.acceptance_signature)
        raw = signature.read_bytes()
        self.write(signature, b"changed")
        with self.assertRaises(RuntimeError):
            self.proposal()
        self.assertFalse((self.output / "b1").exists())
        self.write(signature, raw)
        self.policy["keys"][0]["state"] = "REVOKED"
        self.write(self.policy_path, self.policy)
        self.args.b1b2_trust_policy_sha256 = self.pin(self.policy_path)["sha256"]
        self.manifest["trustPolicy"] = self.pin(self.policy_path)
        self.sign_acceptance()
        with self.assertRaisesRegex(self.a.AuthorityDenied, "ACTIVE_LOCAL_ROLE_MANDATE_REQUIRED"):
            self.proposal()
        self.assertFalse((self.output / "b1").exists())

    def test_closure_and_current_wrapper_drift_prevent_apply_writes(self):
        proposal = self.proposal()
        self.args.plan_sha256 = proposal["planSha256"]
        self.write(self.wrapper, self.old_wrapper.replace(b" -I -B ", b" -I  -B "), 0o755)
        with self.assertRaises(RuntimeError):
            self.proposal()
        self.assertFalse((self.output / "b1").exists())
        self.write(self.wrapper, self.old_wrapper, 0o755)
        self.write(self.delivery / C.VERIFIER, b"# closure drift\n")
        with self.assertRaises(RuntimeError):
            self.proposal()
        self.assertFalse((self.output / "b1").exists())

    def test_changed_digest_has_no_writes(self):
        proposal = self.proposal()
        self.args.plan_sha256 = "0" * 64
        with self.assertRaisesRegex(self.c.Held, "B1_PLAN_DIGEST_CHANGED"):
            self.c.apply(self.args, self.d, proposal, {})
        self.assertFalse((self.output / "b1").exists())

    def test_smoke_failure_does_not_call_switch(self):
        self.write(self.runc, b"#!/bin/sh\nexit 93\n", 0o755)
        self.old_config["runtimeSha256"] = self.pin(self.runc)["sha256"]
        self.write(self.old_config_path, self.old_config)
        proposal = self.proposal()
        with patch.object(self.d.S, "switch_existing_wrapper", side_effect=AssertionError("unexpected switch")):
            with self.assertRaisesRegex(self.c.Held, "B1_SMOKE_FAILED"):
                self.apply(proposal)
        self.assertEqual(self.wrapper.read_bytes(), self.old_wrapper)
        self.assertEqual(list((self.output / "b1/switch").iterdir()), [])

    def test_before_rename_drift_keeps_wrapper_and_unchanged_diagnosis(self):
        original = self.c.observation
        phases = []
        def observe(*args, **kwargs):
            phases.append(kwargs.get("phase"))
            if kwargs.get("phase") == "BEFORE_RENAME":
                self.write(self.nft, {"sets": ["drift"]})
            return original(*args, **kwargs)
        with patch.object(self.c, "observation", side_effect=observe), self.assertRaises(ValueError) as raised:
            self.apply()
        diagnosis = raised.exception.diagnosis
        self.assertEqual(diagnosis["switchOutcome"], "UNCHANGED")
        self.assertTrue(diagnosis["doNotRerunApply"])
        self.assertEqual(self.wrapper.read_bytes(), self.old_wrapper)
        self.assertEqual((self.output / "b1/switch/prior-runtime-wrapper.sh").read_bytes(), self.old_wrapper)
        self.assertIn("BEFORE_CLAIM", phases)
        self.assertIn("BEFORE_RENAME", phases)

    def test_checkpoint_rejects_arming_or_installed_closure_drift_before_claim(self):
        original = self.c.observation
        def observe(*args, **kwargs):
            if kwargs.get("phase") == "BEFORE_CLAIM":
                self.write(self.output / "b1/arming/1.json", {"foreign": "B2"})
            return original(*args, **kwargs)
        with patch.object(self.c, "observation", side_effect=observe), self.assertRaises(ValueError) as raised:
            self.apply()
        self.assertEqual(raised.exception.diagnosis["switchOutcome"], "UNCHANGED")
        self.assertFalse((self.output / "b1/switch/runtime-switch-claim.json").exists())


if __name__ == "__main__":
    unittest.main()
