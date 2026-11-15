"""Opt-in offline Docker cohort: real Engine, runc, broker, epochs and operate.

Only the WAITING systemd observer, empty nft observer and quiescer are fixture
programs. They never publish ACTIVE or grant a lease. A private Docker daemon
and locally imported rootfs avoid registry access and host Docker changes.
"""
import ast
import copy
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_semantic_provider_operation_issuance as F
from tools.semantic_provider_r3 import operate as O
from tools.semantic_provider_admission_v2 import broker_v2 as B

ROOT, A, C = F.ROOT, F.A, F.C
NATIVE = os.environ.get("OUF_R3_COHORT_NATIVE") == "1"
if NATIVE and (sys.platform != "linux" or os.geteuid() != 0 or os.getegid() != 0):
    raise RuntimeError("OUF_R3_COHORT_NATIVE requires Linux root:root; refusing to skip")

CAPTURE = r'''
import json,pathlib,subprocess,sys
args=sys.argv[1:]
if 'create' not in args:
    raise SystemExit(subprocess.run([RUNC,*args]).returncode)
cid=args[-1]; option='--bundle' if '--bundle' in args else '-b'
bundle=pathlib.Path(args[args.index(option)+1]).resolve()
oci=json.loads((bundle/'config.json').read_bytes())
if not pathlib.Path(oci['root']['path']).is_absolute():
    oci['root']['path']=str((bundle/oci['root']['path']).resolve())
for ns in oci['linux']['namespaces']:
    if ns.get('type')=='network' and ns.get('path'):
        ns['path']=str(pathlib.Path(ns['path']).resolve())
path=pathlib.Path(BASE)/('capture-'+cid+'.json')
path.write_text(json.dumps({'oci':oci,'bundle':str(bundle),'root':args[args.index('--root')+1]},
                          sort_keys=True,separators=(',',':')))
path.chmod(0o600)
raise SystemExit(1) # read-only qualification: never create/start an application
'''

SYSTEMCTL = "print('ActiveState=active\\nSubState=running\\nNRestarts=0')\n"
NFT = "print('{\"nftables\":[]}')\n"
QUIESCE = "# Isolated fixture is permanently QUIESCED; no activation implementation.\n"


def collect_codes():
    """Read the real collect's public codes; no assumption about Docker's result."""
    path = ROOT / C.SOURCE_MAP["tools/semantic_provider_peer_bindings.py"]
    tree = ast.parse(path.read_bytes())
    collect = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "collect")
    return {n.args[-1].value for n in ast.walk(collect) if isinstance(n, ast.Call)
            and isinstance(n.func, ast.Name) and n.func.id == "require" and n.args
            and isinstance(n.args[-1], ast.Constant) and type(n.args[-1].value) is str}


class PortableTests(unittest.TestCase):
    def test_fixture_programs_compile_and_collect_codes_are_real(self):
        for source in (CAPTURE, SYSTEMCTL, NFT, QUIESCE):
            compile(source, "<cohort-fixture>", "exec")
        self.assertIn("PEER_MAC_IP_DRIFT", collect_codes())


class CohortFixture(F.NativeTests):
    __unittest_skip__ = False

    def setUp(self):
        F.fixtures.SOURCE_CACHE = {p: (ROOT / p).read_bytes() for p in C.SOURCE_INPUTS}
        super().setUp()
        self.assertTrue(str(self.root).startswith("/var/lib/"))
        self.python = Path(sys.executable).resolve()
        self.wrapper = self.root / "admitted-runtime"
        self.real_runc = Path(shutil.which("runc")).resolve()
        self.docker_binary = Path(shutil.which("docker")).resolve()
        self.socket = "unix://" + str(self.root / "docker.sock")
        self.script(self.wrapper, CAPTURE.replace("RUNC", repr(str(self.real_runc))).replace("BASE", repr(str(self.root))))
        log = (self.root / "dockerd.log").open("wb")
        self.addCleanup(log.close)
        daemon = subprocess.Popen([shutil.which("dockerd"), "--host=" + self.socket,
            "--data-root=" + str(self.root / "docker-data"), "--exec-root=" + str(self.root / "docker-exec"),
            "--pidfile=" + str(self.root / "dockerd.pid"), "--storage-driver=vfs", "--bridge=none",
            "--iptables=false", "--ip6tables=false", "--ip-forward=false", "--ip-masq=false",
            "--add-runtime=ouf-semantic-admitted-v2=" + str(self.wrapper)],
            stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        def stop_daemon():
            daemon.terminate()
            try:
                daemon.wait(timeout=30)
            except subprocess.TimeoutExpired:
                daemon.kill()
                daemon.wait(timeout=5)
        self.addCleanup(stop_daemon)
        end = time.monotonic() + 45
        while True:
            probe = self.engine("info", check=False)
            if probe.returncode == 0:
                break
            self.assertIsNone(daemon.poll(), (self.root / "dockerd.log").read_text())
            self.assertLess(time.monotonic(), end, "isolated dockerd readiness timeout")
            time.sleep(.1)
        print("COHORT_DOCKER_VERSION=" + self.engine("version", "--format", "{{json .}}").stdout.decode(), flush=True)
        self.import_image()
        self.ids = {}
        self.networks = []
        for n in (1, 2):
            name = "cohort" + str(n)
            self.engine("network", "create", "--driver", "bridge", "--internal", "--subnet", f"172.30.{90+n}.0/24",
                        "--opt", "com.docker.network.bridge.name=oufcohort" + str(n), name)
            self.networks.append(name)
        for index, role in enumerate(O.ROLES, 2):
            cid = self.engine("create", "--runtime", "ouf-semantic-admitted-v2", "--read-only", "--restart=no",
                "--network", self.networks[0], "--ip", f"172.30.91.{index}", "--entrypoint", "/sleep",
                "cohort-local:fixture", "300").stdout.decode().strip()
            self.assertRegex(cid, r"^[0-9a-f]{64}$")
            self.ids[role] = cid
            self.engine("network", "connect", "--ip", f"172.30.92.{index}", self.networks[1], cid)
            self.addCleanup(lambda cid=cid: self.engine("rm", "--force", cid, check=False))
            frame = json.loads(self.engine("inspect", cid).stdout)[0]
            self.assertEqual(frame["HostConfig"]["Runtime"], "ouf-semantic-admitted-v2")
            endpoints = frame["NetworkSettings"]["Networks"]
            self.assertEqual(set(endpoints), set(self.networks))
            for n, name in enumerate(self.networks, 91):
                self.assertEqual(endpoints[name]["IPAMConfig"]["IPv4Address"], f"172.30.{n}.{index}")
            # Capture independent full OCI expectations before signing. This
            # runtime intentionally denies create, so no epoch/application runs.
            self.assertNotEqual(self.engine("start", cid, check=False).returncode, 0)
            self.assertTrue((self.root / ("capture-" + cid + ".json")).exists())
        self.publish_runtime()

    def script(self, path, body):
        self.write(Path(path), ("#!" + str(self.python) + "\n" + body).encode())
        Path(path).chmod(0o755)
        return {"path": str(path), "sha256": A.sha(Path(path).read_bytes())}

    def engine(self, *args, check=True):
        result = subprocess.run([str(self.docker_binary), "--host", self.socket, *args],
                                capture_output=True, timeout=90)
        if check:
            self.assertEqual(result.returncode, 0, result.stderr.decode())
        return result

    def import_image(self):
        sleep = Path(shutil.which("sleep")).resolve()
        linked = subprocess.run(["ldd", str(sleep)], capture_output=True, check=True).stdout.decode()
        dependencies = set(re.findall(r"(/[A-Za-z0-9_./+-]+)", linked))
        archive = self.root / "rootfs.tar"
        with tarfile.open(archive, "w") as tar:
            tar.add(sleep, arcname="sleep")
            for path in sorted(dependencies):
                # Dereference host symlinks so no link escapes the image.
                raw = Path(path).read_bytes()
                info = tarfile.TarInfo(path.lstrip("/"))
                info.size, info.mode = len(raw), 0o755
                tar.addfile(info, io.BytesIO(raw))
        self.engine("import", str(archive), "cohort-local:fixture")

    def publish_runtime(self):
        # Use the real composed closure as a skeleton. Fixture-only bindings
        # below describe the independently captured Docker candidates; they are
        # signed afterwards with the existing native authority fixture keys.
        result = C.compose(self.inputs, 3, sequence=3, supersedes="a" * 64)
        self.code = self.install / "versions/3"
        docs = copy.deepcopy(result["documents"])
        original = json.loads(result["authorization"])
        old_ids = {r: original["roles"][r]["containerId"] for r in O.ROLES}
        def substitute(value):
            if type(value) is str:
                for r in O.ROLES:
                    value = value.replace(old_ids[r], self.ids[r])
                return value
            if type(value) is dict:
                return {substitute(k): substitute(v) for k, v in value.items()}
            if type(value) is list:
                return [substitute(v) for v in value]
            return value
        for name, raw in list(docs.items()):
            if "/source/" not in name:
                docs[name] = A.canonical(substitute(json.loads(raw)))
        for directory in sorted(result["layout"]["directories0700"], key=lambda p: (p.count("/"), p)):
            directory = substitute(directory)
            (self.install / directory).mkdir(parents=True, mode=0o700, exist_ok=True)
        for name, raw in docs.items():
            path = self.install / substitute(name)
            path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            self.write(path, raw)
        def document(relative, value):
            path = self.code / relative
            self.write(path, A.canonical(value))
            return {"path": str(path), "sha256": A.sha(path.read_bytes())}
        self.script(self.root / "systemctl", SYSTEMCTL)
        self.script(self.root / "nft", NFT)
        quiescer = self.root / "quiesce.py"
        self.write(quiescer, QUIESCE.encode())
        qbinding = {"path": str(quiescer), "sha256": A.sha(quiescer.read_bytes())}
        runtime = json.loads((self.code / "runtime-configuration.json").read_bytes())
        captures = {r: json.loads((self.root / ("capture-" + cid + ".json")).read_bytes()) for r, cid in self.ids.items()}
        real = {"path": str(self.real_runc), "sha256": A.sha(self.real_runc.read_bytes())}
        python = {"path": str(self.python), "sha256": A.sha(self.python.read_bytes())}
        self.assertEqual(len({v["root"] for v in captures.values()}), 1)
        runtime.update(runtimePath=real["path"], runtimeSha256=real["sha256"],
                       pythonPath=python["path"], pythonSha256=python["sha256"],
                       runtimeStateRoot=str(Path(captures["adapter"]["root"]).parent))
        all_nics = {}
        for index, role in enumerate(O.ROLES, 2):
            all_nics[role] = [dict(interface="eth" + str(n-1), ipv4=f"172.30.{90+n}.{index}",
                mac=f"02:42:ac:1e:{90+n:02x}:{index:02x}", bridge="oufcohort" + str(n),
                bindingRef=role + "_" + str(n), workloadRef=role) for n in (1, 2)]
        for role in O.ROLES:
            cid = self.ids[role]
            other = next(r for r in O.ROLES if r != role)
            cfg = json.loads((self.code / "broker" / (role + ".json")).read_bytes())
            template = json.loads(Path(cfg["preparerTemplate"]["path"]).read_bytes())
            template.update(pythonPath=python["path"], pythonHash=python["sha256"])
            cfg["creationFrameObserverBinding"]["python"] = python
            flow = dict(purpose="GATEWAY_ADAPTER", authorityRef="provider", protocol="tcp", port=9443,
                source=all_nics[role][0]["ipv4"], destination=all_nics[other][0]["ipv4"], peerIngress={
                    "kind": "CREATED_CANDIDATE", "bindingRef": all_nics[other][0]["bindingRef"], "declaration": {
                        "containerId": self.ids[other], "applicationHash": A.sha(A.canonical(captures[other]["oci"])),
                        "networkBindings": all_nics[other]}})
            template["candidate"].update(networkBindings=all_nics[role], transport=[flow], runtimeBinding=real)
            for name in ("ip", "nsenter"):
                path = Path(shutil.which(name)).resolve()
                template["commands"][name], template["commandHashes"][name] = str(path), A.sha(path.read_bytes())
            lock = self.root / "common.lock"
            self.write(lock, b"")
            template["lockFile"] = str(lock)
            cfg.update(preparerTemplate=document("documents/" + role + "/preparer-template.json", template),
                runtimeRootParent=runtime["runtimeStateRoot"])
            policy = json.loads(Path(cfg["framePolicyBinding"]["path"]).read_bytes())
            policy["expectedOci"] = captures[role]["oci"]
            cfg["framePolicyBinding"] = document("documents/" + role + "/frame-policy.json", policy)
            cfg["creationFrameObserverBinding"]["configuration"] = cfg["framePolicyBinding"]
            cfg["transportBinding"] = document("documents/" + role + "/transport.json",
                {k: template["candidate"][k] for k in ("networkBindings", "transport", "tableName")})
            bound = document("broker/" + role + ".json", cfg)
            B.validate(A.canonical(cfg))
            runtime["admissionConfigurations"][cid] = bound
            runtime["candidates"][cid]["bundleParents"] = [str(Path(captures[role]["bundle"]).parent)]
            original["roles"][role].update(containerId=cid, admissionConfigurationSha256=bound["sha256"],
                framePolicySha256=cfg["framePolicyBinding"]["sha256"], transportSha256=cfg["transportBinding"]["sha256"])
        sup = {"registryRoot": str(self.install / "registry"), "authorizationRoot": str(self.chain),
               "statusPath": str(self.code / "supervisor/status.json"),
               "coordinator": {"journalPath": str(self.root / "lease.json")}}
        supbinding = document("supervisor/configuration.json", sup)
        self.write(self.root / "lease.json", A.canonical(dict(state="QUIESCED", leaseAuthorized=False, startAuthorized=False)))
        self.write(Path(sup["statusPath"]), A.canonical(dict(schema="ouf.semantic-provider-lease-supervisor-status.v1",
            state="WAITING", reason="EPOCH_NOT_LIVE", epochs=dict.fromkeys(O.ROLES), activationsLastHour=0,
            authorizationSequence=1)))
        runtime["leaseQuiesce"] = dict(entrypoint=qbinding, configuration=supbinding)
        runtimebinding = document("runtime-configuration.json", runtime)
        original.update(sequence=1, supersedes=None, runtimeConfigurationSha256=runtimebinding["sha256"])
        self.chain.mkdir(mode=0o700, exist_ok=True)
        self.put(1, A.canonical(original))
        # Switch the test daemon's runtime entrypoint only after signing. This
        # does not change any production wrapper or host daemon configuration.
        self.write(self.wrapper, O.I.wrapper_bytes(str(self.python), self.code))
        self.wrapper.chmod(0o755)

    def scenario(self):
        def argv(mode="--plan", digest=None):
            result = [mode, "--action", "start", "--install-root", str(self.install), "--wrapper", str(self.wrapper),
                "--wrapper-sha256", A.sha(self.wrapper.read_bytes()), "--docker", str(self.docker_binary),
                "--docker-sha256", A.sha(self.docker_binary.read_bytes()), "--docker-socket", self.socket,
                "--timeout-seconds", "45", "--output-directory", str(self.root / "operate-result")]
            for name in ("systemctl", "nft"):
                result.extend(["--" + name, str(self.root / name), "--" + name + "-sha256", A.sha((self.root / name).read_bytes())])
            return result + (["--plan-sha256", digest] if digest else [])
        def operate(args):
            p = subprocess.run([str(self.python), "-I", "-B", str(ROOT / "scripts/operate-semantic-provider-r3.py"), *args],
                               capture_output=True, timeout=150)
            self.assertEqual(p.stderr, b"")
            return p.returncode, json.loads(p.stdout)
        code, plan = operate(argv())
        self.assertEqual(code, 0, plan)
        code, result = operate(argv("--apply", plan["planSha256"]))
        allowed = collect_codes() | {"COHORT_PEER_WAIT_TIMEOUT", "COHORT_PEER_STATE_DENIED",
            "COHORT_RUNTIME_IDENTITY_AMBIGUOUS", "BOUNDED_COHORT_RUNTIME_INVENTORY_REQUIRED", "COHORT_RUNTIME_ROW_INVALID"}
        # Print both diagnostics before asserting, even if one side is missing.
        for role, cid in self.ids.items():
            folder = self.install / "registry" / cid / "epochs/1"
            path = folder / "broker-denial-cohort-ready.json"
            print("COHORT_BROKER_DENIAL_" + role.upper() + "=" +
                  (path.read_text() if path.exists() else "MISSING"), flush=True)
            state = self.engine("inspect", "-f", "{{json .State}}", cid, check=False)
            print("COHORT_DOCKER_STATE_" + role.upper() + "=" + state.stdout.decode("utf-8", "replace").strip()
                  + state.stderr.decode("utf-8", "replace").strip(), flush=True)
        summary = {k: result.get(k) for k in ("status", "reason", "requestErrors", "observationError")}
        summary["candidates"] = {r: {k: v.get(k) for k in ("epoch", "previousEpoch", "denials")}
                                 for r, v in (result.get("lastObservation") or {}).get("candidates", {}).items()}
        print("COHORT_OPERATE_RESULT=" + json.dumps(summary, sort_keys=True), flush=True)
        log = self.root / "dockerd.log"
        if log.exists():
            lines = [l for l in log.read_text(errors="replace").splitlines() if "level=error" in l or "BLOCKED" in l]
            print("COHORT_DOCKERD_ERRORS=" + json.dumps(lines[-20:]), flush=True)
        self.assertEqual(code, 1, result)
        self.assertEqual(result["status"], "HELD")
        observation = result["lastObservation"]
        self.assertEqual(observation["lease"], {"state": "QUIESCED", "leaseAuthorized": False})
        for role, cid in self.ids.items():
            row = observation["candidates"][role]
            self.assertEqual(row["epoch"]["state"], "FAILED")
            self.assertFalse(row["docker"]["Running"])
            path = self.install / "registry" / cid / "epochs/1/broker-denial-cohort-ready.json"
            value = B.validate_denial(path.read_bytes(), cid, 1, "cohort-ready")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertIn(value["reason"], allowed)
            self.assertIsNotNone(value["cohort"])
            self.assertIn(value, row["denials"])
            self.assertFalse((path.parent / "evidence.json").exists())


@unittest.skipUnless(NATIVE, "set OUF_R3_COHORT_NATIVE=1 under Linux root:root")
class NativeTests(unittest.TestCase):
    def test_real_docker_cohort_denials(self):
        for name in ("docker", "dockerd", "runc", "unshare", "mount", "ip", "nsenter", "openssl", "ldd", "sleep"):
            self.assertIsNotNone(shutil.which(name), "native prerequisite: " + name)
        result = subprocess.run([shutil.which("unshare"), "--mount", "--net", "--fork", sys.executable,
            "-I", "-B", str(Path(__file__).resolve()), "--native-child"], capture_output=True, timeout=360)
        print(result.stdout.decode("utf-8", "replace"), flush=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", "replace"))


def load_tests(loader, tests, pattern):
    return unittest.TestSuite([loader.loadTestsFromTestCase(PortableTests), loader.loadTestsFromTestCase(NativeTests)])


if __name__ == "__main__":
    if sys.argv[1:] == ["--native-child"]:
        if not NATIVE:
            raise RuntimeError("disabled native scenario")
        subprocess.run([shutil.which("mount"), "--make-rprivate", "/"], check=True)
        suite = unittest.TestSuite([CohortFixture("scenario")])
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        raise SystemExit(0 if result.wasSuccessful() else 1)
    unittest.main()
