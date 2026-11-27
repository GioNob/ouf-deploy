"""Check the bootstrap manifest and import both owners from its installed layout."""
from contextlib import ExitStack, nullcontext, redirect_stdout
import hashlib
import importlib.util
import io
import itertools
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


class Bootstrap(unittest.TestCase):
    def setUp(self):
        stack = self.enterContext(ExitStack())
        tmp = Path(stack.enter_context(tempfile.TemporaryDirectory()))
        spec = importlib.util.spec_from_file_location("install_a2", ROOT / "scripts/install-ouf-a2.py")
        inst = self.inst = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(inst)
        inst.ROOT, inst.ENTRY, inst.RULE, inst.REPO = (tmp / name for name in ("install", "entry", "rule", "clone"))
        (inst.REPO / ".git").mkdir(parents=True)
        key = tmp / ".release-hmac.key"
        key.touch(mode=0o600)
        key.write_bytes(os.urandom(32))
        self.path = tmp / "private.json"
        cfg = json.loads((ROOT / "docs/privileged-executor.example.json").read_bytes())
        cfg.update(fingerprintKeyFile=str(key), repository="fixture/repo", repositoryId=1, environmentId=2, reviewerIds=[3], commit="a"*40,
                   runner="runner", readinessPort=8080, installRoot=str(tmp), leaseJournal=str(tmp/"lease"),
                   socket=str(tmp/"docker.sock"))
        c = cfg["queue"]
        cfg["successorImage"].update(inbox=str(tmp/"semantic-inbox"), migrationsField="migrations",
                                     predecessorMigrations=["V12__baseline.sql"])
        cfg["successorImage"]["ci"].update(repository="fixture/ouf-semantic-registry", imageName="registry",
            sourceCommit="a"*40, sourceTree="b"*40, workflow="module-ci.yml", manifestSchema="fixture.v1",
            runId=3, runAttempt=1, artifactId=4, pullRequest=2, zipSha256="a"*64, imageId="sha256:"+"b"*64)
        c.update(container="pg", role="reader", database="semantic", socket="/run/postgresql")
        cfg["semanticDatabase"].update(postgresCid="d"*64, socket=c["socket"])
        module = cfg["modules"]["onboarding"]
        cfg["gateway"].update(host="127.0.0.1", port=9180, adminPath="/apisix/admin", keyFile=str(tmp/"key"),
                              dockerSocket=cfg["socket"], container="fixture")
        cfg["gateway"]["source"]["workflow"] = "ci.yml"
        module.update(inbox=str(tmp/"inbox"), journal=str(tmp/"journal"), dockerSocket=cfg["socket"],
                      nsenter=str(tmp/"nsenter"), oldImage="sha256:"+"a"*64)
        for i, net in enumerate(module["networks"].values()):
            net["ipv4"] = f"192.0.2.{i+1}"
        module["ci"].update(runId=1, runAttempt=1, artifactId=1, imageId="sha256:"+"b"*64, zipSha256="c"*64)
        mcp = cfg["modules"]["mcp"]
        for key in ("inbox", "journal", "dockerSocket", "nsenter", "oldImage", "networks"):
            mcp[key] = module[key]
        for key in ("runId", "runAttempt", "artifactId", "imageId", "zipSha256", "sourceCommit", "sourceTree"):
            mcp["ci"][key] = module["ci"][key]
        mcp["ci"]["publisherCommit"] = mcp["ci"]["sourceCommit"]
        mcp["ci"]["transportSha256"] = "e"*64
        mcp["migration"]["database"].update(postgresCid="d"*64, socket="/run/postgresql")
        for name in ("udp", "ingestion"):
            java = cfg["modules"][name]
            for key in ("inbox", "journal", "dockerSocket", "nsenter", "oldImage", "networks", "readiness"):
                java[key] = module[key]
            if name == "udp":
                java["gate"] = module["gate"]
            java["ci"] = dict(module["ci"], artifactPrefix="fixture-" + name)
            java["migration"]["flyway"].update(postgresCid="d"*64, socket="/tmp", urlEnv="APP_URL",
                                               userEnv="APP_USER", database="fixture", schema=name)
        mock = cfg["modules"]["vertical-mock"]
        section = json.dumps(mock["install"])
        for placeholder, value in {
            "<host data root>": "/fixture/data", "<host configuration root>": "/fixture/config",
            "<container data directory>": "/mock/data", "<container domain file>": "/mock/domain",
            "<container read token file>": "/mock/read", "<container admin token file>": "/mock/admin",
            "<approved domain SHA-256>": "c"*64,
        }.items():
            section = section.replace(placeholder, value)
        mock["install"] = json.loads(section)
        for key in ("inbox", "journal", "dockerSocket", "nsenter", "oldImage", "networks"):
            mock[key] = module[key]
        mock["ci"] = dict(module["ci"], repository="fixture/ouf-vertical-mock", workflow="module-ci.yml",
                          pullRequest=1, artifactPrefix="vertical-mock-governed-image",
                          manifestSchema="ouf.vertical-mock-tested-image.v1", imageName="ouf-vertical-mock",
                          sourceCommit="f"*40, sourceTree="e"*40)
        book = ("C="+"f"*40+"\n").encode()
        self.artifacts = {}
        for binding in cfg["runbooks"].values():
            binding.update(artifactCommit="a"*40, sourceCommit="f"*40, sha256=hashlib.sha256(book).hexdigest())
        self.path.write_text(json.dumps(cfg))
        self.path.chmod(0o600)
        def git(argv, **kwargs):
            if argv[-2:] == ["rev-parse", "HEAD"]:
                return cfg["commit"].encode()
            name = argv[-1].split(":", 1)[1]
            if argv[-1] in self.artifacts:
                return self.artifacts[argv[-1]]
            return book if name.startswith("ops/vps/") else (ROOT / name).read_bytes()
        stack.enter_context(patch.object(inst.subprocess, "check_output", side_effect=git))
        stack.enter_context(patch.dict(sys.modules, pwd=types.SimpleNamespace(
            getpwnam=lambda name: types.SimpleNamespace(pw_uid=1001))))
        stack.enter_context(patch.object(inst, "safe"))  # temporary directory, no system paths
        if os.name == "nt":
            native_stat = Path.stat
            def stat(path, *args, **kw):
                result = native_stat(path, *args, **kw)
                if path == self.path:
                    return os.stat_result([0o100600, *list(result)[1:]])
                return result
            stack.enter_context(patch.object(Path, "stat", stat))

    def test_one_manifest_supplies_both_owners(self):
        inst = self.inst
        files = inst.inspect(self.path)
        self.assertEqual(files[inst.RULE], ((f'runner ALL=(root) NOPASSWD: NOSETENV: {inst.ENTRY} ""\n').encode(), 0o440))
        cfg = json.loads(files[inst.ROOT / "profile.json"][0])
        self.assertNotIn("proof", cfg["queue"])
        self.assertEqual(len(cfg["runbooks"]), 13)
        self.assertEqual(set(cfg["modules"]), {"onboarding", "mcp", "udp", "ingestion", "vertical-mock"})
        install = cfg["modules"]["vertical-mock"]["install"]
        self.assertEqual(install["user"], "10008:10008")
        env = {e["name"]: e["value"] for e in install["env"]}
        self.assertEqual({b["target"]: b["mode"] for b in install["binds"]},
                         {env["OUF_MOCK_DATA_DIR"]: "rw", env["OUF_MOCK_DOMAIN_FILE"]: "ro",
                          env["OUF_MOCK_READ_TOKEN_FILE"]: "ro", env["OUF_MOCK_ADMIN_TOKEN_FILE"]: "ro"})
        lib = inst.ROOT / "lib"
        for file, (data, _) in files.items():
            if file.is_relative_to(lib):
                file.parent.mkdir(exist_ok=True, parents=True)
                file.write_bytes(data)
        probe = ("import sys;sys.path.insert(0,sys.argv[1]);"
                 "from successor_image import admit;from module_release.mcp_artifact import verify;"
                 "from pipeline import Cutover;from module_operation import ModuleRelease;"
                 "from module_release.operation import migrate;from gateway_operation import GatewayRelease")
        subprocess.run([sys.executable, "-I", "-B", "-c", probe, str(lib)], check=True)

    def test_optional_sections_are_independent(self):
        original = self.path.read_bytes()
        for successor, gateway, mcp in itertools.product((False, True), repeat=3):
            with self.subTest(successor=successor, gateway=gateway, mcp=mcp):
                cfg = json.loads(original)
                del cfg["semanticDatabase"]
                if not successor:
                    del cfg["successorImage"]
                if not gateway:
                    del cfg["gateway"]
                if not mcp:
                    del cfg["modules"]["mcp"]
                    del cfg["modules"]["udp"]
                    del cfg["modules"]["ingestion"]
                    del cfg["modules"]["vertical-mock"]
                self.path.write_text(json.dumps(cfg))
                self.assertIn(self.inst.ENTRY, self.inst.inspect(self.path))

    def test_next_image_uses_the_same_ci_contract(self):
        cfg = json.loads(self.path.read_bytes())
        cfg["nextSuccessorImage"] = json.loads(json.dumps(cfg["successorImage"]))
        cfg["nextSuccessorImage"]["ci"]["pullRequest"] += 1
        self.path.write_text(json.dumps(cfg))
        installed = json.loads(self.inst.inspect(self.path)[self.inst.ROOT / "profile.json"][0])
        self.assertEqual(installed["nextSuccessorImage"], cfg["nextSuccessorImage"])
        del cfg["nextSuccessorImage"]["ci"]["sourceTree"]
        self.path.write_text(json.dumps(cfg))
        with self.assertRaisesRegex(ValueError, "SUCCESSOR_IMAGE_PROFILE"):
            self.inst.inspect(self.path)

    def test_complete_extensions_use_reviewed_blobs(self):
        cfg = json.loads(self.path.read_bytes())
        filenames = {"start": "r3-operate", "stop": "r3-operate", "probe": "c-probe"}
        source = "c58515e8d4567742fc9dad988b4871966ce49563"
        artifact = "d" * 40
        for version in (30, 31, 32, 33, 34, 35, 36, 37):
            for op in ("start", "stop", "issue", "upgrade", "probe"):
                name = filenames.get(op, f"r3-{op}-v{version}")
                path = f"ops/vps/{name}.sh"
                raw = (ROOT / path).read_text(encoding="utf8").encode()
                self.artifacts[f"{artifact}:{path}"] = raw
                cfg["runbooks"][f"{op}-{version}"] = dict(artifactCommit=artifact, sourceCommit=source,
                                                          sha256=hashlib.sha256(raw).hexdigest())
            self.path.write_text(json.dumps(cfg))
            if version == 30:
                self.install_fixture()
            else:
                files = self.inst.inspect(self.path)
                self.inst.install(files, self.inst.manifest(files))
            installed = json.loads((self.inst.ROOT / "profile.json").read_bytes())["runbooks"]
            self.assertEqual(installed.keys(), cfg["runbooks"].keys())
            for role, binding in cfg["runbooks"].items():
                path = self.inst.ROOT / "books" / role
                self.assertEqual(Path(installed[role]["path"]), path)
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), binding["sha256"])
        cfg["runbooks"]["probe-31"]["sha256"] = "0" * 64
        self.path.write_text(json.dumps(cfg))
        with self.assertRaisesRegex(ValueError, "RUNBOOK_PIN_DRIFT"):
            self.inst.inspect(self.path)
        for missing in ("probe-31", "issue-30"):
            books = {role: pin for role, pin in cfg["runbooks"].items() if role != missing}
            self.path.write_text(json.dumps(dict(cfg, runbooks=books)))
            with self.assertRaisesRegex(ValueError, "RUNBOOK_SET_REQUIRED"):
                self.inst.inspect(self.path)

    def test_gateway_rejects_legacy_source_token_file(self):
        cfg = json.loads(self.path.read_bytes())
        cfg["gateway"]["source"]["tokenFile"] = str(self.path.parent / "token")
        self.path.write_text(json.dumps(cfg))
        with self.assertRaisesRegex(ValueError, "GATEWAY_INSTALL_PROFILE"):
            self.inst.inspect(self.path)

    def install_fixture(self):
        inst = self.inst
        self.files = inst.inspect(self.path)
        self.native = sys.platform == "linux" and os.getenv("OUF_A2_NATIVE") == "1"
        if not self.native:
            self.enterContext(patch.object(inst, "visudo"))
        if os.name == "nt":
            # NTFS has rename and hard links, but no POSIX permissions or directory fsync.
            modes = {}
            self.enterContext(patch.object(inst, "sync_dir"))
            def chmod(fd, mode):
                modes[os.fstat(fd).st_ino] = mode
            self.enterContext(patch.object(os, "fchmod", chmod, create=True))
            path_stat = Path.stat
            def posix_stat(path, *args, **kwargs):
                result = path_stat(path, *args, **kwargs)
                mode = 0o700 if stat.S_ISDIR(result.st_mode) else modes.get(result.st_ino)
                if mode is not None:
                    return os.stat_result([stat.S_IFMT(result.st_mode) | mode, *list(result)[1:]])
                return result
            self.enterContext(patch.object(Path, "stat", posix_stat))
        previous = os.umask(0o077)
        self.addCleanup(os.umask, previous)
        spec = inst.manifest(self.files)
        self.assertTrue(all(row["before"] is None and row["action"] == "create" for row in spec.values()))
        inst.install(self.files, spec)

    def snapshot(self):
        return {p: (p.read_bytes(), p.stat().st_mode, p.stat().st_ino)
                for p in self.path.parent.rglob("*") if p.is_file()}

    def prepare_update(self):
        self.install_fixture()
        inst = self.inst
        state = inst.ROOT / "state"
        (state / "123").mkdir()
        for name in ("123/approvals", "gateway-head"):
            (state / name).write_bytes(b"retained")
        (self.path.parent / "journal" / "receipt").write_bytes(b"retained")
        (inst.ROOT / "lib/operator-file").write_bytes(b"unmanaged")
        old = inst.ROOT / "lib/obsolete.py"
        old.write_bytes(b"old module")
        inventory = inst.ROOT / "managed-files.json"
        inventory.write_text(json.dumps(json.loads(inventory.read_bytes()) + ["lib/obsolete.py"]))
        self.files[inst.ENTRY] = (b"new executable", 0o755)
        self.files[inst.RULE] = (b"# updated rule\n" + self.files[inst.RULE][0], 0o440)
        self.spec = inst.manifest(self.files)
        self.assertEqual(self.spec[str(old)]["action"], "delete")
        self.assertIsNone(self.spec[str(old)]["after"])
        return old

    def test_update_replaces_rule_last_and_preserves_state(self):
        obsolete = self.prepare_update()
        inst = self.inst
        before = self.snapshot()
        with patch.object(os, "replace", wraps=os.replace) as replace:
            inst.install(self.files, self.spec)
        self.assertEqual(replace.call_args.args[1], inst.RULE)
        after = self.snapshot()
        self.assertNotIn(obsolete, after)
        for p in before.keys() - {obsolete, inst.ENTRY, inst.RULE, inst.ROOT / "managed-files.json"}:
            self.assertEqual(after[p], before[p], p)
        self.assertEqual(after[inst.ENTRY][0], b"new executable")
        self.assertTrue(all(row["action"] == "unchanged" for row in inst.manifest(self.files).values()))
        self.assertEqual(set(after), set(before) - {obsolete})

    def test_adopt_existing_installation_without_inventory(self):
        self.install_fixture()
        inst = self.inst
        inventory = inst.ROOT / "managed-files.json"
        inventory.unlink()
        profile = inst.ROOT / "profile.json"
        legacy = json.loads(profile.read_bytes())
        del legacy["modules"]
        profile.write_text(json.dumps(legacy))
        entry = inst.ROOT / "lib/mandate.py"
        entry.write_bytes(b"previous revision")
        extra = inst.ROOT / "books/local-copy"
        extra.write_bytes(b"owner file")
        spec = inst.manifest(self.files)
        self.assertEqual(spec[str(inventory)]["action"], "create")
        self.assertEqual(spec[str(entry)], dict(action="replace", before=inst.fingerprint(b"previous revision", 0o600),
                                                after=inst.fingerprint(*self.files[entry])))
        self.assertNotIn(str(extra), spec)
        inst.install(self.files, spec)
        self.assertEqual(entry.read_bytes(), self.files[entry][0])
        self.assertEqual(extra.read_bytes(), b"owner file")
        self.assertNotIn("books/local-copy", json.loads(inventory.read_bytes()))

    def test_failed_last_rename_rolls_back_all_creates_replacements_and_deletions(self):
        self.prepare_update()
        inst = self.inst
        (inst.ROOT / "lib/mandate.py").unlink()
        before = self.snapshot()
        spec = inst.manifest(self.files)
        rename = os.replace
        def fail_rule(src, dst):
            if dst == inst.RULE:
                raise OSError("rename failed")
            rename(src, dst)
        with patch.object(os, "replace", side_effect=fail_rule), self.assertRaisesRegex(OSError, "rename failed"):
            inst.install(self.files, spec)
        self.assertEqual(self.snapshot(), before)

    def test_invalid_sudoers_replaces_nothing(self):
        self.prepare_update()
        inst = self.inst
        self.files[inst.RULE] = (b"this is not a valid sudoers rule\n", 0o440)
        if not self.native:
            def validate(*args):
                if args:
                    self.assertEqual(args[0], "-f")
                    self.assertEqual(Path(args[1]).read_bytes(), self.files[inst.RULE][0])
                    raise subprocess.CalledProcessError(1, "visudo")
            inst.visudo.side_effect = validate
        before = self.snapshot()
        with patch.object(os, "replace") as rename, self.assertRaises(subprocess.CalledProcessError):
            inst.install(self.files, inst.manifest(self.files))
        rename.assert_not_called()
        self.assertEqual(self.snapshot(), before)

    def test_inventory_rejects_traversal_and_protects_retired_journal(self):
        self.install_fixture()
        inst = self.inst
        inventory = inst.ROOT / "managed-files.json"
        for name in ("state/gateway-head", "lib/../state/gateway-head", str(inst.ENTRY)):
            inventory.write_text(json.dumps([name]))
            with self.assertRaisesRegex(ValueError, "INVALID_INSTALL_INVENTORY"):
                inst.manifest(self.files)
        retired = inst.ROOT / "lib/retired-journal"
        profile = inst.ROOT / "profile.json"
        cfg = json.loads(profile.read_bytes())
        cfg["modules"]["mcp"]["journal"] = str(retired)
        profile.write_text(json.dumps(cfg))
        inventory.write_text(json.dumps(["lib/retired-journal/receipt"]))
        with self.assertRaisesRegex(ValueError, "PROTECTED_INSTALL_STATE"):
            inst.manifest(self.files)

    def test_apply_rechecks_digest_under_lock(self):
        inst = self.inst
        self.install_fixture()
        if not self.native:
            self.enterContext(patch.object(os, "geteuid", return_value=0, create=True))
            self.enterContext(patch.object(inst, "sys", types.SimpleNamespace(
                flags=types.SimpleNamespace(isolated=True), path=sys.path, modules=sys.modules)))
        if os.name == "nt":
            self.enterContext(patch.object(inst, "installation_lock", nullcontext))
        def cli(mode, *args):
            output = io.StringIO()
            with patch.object(sys, "argv", ["install", mode, str(self.path), *args]), redirect_stdout(output):
                inst.main()
            return output.getvalue()
        inst.ENTRY.write_bytes(b"previous version")
        digest = json.loads(cli("plan"))["planSha256"]
        inspect = inst.inspect
        calls = 0
        def drift(path):
            nonlocal calls
            calls += 1
            if calls == 2:
                inst.ENTRY.write_bytes(b"concurrent update")
            return inspect(path)
        with patch.object(inst, "inspect", side_effect=drift), self.assertRaisesRegex(ValueError, "INSTALL_PLAN_DRIFT"):
            cli("apply", "--plan-sha256", digest)
        self.assertEqual(inst.ENTRY.read_bytes(), b"concurrent update")
        digest = json.loads(cli("plan"))["planSha256"]
        self.assertIn("OUF_A2_INSTALLED", cli("apply", "--plan-sha256", digest))
        current = json.loads(cli("plan"))["planSha256"]
        self.assertNotEqual(current, digest)
        with patch("builtins.input", return_value=current), patch.object(os, "replace") as rename:
            self.assertIn("OUF_A2_INSTALLED", cli("bootstrap"))
            rename.assert_not_called()
