"""Check the bootstrap manifest and import both owners from its installed layout."""
from contextlib import ExitStack, redirect_stdout
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
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
        self.path = tmp / "private.json"
        cfg = json.loads((ROOT / "docs/privileged-executor.example.json").read_bytes())
        cfg.update(repository="fixture/repo", repositoryId=1, environmentId=2, reviewerIds=[3], commit="a"*40,
                   runner="runner", readinessPort=8080, installRoot=str(tmp), leaseJournal=str(tmp/"lease"),
                   socket=str(tmp/"docker.sock"))
        c = cfg["queue"]
        c.update(container="pg", role="reader", database="semantic", socket="/run/postgresql")
        module = cfg["modules"]["onboarding"]
        module.update(inbox=str(tmp/"inbox"), journal=str(tmp/"journal"), dockerSocket=cfg["socket"],
                      nsenter=str(tmp/"nsenter"), oldImage="sha256:"+"a"*64)
        for i, net in enumerate(module["networks"].values()):
            net["ipv4"] = f"192.0.2.{i+1}"
        module["ci"].update(runId=1, runAttempt=1, artifactId=1, imageId="sha256:"+"b"*64, zipSha256="c"*64)
        book = ("C="+"f"*40+"\n").encode()
        for binding in cfg["runbooks"].values():
            binding.update(artifactCommit="a"*40, sourceCommit="f"*40, sha256=hashlib.sha256(book).hexdigest())
        self.path.write_text(json.dumps(cfg))
        self.path.chmod(0o600)
        def git(argv, **kwargs):
            if argv[-2:] == ["rev-parse", "HEAD"]:
                return cfg["commit"].encode()
            name = argv[-1].split(":", 1)[1]
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
        self.assertEqual(set(cfg["modules"]), {"onboarding"})
        lib = inst.ROOT / "lib"
        for file, (data, _) in files.items():
            if file.is_relative_to(lib):
                file.parent.mkdir(exist_ok=True, parents=True)
                file.write_bytes(data)
        probe = ("import sys;sys.path.insert(0,sys.argv[1]);"
                 "from pipeline import Cutover;from module_operation import ModuleRelease;"
                 "from module_release.operation import migrate")
        subprocess.run([sys.executable, "-I", "-B", "-c", probe, str(lib)], check=True)

    @unittest.skipUnless(sys.platform == "linux" and os.getenv("OUF_A2_NATIVE") == "1", "Linux bootstrap opt-in")
    def test_apply_reconciles_one_installation(self):
        inst = self.inst
        # os.umask affects the process; the real isolated entrypoint exits after bootstrap.
        previous = os.umask(0o077)
        self.addCleanup(os.umask, previous)
        manifest = inst.manifest(inst.inspect(self.path))
        digest = inst.sha(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode())
        with patch.object(sys, "argv", ["install", "apply", str(self.path), "--plan-sha256", digest]), redirect_stdout(io.StringIO()):
            inst.main()
            inst.main()
        self.assertTrue(inst.RULE.exists())
        self.assertEqual(inst.manifest(inst.inspect(self.path)), manifest)
