#!/usr/bin/env python3
"""Bounded hosted source observation, deliberately not a release qualifier."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time
import traceback
import zipfile

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from tools.storage_security import vendor_module_origins as origins
from tools.storage_security import vendor_yaml_source as guard
spec = importlib.util.spec_from_file_location("materializer", REPO / "scripts/prepare_iceberg_vendor_patch.py")
materializer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(materializer)


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write(path, value):
    Path(path).write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def vendor_modules(text):
    # Go records unused wildcard replacements at the end of modules.txt.
    # The pinned upstream directive below must never own a vendored package.
    inactive_module = "github.com/tyler-smith/go-bip39"
    inactive_footer = f"# {inactive_module} => github.com/cosmos/go-bip39 v1.0.0"
    lines = text.splitlines()
    has_inactive_footer = bool(lines and lines[-1] == inactive_footer)
    if has_inactive_footer:
        lines.pop()
        guard.require(not any(line == inactive_module or line.startswith(inactive_module + "/")
                              for line in lines), "INACTIVE_VENDOR_REPLACEMENT_OWNS_PACKAGE")
    rows = []
    for line in lines:
        if line.startswith("# "):
            parts = line.split()
            guard.require(len(parts) == 3 and parts[2].startswith("v"), "EXACT_VENDOR_MODULE_HEADERS_REQUIRED")
            guard.require(not has_inactive_footer or parts[1] != inactive_module,
                          "INACTIVE_VENDOR_REPLACEMENT_HAS_MODULE")
            rows.append((parts[1], parts[2]))
    guard.require(rows and len(rows) == len({r[0] for r in rows}), "UNIQUE_VENDOR_MODULES_REQUIRED")
    return sorted(rows)


def module_info(rows):
    return "vendor/modules.txt original-input enumeration; NOT binary build-info\n" + "".join(
        "\tdep\t" + n + "\t" + v + "\t\n" for n, v in rows)


def verify_vendor_files(vendor, rows, records):
    """Authenticate every actual baseline vendor file against its original ZIP."""
    files = guard.inventory(vendor)
    grouped = {name: [] for name, _ in rows}
    for name in files:
        if name == "modules.txt":
            continue
        matches = [module for module in grouped if name.startswith(module + "/")]
        guard.require(matches, "VENDOR_FILE_WITHOUT_MODULE:" + name)
        grouped[max(matches, key=len)].append(name)
    verified = 0
    for module, version in rows:
        selected = [r for r in records if (r.get("Path"), r.get("Version")) == (module, version)]
        guard.require(len(selected) == 1, "EXACT_VENDOR_ORIGIN_RECORD_REQUIRED")
        with zipfile.ZipFile(selected[0]["Zip"]) as archive:
            for name in grouped[module]:
                member = module + "@" + version + "/" + name[len(module) + 1:]
                guard.require(member in archive.namelist(), "VENDOR_FILE_NOT_IN_ORIGINAL_ZIP:" + name)
                with archive.open(member) as stream:
                    wanted = hashlib.file_digest(stream, "sha256").hexdigest()
                guard.require(files[name] == wanted, "VENDOR_FILE_DIFFERS_FROM_ORIGINAL_ZIP:" + name)
                verified += 1
    guard.require(verified == len(files) - 1, "COMPLETE_VENDOR_FILE_ORIGIN_BINDING_REQUIRED")
    return {"filesAuthenticatedAgainstOriginalZip": verified, "modulesTxtGeneratedByGo": True,
            "modulesTxtSha256": files["modules.txt"], "vendorTreeSha256": guard.tree_sha(files)}


def finalize(evidence, report):
    evidence = Path(evidence)
    evidence.mkdir(parents=True, exist_ok=True)
    write(evidence / "observation.json", report)
    rows = {}
    for path in sorted(evidence.rglob("*")):
        guard.require(not path.is_symlink(), "EVIDENCE_SYMLINK_DENIED")
        if path.is_file() and path.name != "SHA256SUMS":
            rows[path.relative_to(evidence).as_posix()] = sha(path)
    (evidence / "SHA256SUMS").write_text("".join(rows[n] + "  " + n + "\n" for n in sorted(rows)))


class Observer:
    def __init__(self, repo, upstream, work, evidence, budget=2100):
        self.repo, self.upstream = Path(repo).resolve(), Path(upstream).resolve()
        self.work, self.evidence = Path(work).resolve(), Path(evidence).resolve()
        guard.require(not self.work.exists(), "FRESH_OBSERVATION_WORK_REQUIRED")
        guard.require(not self.work.is_relative_to(self.repo) and not self.work.is_relative_to(self.upstream), "ISOLATED_OBSERVATION_WORK_REQUIRED")
        self.work.mkdir(parents=True)
        self.evidence.mkdir(parents=True, exist_ok=True)
        self.started, self.deadline = time.monotonic(), time.monotonic() + budget
        self.commands = []
        self.env = dict(os.environ, CGO_ENABLED="0", GOTOOLCHAIN="local", GOFLAGS="", GOWORK="off",
                        GOMODCACHE=str(self.work / "module-cache"), GOCACHE=str(self.work / "build-cache"),
                        GOPATH=str(self.work / "gopath"), TMPDIR=str(self.work / "tmp"))
        Path(self.env["TMPDIR"]).mkdir()
        self.report = {"schema": "ouf.seaweedfs-yaml-vendor-source-observation.v1", "status": "RUNNING",
            "intendedGeneration": 33, "baseGeneration": 32, "sourcePatchCount": 32, "dependencyPatchCount": 1,
            "releaseAdmitted": False, "runtimeAuthorityIssued": False, "allDependenciesMaintained": False,
            "downstreamMaintenance": {"status": "OPEN", "technicalOwner": None}, "targetOperations": 0,
            "repositoryCommit": os.environ.get("GITHUB_SHA"), "runId": os.environ.get("GITHUB_RUN_ID"),
            "binaryPublished": False, "fullVendorPublished": False}

    def run(self, name, args, cwd=None, timeout=300, extra_env=None, negative=False):
        remaining = int(self.deadline - time.monotonic())
        guard.require(remaining > 0, "OBSERVATION_WALL_CLOCK_BUDGET_EXHAUSTED")
        out, err = self.evidence / (name + ".stdout"), self.evidence / (name + ".stderr")
        row = {"name": name, "args": [str(x) for x in args], "cwd": str(cwd or self.work),
               "timeoutSeconds": min(timeout, remaining), "expectedNonzero": negative,
               "CGO_ENABLED": (extra_env or {}).get("CGO_ENABLED", self.env["CGO_ENABLED"]), "GOFLAGS": "", "GOWORK": "off"}
        started = time.monotonic()
        with out.open("wb") as stdout, err.open("wb") as stderr:
            proc = subprocess.Popen(row["args"], cwd=cwd or self.work, env=dict(self.env, **(extra_env or {})),
                                    stdout=stdout, stderr=stderr, start_new_session=True)
            try:
                code = proc.wait(timeout=row["timeoutSeconds"])
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()
                code = 124
                row["timedOut"] = True
        row.update(exitCode=code, durationSeconds=round(time.monotonic() - started, 3),
                   stdoutSha256=sha(out), stderrSha256=sha(err))
        self.commands.append(row)
        write(self.evidence / "commands.json", self.commands)
        guard.require(not row.get("timedOut"), "COMMAND_TIMEOUT:" + name)
        guard.require((code != 0) if negative else (code == 0), "COMMAND_UNEXPECTED_EXIT:" + name)
        return out.read_text()

    def reconstruct(self, name, manifest):
        root = self.work / name
        self.run(name + "-clone", ["git", "clone", "--no-hardlinks", str(self.upstream), str(root)])
        head = self.run(name + "-head", ["git", "rev-parse", "HEAD"], root).strip()
        guard.require(head == manifest["upstreamCommit"], "EXACT_UPSTREAM_COMMIT_REQUIRED")
        for i, patch in enumerate(manifest["orderedPatches"], 1):
            path = self.repo / patch["path"]
            guard.require(sha(path) == patch["sha256"], "SOURCE_PATCH_CHANGED")
            self.run(name + "-patch-" + str(i), ["git", "apply", "--index", str(path)], root)
        self.run(name + "-diff-check", ["git", "diff", "--cached", "--check"], root)
        self.run(name + "-working-tree-check", ["git", "diff", "--exit-code"], root)
        tree = self.run(name + "-source-tree", ["git", "write-tree"], root).strip()
        guard.require(tree == manifest["build"]["patchedSourceTree"], "EXACT_GENERATION32_SOURCE_TREE_REQUIRED")
        replay_output = self.evidence / (name + "-canonical-replay.json")
        self.run(name + "-canonical-replay", [sys.executable, "-I", "-B", "-S",
            str(self.repo / "scripts/replay-seaweedfs-source-tree.py"),
            "--repository", str(root), "--manifest", str(self.repo / "releases/seaweedfs-452-generation32-build-manifest-20261103.json"),
            "--patch-root", str(self.repo), "--work-parent", str(self.work / "canonical-replay"),
            "--output", str(replay_output), "--entries-output", str(self.evidence / (name + "-canonical-ls-tree.z"))])
        replay = json.loads(replay_output.read_bytes())
        guard.require(replay["patchedSourceTree"] == tree and replay["callerIndexRefsObjectsUntouched"] is True,
                      "INDEPENDENT_CANONICAL_REPLAY_MISMATCH")
        self.verify_locks(root, manifest)
        return root

    @staticmethod
    def verify_locks(root, manifest):
        for name, wanted in manifest["build"]["rootLockfilesSha256"].items():
            guard.require(sha(root / name) == wanted, "FROZEN_ROOT_LOCK_CHANGED:" + name)

    def observe(self):
        inputs_path = self.repo / "config/seaweedfs-yaml33-observation-inputs.json"
        inputs = json.loads(inputs_path.read_bytes())
        manifest_path = self.repo / inputs["baseManifestPath"]
        guard.require(sha(manifest_path) == inputs["baseManifestSha256"], "FROZEN_GENERATION32_MANIFEST_CHANGED")
        for name, wanted in inputs["inputFilesSha256"].items():
            guard.require(sha(self.repo / name) == wanted, "OBSERVATION_INPUT_CHANGED:" + name)
        manifest = json.loads(manifest_path.read_bytes())
        guard.require(manifest["generation"] == 32 and len(manifest["orderedPatches"]) == 32
                      and manifest["build"]["patchedSourceTree"] == inputs["rootSourceTree32"], "EXACT_GENERATION32_REQUIRED")
        shutil.copyfile(inputs_path, self.evidence / "observation-inputs.json")
        shutil.copyfile(manifest_path, self.evidence / "base32-manifest.json")
        version = self.run("go-version", ["go", "version"])
        guard.require(version.strip() == "go version go1.27.3 linux/amd64", "EXACT_GO_TOOLCHAIN_REQUIRED")
        self.run("go-env", ["go", "env", "-json"])
        first = self.reconstruct("first", manifest)
        self.report["rootSourceTree32"] = manifest["build"]["patchedSourceTree"]
        self.report["baseManifestSha256"] = sha(manifest_path)
        self.run("root-tidy", ["go", "mod", "tidy", "-diff"], first, 300)
        guard.require((self.evidence / "root-tidy.stdout").stat().st_size == 0, "ROOT_TIDY_NOT_FIXED_POINT")
        self.run("root-module-graph", ["go", "mod", "graph"], first)
        self.run("first-vendor", ["go", "mod", "vendor"], first, 600)
        self.verify_locks(first, manifest)
        modules_manifest = self.evidence / "baseline-vendor-modules.txt"
        shutil.copyfile(first / "vendor/modules.txt", modules_manifest)
        rows = vendor_modules(modules_manifest.read_text())
        records = origins.parse_records(self.run("vendor-input-download-records",
            ["go", "mod", "download", "-json"] + [n + "@" + v for n, v in rows], first, 600).encode())
        self.verify_locks(first, manifest)
        self.run("module-cache-verify-before", ["go", "mod", "verify"], first, 300)
        all_info = module_info(rows)
        (self.evidence / "baseline-vendor-module-enumeration.txt").write_text(all_info)
        all_origins = origins.collect(all_info, (first / "go.sum").read_text(), records)
        write(self.evidence / "baseline-vendor-origins.json", all_origins)
        write(self.evidence / "baseline-vendor-file-origins.json", verify_vendor_files(first / "vendor", rows, records))
        before = guard.inventory(first / "vendor")
        write(self.evidence / "vendor-before-files.json", before)
        original_config = (first / "vendor" / guard.CONFIG).read_bytes()
        after = dict(before)
        after[guard.CONFIG] = guard.PATCHED_CONFIG_SHA256
        archive = next(Path(r["Zip"]) for r in records if r["Path"] == guard.ICEBERG)
        materialized = materializer.prepare(first / "vendor", archive, guard.tree_sha(before), guard.tree_sha(after))
        write(self.evidence / "vendor-materializer.json", materialized)
        write(self.evidence / "vendor-after-files.json", guard.inventory(first / "vendor"))
        self.report.update(vendorBeforeTreeSha256=guard.tree_sha(before), vendorAfterTreeSha256=guard.tree_sha(after),
                           vendorFileCount=len(before), baselineVendorModuleCount=len(rows), vendorDigestsObservedNotAdmitted=True)
        self.contract_tests(first, archive, original_config)
        self.run("production-graph", ["go", "list", "-mod=vendor", "-deps", "-json", "./weed"], first, 300)
        packages = self.run("production-packages", ["go", "list", "-mod=vendor", "-deps", "./weed"], first).splitlines()
        write(self.evidence / "production-packages.json", {"packages": sorted(packages)})
        first_binary = self.work / "weed-first"
        self.run("first-build", ["go", "build", "-mod=vendor", "-trimpath", "-buildvcs=true", "-o", str(first_binary), "./weed"], first, 600)
        info = self.run("first-build-info", ["go", "version", "-m", str(first_binary)])
        guard.verify_compiled_closure(packages, info)
        guard.require("\tbuild\tvcs.revision=" + manifest["upstreamCommit"] in info and "\tbuild\tvcs.modified=true" in info, "EXPLICIT_PATCHED_VCS_IDENTITY_REQUIRED")
        compiled = origins.collect(info, (first / "go.sum").read_text(), records)
        write(self.evidence / "compiled-module-origins.json", compiled)
        self.report["compiledModuleCount"] = compiled["moduleCount"]
        self.run("iceberg-worker-tests", ["go", "test", "-mod=vendor", "-count=1", "-timeout=4m", "-json", "./weed/worker/tasks/iceberg"], first, 600)
        self.run("source-profile-tests", ["go", "test", "-mod=vendor", "-count=1", "-timeout=3m", "-run", "TestOUF|TestChunk|TestFilerChunk", "-json", "./weed/command", "./weed/server", "./weed/replication/sink/filersink"], first, 600)
        self.config_tests(first, archive)
        summaries = {}
        for name, minimum in [("iceberg-worker-tests", 100), ("source-profile-tests", 1), ("upstream-config-tests", 6), ("upstream-config-race", 6)]:
            events = [json.loads(line) for line in (self.evidence / (name + ".stdout")).read_text().splitlines() if line]
            passed = [r for r in events if r.get("Action") == "pass" and r.get("Test")]
            guard.require(len(passed) >= minimum and not any(r.get("Action") == "fail" for r in events), "MEANINGFUL_TEST_EXECUTION_REQUIRED:" + name)
            summaries[name] = {"testPassEvents": len(passed), "testSkipEvents": sum(r.get("Action") == "skip" and bool(r.get("Test")) for r in events)}
        write(self.evidence / "go-test-summaries.json", summaries)
        for tag in ["elastic", "rclone", "kafka", "openbao", "vault", "gcs", "google_pub_sub", "googlecloud"]:
            self.run("denied-" + tag, ["go", "build", "-mod=vendor", "-tags=" + tag, "-o", str(self.work / "denied"), "./weed"], first, 120, negative=True)
            denial = "OUF_STANDARD_PROFILE_GOOGLE_UNSUPPORTED_USE_SEPARATELY_QUALIFIED_CANDIDATE" if tag in {"gcs", "google_pub_sub", "googlecloud"} else "OUF_STANDARD_PROFILE_DOES_NOT_SUPPORT"
            guard.require(denial in (self.evidence / ("denied-" + tag + ".stderr")).read_text(), "EXPLICIT_PROFILE_DENIAL_REQUIRED:" + tag)
        second = self.reconstruct("second-independent-path", manifest)
        self.run("second-vendor", ["go", "mod", "vendor"], second, 600)
        guard.require(guard.inventory(second / "vendor") == before, "INDEPENDENT_BASE_VENDOR_REPLAY_MISMATCH")
        materializer.prepare(second / "vendor", archive, guard.tree_sha(before), guard.tree_sha(after))
        second_binary = self.work / "weed-second"
        self.run("second-build", ["go", "build", "-mod=vendor", "-trimpath", "-buildvcs=true", "-o", str(second_binary), "./weed"], second, 600)
        second_info = self.run("second-build-info", ["go", "version", "-m", str(second_binary)])
        guard.require(sha(first_binary) == sha(second_binary), "INDEPENDENT_BINARY_REPRODUCTION_MISMATCH")
        guard.require(info.splitlines()[1:] == second_info.splitlines()[1:], "INDEPENDENT_BUILD_INFO_REPRODUCTION_MISMATCH")
        for root in (first, second):
            self.verify_locks(root, manifest)
            guard.require(guard.inventory(root / "vendor") == after, "VENDOR_CHANGED_DURING_TEST_OR_BUILD")
        self.run("module-cache-verify-after", ["go", "mod", "verify"], first, 300)
        guard.require(origins.collect(all_info, (first / "go.sum").read_text(), records) == all_origins, "ORIGINAL_INPUTS_CHANGED_DURING_BUILD")
        self.report.update(binarySha256=sha(first_binary), binaryBytes=first_binary.stat().st_size, reproducibleTwoCleanPaths=True,
                           compiledLegacyYaml=False, cacheInputsAndVendorUnchanged=True, status="OBSERVATION_PASS_NOT_RELEASE_QUALIFIED")

    def contract_tests(self, root, archive, original_config):
        fixture = self.work / "bounded-fixture"
        fixture.mkdir()
        for module in (guard.ICEBERG, guard.YAML):
            src, dst = root / "vendor" / module, fixture / module
            dst.parent.mkdir(parents=True, exist_ok=True)
            if module == guard.ICEBERG:
                shutil.copytree(src / "config", dst / "config")
                for name in ("LICENSE", "NOTICE"):
                    shutil.copyfile(src / name, dst / name)
            else:
                shutil.copytree(src, dst)
        shutil.copyfile(root / "vendor/modules.txt", fixture / "modules.txt")
        original = self.work / "bounded-original-fixture"
        shutil.copytree(fixture, original)
        (original / guard.CONFIG).write_bytes(original_config)
        env = {"OUF_YAML_BASE_VENDOR_FIXTURE": str(original), "OUF_YAML_PATCHED_VENDOR_FIXTURE": str(fixture),
               "OUF_ICEBERG_INPUT_ZIP": str(archive), "OUF_YAML_NOTICE_PATCH": str(self.repo / "patches/iceberg-go/0.7.0-maintained-yaml-vendor.patch"),
               "OUF_MODULE_CACHE": self.env["GOMODCACHE"], "OUF_ROOT_GO_SUM": str(root / "go.sum")}
        counts = {}
        for test, expected in [("test_prepare_iceberg_vendor_patch.py", 8), ("test_vendor_yaml_source_profile.py", 25), ("test_vendor_module_origins.py", 8)]:
            self.run(test[:-3], [sys.executable, "-B", str(self.repo / "tests" / test)], extra_env=env)
            stderr = (self.evidence / (test[:-3] + ".stderr")).read_text()
            guard.require(re.search(r"Ran " + str(expected) + r" tests? in ", stderr) and "\nOK\n" in stderr, "EXACT_GUARD_TEST_EXECUTION_REQUIRED")
            counts[test] = expected
        write(self.evidence / "guard-test-summary.json", {"testsPassed": sum(counts.values()), "suites": counts})

    def config_tests(self, root, archive):
        comparator = self.work / "config-test-copy"
        comparator.mkdir()
        shutil.copyfile(root / "vendor" / guard.CONFIG, comparator / "config.go")
        with zipfile.ZipFile(archive) as z:
            test = z.read(guard.ICEBERG + "@v0.7.0/config/config_test.go")
        (comparator / "config_test.go").write_bytes(test)
        write(self.evidence / "actual-config-test-inputs.json", {"configSha256": sha(comparator / "config.go"), "upstreamTestSha256": sha(comparator / "config_test.go")})
        args = ["go", "test", "-mod=vendor", "-count=1", "-timeout=90s", "-json", str(comparator / "config.go"), str(comparator / "config_test.go")]
        self.run("upstream-config-tests", args, root, 300)
        self.run("upstream-config-race", args[:2] + ["-race"] + args[2:], root, 300, extra_env={"CGO_ENABLED": "1"})
        self.run("yaml-differential", ["go", "run", "-mod=vendor", str(self.repo / "tests/fixtures/compare_iceberg_yaml.go")], root, 180)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--upstream", required=True, type=Path)
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    args = parser.parse_args()
    observer = Observer(args.repo, args.upstream, args.work, args.evidence)
    try:
        observer.observe()
    except Exception as error:
        observer.report.update(status="OBSERVATION_FAIL_NOT_RELEASE_QUALIFIED", failure=str(error), failureType=type(error).__name__)
        (observer.evidence / "failure.traceback.txt").write_text(traceback.format_exc())
    finally:
        observer.report["elapsedSeconds"] = round(time.monotonic() - observer.started, 3)
        finalize(observer.evidence, observer.report)
    return 0 if observer.report["status"] == "OBSERVATION_PASS_NOT_RELEASE_QUALIFIED" else 1


if __name__ == "__main__":
    sys.exit(main())
