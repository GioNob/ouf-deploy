import copy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import warnings
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


candidate = module("candidate29", "scripts/qualify-seaweedfs-452-generation29-image.py")
readback = module("readback29", "scripts/readback-seaweedfs-452-generation29-image.py")
image = candidate.image


class GenerationBoundaryTests(unittest.TestCase):
    def test_reviewed_manifest_and_patch_bytes_are_exact(self):
        candidate.validate_manifest(candidate.MANIFEST)
        candidate.verify_patch_sources()
        self.assertEqual(len(candidate.source_names()), 37)
        self.assertEqual(candidate.MANIFEST["orderedPatches"][-1]["path"],
                         "patches/seaweedfs/4.52-s3-content-type-persistence.patch")

    def test_prior_generation_and_authority_are_rejected(self):
        for field, value in (("generation", 15), ("releaseAdmitted", True),
                             ("runtimeAuthorityIssued", True), ("targetOperations", 1)):
            changed = copy.deepcopy(candidate.MANIFEST)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                candidate.validate_manifest(changed)
        changed = copy.deepcopy(candidate.MANIFEST)
        changed["build"]["binarySha256"] = "85fa52c68a783f3cf4d54ae6064e7b46d022982c1bef4460616dd76cdc609033"
        with self.assertRaisesRegex(ValueError, "NEW_STANDARD_BUILD_PIN"):
            candidate.validate_manifest(changed)

    def test_patch_duplicates_paths_and_optional_tags_are_rejected(self):
        for mutation in ("duplicate", "path", "tags"):
            changed = copy.deepcopy(candidate.MANIFEST)
            if mutation == "duplicate":
                changed["orderedPatches"][-1] = changed["orderedPatches"][0]
            elif mutation == "path":
                changed["orderedPatches"][0]["path"] = "../escape.patch"
            else:
                changed["build"]["tags"] = ["rclone"]
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                candidate.validate_manifest(changed)

    def test_patch_tamper_denied_before_build(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "fixture.patch").write_bytes(b"changed")
            manifest = {"orderedPatches": [{"path": "fixture.patch", "sha256": image.sha(b"original")} ]}
            with patch.object(candidate, "ROOT", root), patch.object(candidate, "MANIFEST", manifest):
                with self.assertRaisesRegex(ValueError, "PATCH_SOURCE_CHANGED"):
                    candidate.verify_patch_sources()


class ImageReadbackTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.build = self.root / "build"
        self.build.mkdir()
        self.out = self.root / "image"
        self.binary = b"synthetic generation29 executable"
        licence = b"Apache License synthetic fixture"
        profile = candidate.PROFILE._replace(binary_sha=image.sha(self.binary), licence_sha=image.sha(licence))
        manifest = copy.deepcopy(candidate.MANIFEST)
        manifest["build"]["patchedSourceTree"] = "a" * 40
        graph = [candidate.lifecycle.WEED, candidate.lifecycle.WEED + "/s3api"]
        graph_raw = ("\n".join(graph) + "\n").encode()
        manifest["build"].update(binarySha256=profile.binary_sha, compiledPackages=2,
                                 compiledPackagesSha256=image.sha(graph_raw))
        for target, key, value in ((candidate, "PROFILE", profile), (candidate, "MANIFEST", manifest),
                                   (readback, "candidate", candidate)):
            item = patch.object(target, key, value)
            item.start()
            self.addCleanup(item.stop)
        self.profile = profile
        info = ("fixture: go1.27.3\n"
                "\tmod\tgithub.com/seaweedfs/seaweedfs\tv0.0.0-fixture\t\n"
                "\tdep\tgolang.org/x/net\tv0.62.0\th1:fixture\n"
                "\tdep\tgolang.org/x/crypto\tv0.58.1-0.20261009181718-2f1f834330b2\th1:fixture\n"
                "\tbuild\t-trimpath=true\n\tbuild\tCGO_ENABLED=0\n\tbuild\tGOARCH=amd64\n"
                "\tbuild\tGOOS=linux\n\tbuild\tvcs.revision=" + profile.source_commit + "\n").encode()
        rows = [line for line in info.decode().splitlines() if line.startswith("\tdep\t")]
        manifest["build"]["binaryModuleRows"] = len(rows)
        manifest["build"]["binaryModuleInventorySha256"] = image.sha(("\n".join(rows) + "\n").encode())
        modules = b"github.com/seaweedfs/seaweedfs\ngolang.org/x/net v0.62.0\n"
        module_graph = b"github.com/seaweedfs/seaweedfs golang.org/x/net@v0.62.0\n"
        for name, data in {"weed": self.binary, "LICENSE": licence, "compiled-deps": graph_raw,
                           "build-info.txt": info, "root-modules.txt": modules,
                           "root-module-graph.txt": module_graph}.items():
            (self.build / name).write_bytes(data)
        source = {"upstreamCommit": profile.source_commit, "patchedTree": "a" * 40,
                  "orderedPatchCount": 29, "rootLockfilesSha256": manifest["build"]["rootLockfilesSha256"],
                  "patchManifestSha256": image.sha((ROOT / candidate.MANIFEST_PATH).read_bytes()),
                  "moduleEvidenceSha256": {"root-modules.txt": image.sha(modules),
                                           "root-module-graph.txt": image.sha(module_graph)}}
        (self.build / "build-source.json").write_bytes(image.canonical(source))

    def prepare(self, findings=None):
        candidate.package(self.build, self.out)
        record = image.verify_layout(self.out, profile=self.profile)
        config = json.loads((self.out / "blobs/sha256" / record["configDigest"][7:]).read_bytes())
        scan = {"SchemaVersion": 2, "Trivy": {"Version": "0.70.0"}, "ArtifactName": self.profile.image_tag,
                "Metadata": {"ImageID": record["configDigest"], "ImageConfig": config},
                "Results": [{"Target": "usr/local/bin/weed", "Class": "lang-pkgs", "Type": "gobinary",
                             "Packages": [{"Name": "stdlib", "Version": "v1.27.3"},
                                          {"Name": "golang.org/x/net", "Version": "v0.62.0"},
                                          {"Name": "golang.org/x/crypto", "Version": "v0.58.1-0.20261009181718-2f1f834330b2"},
                                          {"Name": "github.com/seaweedfs/seaweedfs", "Version": "v0.0.0-fixture"}],
                             "Vulnerabilities": findings or []}]}
        (self.out / "fresh-image-scan.json").write_bytes(image.canonical(scan))
        (self.out / "image.spdx.json").write_bytes(image.canonical({
            "spdxVersion": "SPDX-2.3", "documentNamespace": "urn:fixture:spdx",
            "packages": [{"name": p["Name"], "versionInfo": p["Version"]} for p in scan["Results"][0]["Packages"]]
                        + [{"name": "usr/local/bin/weed", "primaryPackagePurpose": "APPLICATION"},
                           {"name": self.profile.image_tag, "primaryPackagePurpose": "CONTAINER"}],
        }))
        (self.out / "daemon-image-id.txt").write_text(record["configDigest"] + "\n")
        (self.out / "version-smoke.txt").write_text("synthetic version fixture\n")
        result = candidate.assess(self.out, record["configDigest"], "b" * 40, 1)
        (self.out / "assessment.json").write_bytes(image.canonical(result))
        candidate.seal_sources(self.out)
        return result

    def zip(self):
        names = sorted(p for p in self.out.rglob("*") if p.is_file()
                       and p.name not in {"SHA256SUMS", "provenance.json"})
        (self.out / "SHA256SUMS").write_text("".join(
            image.sha(p.read_bytes()) + "  " + p.relative_to(self.out).as_posix() + "\n" for p in names))
        (self.out / "provenance.json").write_text('{"fixture":"not-a-signature"}\n')
        path = self.root / "image.zip"
        with zipfile.ZipFile(path, "w") as archive:
            for p in self.out.rglob("*"):
                if p.is_file():
                    archive.write(p, p.relative_to(self.out).as_posix())
        return path

    def test_complete_roundtrip_reproduces_new_profile_without_admission(self):
        result = self.prepare()
        self.assertEqual(result["generation"], 29)
        self.assertEqual(result["vulnerabilitySubgate"], "PASS_RAW")
        self.assertFalse(result["releaseAdmitted"])
        path = self.zip()
        receipt = readback.verify(path, self.root / "readback", readback.file_hash(path), "b" * 40, 1)
        self.assertEqual(receipt["checksumMembersVerified"], 20)
        self.assertEqual(receipt["sourceFilesVerified"], 37)
        self.assertFalse(receipt["publisherSignatureVerifiedByThisScript"])
        self.assertEqual(receipt["targetOperations"], 0)

    def test_foreign_image_profile_is_rejected(self):
        self.prepare()
        with self.assertRaisesRegex(ValueError, "EXACT_OWNER_REVIEWED_BINARY"):
            image.verify_layout(self.out, profile=self.profile._replace(binary_sha="0" * 64))

    def test_wrong_graph_or_binary_fails_packaging(self):
        (self.build / "compiled-deps").write_text("wrong\n")
        with self.assertRaisesRegex(ValueError, "EXACT_STANDARD_PACKAGE_CLOSURE"):
            candidate.package(self.build, self.out)
        self.assertFalse(self.out.exists())

    def test_source_manifest_mismatch_fails_reassessment(self):
        result = self.prepare()
        (self.out / "generation-manifest.json").write_text("{}")
        with self.assertRaisesRegex(ValueError, "EXACT_GENERATION_MANIFEST"):
            candidate.assess(self.out, result["configDigest"], "b" * 40, 1)

    def test_module_evidence_tampering_is_denied(self):
        result = self.prepare()
        (self.out / "root-modules.txt").write_text("changed")
        with self.assertRaisesRegex(ValueError, "MODULE_EVIDENCE_BINDING"):
            candidate.assess(self.out, result["configDigest"], "b" * 40, 1)

    def test_legacy_module_is_denied_even_with_updated_local_hash(self):
        result = self.prepare()
        path = self.out / "root-modules.txt"
        path.write_text("github.com/aws/aws-sdk-go v1.55.8\n")
        source = json.loads((self.out / "build-source.json").read_bytes())
        source["moduleEvidenceSha256"][path.name] = image.sha(path.read_bytes())
        (self.out / "build-source.json").write_bytes(image.canonical(source))
        with self.assertRaisesRegex(ValueError, "UNMAINTAINED_ROOT_MODULE"):
            candidate.assess(self.out, result["configDigest"], "b" * 40, 1)

    def test_build_info_hash_is_bound(self):
        result = self.prepare()
        (self.out / "build-info.txt").write_text("changed")
        with self.assertRaisesRegex(ValueError, "BUILD_INFO_BINDING"):
            candidate.assess(self.out, result["configDigest"], "b" * 40, 1)

    def test_fresh_high_and_unknown_findings_are_held(self):
        result = self.prepare([{"Severity": "HIGH", "VulnerabilityID": "FIXTURE-HIGH"},
                               {"Severity": "UNKNOWN", "VulnerabilityID": "FIXTURE-UNKNOWN"}])
        self.assertEqual(result["vulnerabilitySubgate"], "HELD_RAW_FINDINGS")
        self.assertEqual(result["appliedApplicabilityDispositions"], [])
        self.assertFalse(result["runtimeAuthorityIssued"])

    def test_partial_or_wrong_version_scan_inventory_is_denied(self):
        result = self.prepare()
        path = self.out / "fresh-image-scan.json"
        original = json.loads(path.read_bytes())
        for mutation in ("omission", "version", "duplicate"):
            changed = copy.deepcopy(original)
            packages = changed["Results"][0]["Packages"]
            if mutation == "omission":
                packages.pop()
            elif mutation == "version":
                packages[-1]["Version"] = "v0.0.0-wrong"
                # Also alter SPDX so the independent completeness check is exercised.
                bom = json.loads((self.out / "image.spdx.json").read_bytes())
                bom["packages"].append({"name": packages[-1]["Name"], "versionInfo": "v0.0.0-wrong"})
                (self.out / "image.spdx.json").write_bytes(image.canonical(bom))
            else:
                packages.append(copy.deepcopy(packages[0]))
            path.write_bytes(image.canonical(changed))
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, "COMPLETE_BINARY_SCAN_INVENTORY"):
                candidate.assess(self.out, result["configDigest"], "b" * 40, 1)

    def test_readback_and_cli_reject_high_critical_unknown_without_output(self):
        result = self.prepare()
        scan_path = self.out / "fresh-image-scan.json"
        scan = json.loads(scan_path.read_bytes())
        for severity in ("HIGH", "CRITICAL", "UNKNOWN"):
            scan["Results"][0]["Vulnerabilities"] = [{"Severity": severity, "VulnerabilityID": "FIXTURE-" + severity}]
            scan_path.write_bytes(image.canonical(scan))
            held = candidate.assess(self.out, result["configDigest"], "b" * 40, 1)
            (self.out / "assessment.json").write_bytes(image.canonical(held))
            path = self.zip()
            output = self.root / ("held-" + severity)
            with self.subTest(severity=severity), self.assertRaisesRegex(ValueError, "UNRESOLVED_RAW_VULNERABILITIES"):
                readback.verify(path, output, readback.file_hash(path), "b" * 40, 1)
            with patch.object(readback.sys, "stderr", io.StringIO()) as stderr:
                code = readback.main([str(path), str(output), readback.file_hash(path), "b" * 40, "1"])
            self.assertEqual(code, 2)
            self.assertIn("UNRESOLVED_RAW_VULNERABILITIES", stderr.getvalue())
            self.assertFalse(output.exists())

    def test_other_patched_tree_is_denied(self):
        result = self.prepare()
        path = self.out / "build-source.json"
        source = json.loads(path.read_bytes())
        source["patchedTree"] = "f" * 40
        path.write_bytes(image.canonical(source))
        with self.assertRaisesRegex(ValueError, "PATCHED_SOURCE_BINDING"):
            candidate.assess(self.out, result["configDigest"], "b" * 40, 1)

    def test_spdx_missing_extra_duplicate_version_and_descriptive_nodes_denied(self):
        result = self.prepare()
        path = self.out / "image.spdx.json"
        original = json.loads(path.read_bytes())
        for mutation in ("missing", "extra", "duplicate", "version", "descriptive"):
            bom = copy.deepcopy(original)
            packages = bom["packages"]
            if mutation == "missing":
                packages.pop(0)
            elif mutation == "extra":
                packages.append({"name": "fixture.invalid/extra", "versionInfo": "v1.0.0"})
            elif mutation == "duplicate":
                packages.append(copy.deepcopy(packages[0]))
            elif mutation == "version":
                packages[0]["versionInfo"] = "v0.0.0-wrong"
            else:
                packages[-1]["name"] = "wrong-container"
            path.write_bytes(image.canonical(bom))
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, "SPDX|SBOM"):
                candidate.assess(self.out, result["configDigest"], "b" * 40, 1)

    def test_archive_digest_mismatch_is_denied_before_unpack(self):
        self.prepare()
        with self.assertRaisesRegex(ValueError, "EXACT_IMAGE_ARTIFACT"):
            readback.verify(self.zip(), self.root / "readback", "0" * 64, "b" * 40, 1)

    def test_archive_member_tamper_and_duplicate_are_denied(self):
        self.prepare()
        original = self.zip()
        with zipfile.ZipFile(original) as archive:
            members = {name: archive.read(name) for name in archive.namelist()}
        members["build-source.json"] = b"{}"
        bad = self.root / "bad.zip"
        with zipfile.ZipFile(bad, "w") as archive:
            for name, data in members.items():
                archive.writestr(name, data)
        dest = self.root / "unpack"
        dest.mkdir()
        with self.assertRaisesRegex(ValueError, "CHECKSUM_MISMATCH"):
            readback.unpack(bad, dest)
        with warnings.catch_warnings(), zipfile.ZipFile(bad, "a") as archive:
            warnings.simplefilter("ignore", UserWarning)
            archive.writestr("build-source.json", b"duplicate")
        with self.assertRaisesRegex(ValueError, "EXACT_UNIQUE_ARCHIVE"):
            readback.unpack(bad, self.root / "unused")

    def test_checksum_paths_and_traversal_are_rejected(self):
        for path in ("../escape", "/absolute", "a\\b", "a/../b"):
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "UNSAFE_OR_DUPLICATE"):
                readback.checksum_map(["0" * 64 + "  " + path])


if __name__ == "__main__":
    unittest.main()
