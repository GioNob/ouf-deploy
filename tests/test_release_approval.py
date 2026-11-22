"""Run the checked-in workflow clients with public executor fixtures, entirely offline."""
from contextlib import chdir, redirect_stdout
from io import StringIO
import json
import os
from pathlib import Path
import runpy
import shlex
import sys
import tempfile
import unittest
from unittest.mock import patch
from subprocess import CompletedProcess

import yaml


ROOT = Path(__file__).resolve().parents[1]
STAMP = "a" * 64
SECRET = "private-fixture-marker"
ROW = dict(version="21", script="V21__change.sql", type="SQL", checksum=-7, success=True)
SUFFIX = "… vedi il riepilogo del job"


class Approval(unittest.TestCase):
    def client(self, workflow, phase, result=None, **env):
        spec = yaml.safe_load((ROOT / ".github/workflows" / (workflow + ".yml")).read_text(encoding="utf-8"))
        steps = spec["jobs"][phase]["steps"]
        command = next(step["run"] for step in steps if step.get("id") in ("intent", "call"))
        env = dict(GITHUB_RUN_ID="70", GITHUB_RUN_ATTEMPT="1", GITHUB_SHA="b" * 40,
                   DIGEST=STAMP, PHASE=phase, REVIEW_TOKEN=SECRET) | env
        with tempfile.TemporaryDirectory() as tmp, chdir(ROOT):
            summary, output = Path(tmp, "summary"), Path(tmp, "output")
            env.update(GITHUB_STEP_SUMMARY=str(summary), GITHUB_OUTPUT=str(output))
            response = CompletedProcess([], 0, json.dumps(result).encode())
            with patch.dict(os.environ, env, clear=True), redirect_stdout(StringIO()) as log, \
                    patch("subprocess.run", return_value=response) as call:
                if "<<'PY'" in command:
                    code = command.split("<<'PY'\n")[1].rsplit("\nPY", 1)[0]
                    exec(compile(code, workflow, "exec"), {})
                else:
                    args = shlex.split(command)
                    script = next(i for i, arg in enumerate(args) if arg.endswith(".py"))
                    with patch.object(sys, "argv", args[script:]):
                        runpy.run_path(args[script], run_name="__main__")
            if phase == "intent":
                call.assert_not_called()
            else:
                call.assert_called_once()
                self.assertEqual(call.call_args.args[0], ["/usr/bin/sudo", "-n", "--", "/usr/local/sbin/ouf-a2"])
            report = summary.read_text(encoding="utf-8") if summary.exists() else ""
            outputs = dict(line.split("=", 1) for line in output.read_text().splitlines())
            self.assertNotIn(SECRET, log.getvalue() + report + str(outputs))
            return log.getvalue().splitlines(), report, outputs

    def review(self, run, phase, *facts):
        notices, report, outputs = run
        self.assertEqual(len(notices), 1)
        prefix = f"::notice title=Da approvare: {phase}::"
        self.assertTrue(notices[0].startswith(prefix))
        self.assertTrue(report.startswith(f"**Cosa approvi con il job {phase}**\n"))
        self.assertIn("%0A", notices[0])
        self.assertIn(outputs["digest"], notices[0])
        self.assertLessEqual(len(notices[0].encode()), 4096)
        for fact in facts:
            self.assertIn(fact, notices[0])
            self.assertIn(fact, report)
        return outputs

    def test_command_encoding_and_utf8_boundary(self):
        approval = runpy.run_path(str(ROOT / ".github/scripts/release_review.py"))["approval"]
        for payload, truncated in [("%0A\r\n::error::", False), ("%0A\r\n::error::" + "è%" * 4096, True)]:
            with self.subTest(truncated=truncated), redirect_stdout(StringIO()) as log:
                summary = StringIO()
                approval(summary, "apply", STAMP, [payload, "ULTIMA"])
                line, = log.getvalue().splitlines()
                self.assertTrue(line.startswith("::notice title=Da approvare: apply::Job apply " + STAMP))
                self.assertIn("%0A%250A%0D%0A%3A%3Aerror%3A%3A", line)
                self.assertLessEqual(len(line.encode()), 4096)
                self.assertEqual(line.endswith(SUFFIX), truncated)
                self.assertTrue(summary.getvalue().startswith("**Cosa approvi con il job apply**"))
                self.assertIn("ULTIMA", summary.getvalue())

    def test_gateway_release_and_return(self):
        wf = "gateway-release"
        inputs = dict(action="release", sourceRun="11", sourcePr="7", artifact="12", sourceCommit="c"*40)
        changes = [dict(kind="routes", id="a", action="create"),
                   dict(kind="routes", id="b", action="update", paths=["upstream.nodes"]),
                   dict(kind="routes", id="c", action="unchanged")]
        result = dict(digest=STAMP, status="PLANNED", counts=dict(create=1, update=1, unchanged=1),
                      changes=changes, private=SECRET)
        self.review(self.client(wf, "plan", result, DISPATCH_INPUTS=json.dumps(inputs), DIGEST=""), "apply",
                    "routes/a: nuova", "routes/b: modificata (upstream.nodes)", "routes/c: invariata")
        back = dict(action="return", releaseRun="65", receipt=STAMP)
        self.review(self.client(wf, "intent", DISPATCH_INPUTS=json.dumps(back)), "return",
                    "Ripristino dello snapshot del rilascio 65")
        self.assertEqual(self.client(wf, "return", dict(digest=STAMP, status="RETURNED"),
                                     DISPATCH_INPUTS=json.dumps(back))[0], [])

    def test_module_release_gates(self):
        for module in ("onboarding", "mcp", "udp", "ingestion"):
            with self.subTest(module=module):
                wf = module + "-module-release"
                plan = dict(status="PLANNED", digest=STAMP, private=SECRET,
                            databaseReview=dict(migrations=[dict(version=21, checksum=STAMP, body=SECRET)], migrationsSha256=STAMP),
                            candidateReview=dict(candidateCmdSha256="c"*64, predecessorCmdSha256="d"*64,
                                                 removedArgs=[], envOperations={"OTHER": SECRET}, account=SECRET))
                outputs = self.review(self.client(wf, "plan", plan, MODULE=module), "apply",
                                      f"Modulo {module} · stato PLANNED", "version=21", "c"*64, "d"*64,
                                      "ID immagine candidata e predecessore: non esposti")
                stage = dict(status="GATED", digest=STAMP, databaseReview=dict(before="f"*64, pending=[ROW]))
                self.review(self.client(wf, "apply", stage, MODULE=module, PLAN_MIGRATIONS=outputs["migrations"]),
                            "migrate", "stato GATED", "Migrazioni nuove: 1", ROW["script"], "checksum=-7", "f"*64)
                stage.pop("databaseReview")
                self.review(self.client(wf, "apply", stage, MODULE=module, PLAN_MIGRATIONS=outputs["migrations"]),
                            "migrate", "version=21", "checksum=" + STAMP)
                self.review(self.client(wf, "apply", stage, MODULE=module), "migrate",
                            "Elenco delle migrazioni non esposto")
                self.assertEqual(self.client(wf, "apply", dict(status="READY", digest=STAMP), MODULE=module)[0], [])
                if module != "onboarding":
                    self.review(self.client(wf, "intent", MODULE=module, RETURN_PLAN=STAMP), "rollback", "Modulo "+module)
                    self.assertEqual(self.client(wf, "intent", MODULE=module, RETURN_PLAN="")[0], [])
                    rolled = dict(status="ROLLED_BACK", digest=STAMP)
                    self.assertEqual(self.client(wf, "rollback", rolled, MODULE=module)[0], [])

    def test_module_image_ids_in_approval_and_summary(self):
        images = dict(candidateImageId="sha256:" + "1" * 64, predecessorImageId="sha256:" + "2" * 64)
        labels = ("Immagine candidata: " + images["candidateImageId"],
                  "Immagine in esercizio da sostituire: " + images["predecessorImageId"])
        for module in ("onboarding", "mcp", "udp", "ingestion"):
            wf = module + "-module-release"
            for phase, status, gate in (("plan", "PLANNED", "apply"), ("apply", "GATED", "migrate"),
                                        ("apply", "READY", None)):
                with self.subTest(module=module, status=status):
                    run = self.client(wf, phase, dict(status=status, digest=STAMP, **images), MODULE=module)
                    if gate:
                        self.review(run, gate, *labels)
                    else:
                        self.assertEqual(run[0], [])
                        for label in labels:
                            self.assertIn(label, run[1])

    def test_module_image_ids_reject_malformed_or_incomplete_pair(self):
        valid = "sha256:" + "a" * 64
        plan = dict(status="PLANNED", digest=STAMP, candidateImageId=valid, predecessorImageId=valid)
        for key in ("candidateImageId", "predecessorImageId"):
            for value in (None, 42, STAMP, "sha256:" + "A" * 64, valid[:-1], valid + "a", valid + "\n"):
                with self.subTest(key=key, value=value):
                    result = {**plan, key: value}
                    with self.assertRaisesRegex(SystemExit, key):
                        self.client("udp-module-release", "plan", result, MODULE="udp")
            with self.assertRaisesRegex(SystemExit, key):
                partial = {k: v for k, v in plan.items() if k != key}
                self.client("udp-module-release", "plan", partial, MODULE="udp")

    def test_legacy_module_executor_reports_missing_images(self):
        message = "ID immagine candidata e predecessore: non esposti dall’esecutore"
        for phase, status, gate in (("plan", "PLANNED", "apply"), ("apply", "GATED", "migrate")):
            run = self.client("udp-module-release", phase, dict(status=status, digest=STAMP), MODULE="udp")
            self.review(run, gate, message)
        run = self.client("udp-module-release", "apply", dict(status="READY", digest=STAMP), MODULE="udp")
        self.assertIn(message, run[1])

    def test_semantic_cutover_all_gates(self):
        wf = "semantic-a2-cutover"
        env = dict(RELEASE="next", DIRECTION="forward", QUEUE="inventory", WORKER_PROOF="true")
        image = "sha256:" + "c"*64
        plan = dict(digest=STAMP, migrationMode="governed-sql", imageId=image, zipSha256="d"*64,
                    inventorySha256="e"*64, queueCount=1, queueDigest=STAMP,
                    queue=[dict(ref=STAMP, state="PENDING", tenant=SECRET)], returnAfterIssue="available", returnSequence=32)
        outputs = self.review(self.client(wf, "plan", plan, **env), "apply", image, "d"*64, "e"*64,
                              "governed-sql", "PENDING", "emissione 32")
        env["PLAN_REVIEW"] = outputs["context"]
        stage = dict(digest=STAMP, migrationCount=1, migrationsSha256="f"*64, pending=[ROW], imageId=image)
        outputs = self.review(self.client(wf, "apply", stage, **env), "migrate", image, "d"*64, "governed-sql",
                              "Migrazioni nuove: 1", "f"*64, ROW["script"])
        self.review(self.client(wf, "apply", dict(digest=STAMP), **env), "sign", image)
        env["PLAN_REVIEW"] = outputs["context"]
        self.review(self.client(wf, "migrate", dict(digest=STAMP), **env), "sign", image, "f"*64)
        done = dict(digest=STAMP, ingress="VERIFIED", readiness="UP", worker="on")
        self.review(self.client(wf, "sign", done, **env), "proof", "Ingresso VERIFIED", "worker on")
        env["WORKER_PROOF"] = "false"
        self.assertEqual(self.client(wf, "sign", done, **env)[0], [])

    def test_semantic_database_migration(self):
        wf = "semantic-database-migration"
        result = dict(digest=STAMP, pending=[ROW], head=29)
        self.review(self.client(wf, "plan", result, OPERATION=wf), "apply", ROW["script"],
                    "migrazioni pendenti: 1", "CRC32 Flyway -7", "testa R3 29")
        result = dict(digest=STAMP, lastVersion=21, head=29, readiness="UP")
        self.assertEqual(self.client(wf, "apply", result, OPERATION=wf)[0], [])

    def test_clients_bound_notice_and_keep_full_summary(self):
        # CR/LF cannot appear in a validated Gateway field path. The JSON key
        # itself can contain percent and double colon, even in a valid plan.
        key = '["x%::"]'
        paths = [key] + ["x" * 75 + str(i) for i in range(60)] + ["ULTIMA"]
        result = dict(digest=STAMP, status="PLANNED", counts=dict(create=0, update=1, unchanged=0),
                      changes=[dict(kind="routes", id="a", action="update", paths=paths)])
        inputs = dict(action="release", sourceRun="11", sourcePr="7", artifact="12", sourceCommit="c"*40)
        gateway = self.client("gateway-release", "plan", result, DISPATCH_INPUTS=json.dumps(inputs), DIGEST="")
        self.review(gateway, "apply", "routes/a: modificata")
        self.assertIn("x%25%3A%3A", gateway[0][0])
        self.assertTrue(gateway[0][0].endswith(SUFFIX))
        self.assertIn("ULTIMA", gateway[1])

        first = dict(ROW, script="A%\r\n::B")
        rows = [first, *[ROW] * 180, dict(ROW, script="ULTIMA")]
        for module in ("onboarding", "mcp", "udp", "ingestion"):
            with self.subTest(module=module):
                stage = dict(status="GATED", digest=STAMP, databaseReview=dict(pending=rows))
                run = self.client(module+"-module-release", "apply", stage, MODULE=module)
                self.check_long_review(run, "migrate")
        semantic = dict(digest=STAMP, pending=rows, migrationCount=len(rows), migrationsSha256=STAMP)
        run = self.client("semantic-a2-cutover", "apply", semantic, DIRECTION="forward", QUEUE="empty",
                          RELEASE="next", WORKER_PROOF="false")
        self.check_long_review(run, "migrate")
        wf = "semantic-database-migration"
        self.check_long_review(self.client(wf, "plan", dict(digest=STAMP, pending=rows, head=29), OPERATION=wf), "apply")

    def check_long_review(self, run, phase):
        self.review(run, phase)
        self.assertIn("A%25%0D%0A%3A%3AB", run[0][0])
        self.assertTrue(run[0][0].endswith(SUFFIX))
        self.assertIn("ULTIMA", run[1])
