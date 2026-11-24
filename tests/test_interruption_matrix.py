"""Executable review matrix. Use --write locally to refresh after reviewing the diff."""
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from contextlib import ExitStack, contextmanager
from copy import deepcopy
from functools import partial
import hashlib
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from interruption_sweep import sweep
import test_gateway_release as gateway
import test_module_release as modules
import test_module_release_mcp as mcp
import test_privileged_executor_database as database
from test_privileged_executor import mandate, pipeline, store

MATRIX = Path(__file__).with_name("interruption_matrix.json")


@contextmanager
def fixture(case):
    obj = case()
    try:
        obj.setUp()
        yield obj
    finally:
        obj.doCleanups()


def gateway_admin_boundary(f):
    """Run the scoped HTTP client against the same in-memory APISIX resource store."""
    import gateway_admin
    engine = Mock()
    engine.inspect.return_value = {"Id": "a"*64, "State": {"Running": True, "Pid": 1, "StartedAt": "fixture"}}
    original = gateway_admin.generation(engine, "fixture")
    def guard():
        f.assertEqual(gateway_admin.generation(engine, "fixture"), original)
    client = gateway.Admin("127.0.0.1", 9180, "/fixture", gateway.SECRET, guard)
    connection = f.enterContext(patch.object(gateway_admin.http.client, "HTTPConnection")).return_value

    def http(method, path, body, headers):
        f.assertEqual(headers["X-API-KEY"], gateway.SECRET)
        kind, *ids = path.removeprefix("/fixture/").split("/")
        def entry(ident, value):
            return {"key": "/apisix/" + kind + "/" + ident, "value": {"id": ident, **value}}
        status = 200
        if not ids:
            f.assertEqual((method, kind), ("GET", "routes"))
            rows = [entry(k, v) for k, v in f.admin.list_routes().items()]
            result = {"list": rows, "total": len(rows)}
        else:
            ident, = ids
            row = dict(kind=kind, id=ident)
            if method == "GET":
                value = f.admin.get(row)
                status = 404 if value is None else 200
            else:
                f.assertIn(method, ("PUT", "DELETE"))
                value = f.admin.write(row, json.loads(body) if method == "PUT" else None)
            result = entry(ident, value) if value is not None else {"message": "Key not found"}
        response = connection.getresponse.return_value
        response.status = status
        response.read.return_value = gateway.encoded(result)

    connection.request.side_effect = http
    f.enterContext(patch.object(gateway.operation, "connect", side_effect=lambda _: gateway.nullcontext((client, original))))


def gateway_scenario(trace, version, returning=False):
    with fixture(gateway.Phases) as f:
        gateway_admin_boundary(f)
        if version == 2:
            key = ("routes", "a-legacy")
            f.admin.data[key] = f.select_retirements(key[1])
        baseline = deepcopy(f.admin.data)
        expected = deepcopy(baseline)
        package = f.package.return_value[1]
        for row in package["resources"]:
            expected[row["kind"], row["id"]] = row["body"]
        for row in package.get("retired", []):
            del expected[row["kind"], row["id"]]

        def phase(req):
            review = authorize(req, f.cfg, f.root, int(req["phase"] != "plan"))
            return gateway.operation.GatewayRelease(f.cfg, f.root, req).execute(review, gateway.SECRET)

        def apply(run):
            req = f.new_plan_request(run)
            plan = phase(req)
            result = phase(dict(req, phase="apply", digest=plan["digest"]))
            f.assertEqual(result["status"], "APPLIED")
            f.assertEqual(f.admin.data, expected)
            return dict(f.return_req(result), releaseRun=run)

        def restore(req):
            f.assertEqual(phase(req)["status"], "RETURNED")
            f.assertEqual(f.admin.data, baseline)
            return "RETURNED"

        applied = None
        def release(run):
            nonlocal applied
            applied = apply(run)
            return "RESUMED"

        # Every write must change a live resource and be preceded by a GET of it.
        get, write = f.admin.get, f.admin.write
        last_get = None
        def read_resource(resource):
            nonlocal last_get
            last_get = resource["kind"], resource["id"]
            return get(resource)
        f.admin.get = read_resource
        def checked_write(resource, value):
            nonlocal last_get
            key = resource["kind"], resource["id"]
            f.assertEqual(last_get, key)
            last_get = None
            f.assertNotEqual(f.admin.data.get(key), value)
            return write(resource, value)
        f.admin.write = checked_write
        if returning:
            req = apply(gateway.REQ["run"])
            def recover():
                head = store.read(f.root / "gateway-head")
                if head is None:
                    # A completed return is observable with the original snapshot.
                    f.assertEqual(phase(f.new_plan_request("72"))["status"], "PLANNED")
                    f.assertEqual(f.admin.data, baseline)
                    return "RETURNED"
                if head["status"] == "PENDING":
                    req2 = apply("72")
                    return restore(dict(req2, run="73"))
                return restore(dict(req, run="72"))
            trace.transaction(f.root, lambda: restore(req), recover)
        else:
            def recover_apply():
                nonlocal applied
                head_file = f.root / "gateway-head"
                head = store.read(head_file) if head_file.exists() else None
                if head and head["status"] == "APPLIED":
                    receipt = store.read(f.root / head["run"] / "gateway.apply.result")
                    f.assertEqual(receipt, head)
                    observed = phase(f.new_plan_request("72"))
                    f.assertTrue(all(row["action"] in ("unchanged", "absent") for row in observed["changes"]))
                    applied = dict(f.return_req(receipt), releaseRun=head["run"])
                    return "RESUMED"
                return release("72")
            trace.transaction(f.root, lambda: release(gateway.REQ["run"]), recover_apply)
            f.assertTrue(all(n == 1 for n in Counter(f.admin.writes).values()))
            # Each recovered release must still own the original return baseline.
            restore(applied)


def module_scenario(trace, mode):
    spring = mode == "spring"
    with fixture(modules.ReleaseTest if spring else mcp.Release) as f:
        if spring:
            dispatch, req = f.governed_dispatch()
            f.rt.flyway_peer = {"postgresCid": "3"*64}
            scripts = [dict(version=str(n), script=f"V{n}__fixture.sql", type="SQL", checksum=n, success=True)
                       for n in (1, 2)]
            history = {"peer":"3"*64, "db":"42", "history":scripts[:1]}
            f.enterContext(patch.object(mcp.operation.flyway, "inventory", return_value=scripts))
            f.enterContext(patch.object(mcp.operation.flyway, "observe", return_value=history))
            signal = f.rt.signal
            def flyway_signal(cid):
                signal(cid)
                if cid == modules.NEW:
                    history["history"].append(scripts[1])
            f.rt.signal = flyway_signal
            def call(phase, stamp, run, count):
                req.update(phase=phase, run=run, digest=stamp)
                return dispatch(count)
        else:
            req = f.req
            def call(phase, stamp, run, count):
                return f.call(phase, stamp, run=run, approved=count > 0)
        if mode == "none":
            # Exercise the detached receipt publication with a deterministic signing boundary.
            import module_receipt
            f.enterContext(patch.object(store, "trusted", side_effect=lambda path, **kw: Path(path)))
            public = f.root / "fixture.der"
            public.write_bytes(module_receipt.ED25519_SPKI + bytes(32))
            f.p["receiptSigning"] = dict(publicKey=dict(path=str(public), sha256=hashlib.sha256(public.read_bytes()).hexdigest()),
                                         privateKey=str(f.root / "fixture.key"))
            f.enterContext(patch.object(module_receipt, "trusted", side_effect=lambda path, **kw: Path(path)))
            signatures = []
            def openssl(argv, **kwargs):
                if "pkey" in argv:
                    return Mock(returncode=0, stdout=public.read_bytes())
                body = Path(argv[argv.index("-in") + 1]).read_bytes()
                signature = hashlib.sha512(body).digest()
                if "-sign" in argv:
                    signatures.append(signature)
                    f.assertEqual(signatures.count(signature), 1)
                    return Mock(returncode=0, stdout=signature)
                verified = Path(argv[argv.index("-sigfile") + 1]).read_bytes() == signature
                return Mock(returncode=int(not verified))
            f.enterContext(patch.object(module_receipt.subprocess, "run", side_effect=openssl))
        if mode == "dedicated":
            f.dedicated()
        if mode == "error":
            f.rt.fault = "handler"

        def ready(cid):
            doc = f.rt.inspect(f.p["container"])
            f.assertEqual(doc["Id"], cid)
            f.assertTrue(doc["State"]["Running"])
            f.assertTrue(mcp.operation.ready(f.rt, doc, f.p["readiness"]))
            return "RESUMED" if cid == modules.NEW else "RETURNED"

        def release(run):
            request = dict(req, run=run, phase="plan")
            plan = call("plan", mandate.intent(request), run, 0)
            result = call("apply", plan["digest"], run, 1)
            if result["status"] == "GATED":
                result = call("migrate", result["digest"], run, 2)
            f.assertEqual(result["status"], "READY")
            return ready(modules.NEW)

        def classify(fn):
            try:
                return fn()
            except mandate.Held as exc:
                f.assertIn("owner=" + f.p["module"], str(exc))
                f.assertIn("residual=container=", str(exc))
                intents = [p for p in f.root.glob("*/*.json") if len(p.parent.name) == 64 and
                           (p.name.endswith(("-intent.json", "-signal.json")) or
                            p.name in ("restore-start.json", "migration-review-consumed.json"))]
                latest = max(intents, key=lambda p: (p.stat().st_mtime_ns, p.name), default=None)
                f.assertIn(" claim=" + (latest.name if latest else "none"), str(exc))
                for role in ("container", "retainedName", "failedName"):
                    doc = f.rt.inspect(f.p[role], missing=True)
                    value = doc["State"]["Status"] + "(" + doc["Id"] if doc else "absent"
                    f.assertIn(role + "=" + value, str(exc))
                receipts = [store.read(path) for path in f.root.glob("*/receipt.json")]
                if any(r.get("rollback") == "ROLLED_BACK" for r in receipts):
                    return ready(modules.OLD)
                return "HELD " + str(exc).split()[0]

        if mode == "return":
            stamp = f.planned()["digest"]
            f.assertEqual(f.call("apply", stamp)["status"], "READY")
            def rollback(run):
                result = f.call("rollback", stamp, run=run)
                f.assertEqual(result["status"], "ROLLED_BACK")
                return ready(modules.OLD)
            trace.transaction(f.root, lambda: rollback("2"), lambda: classify(lambda: rollback("3")))
        else:
            def recover():
                completed = list(f.root.glob("*/receipt.json"))
                if completed and not (f.root / (f.p["module"] + ".lock")).exists():
                    # A fresh plan is read-only after the durable terminal receipt.
                    def observe_completion():
                        row = store.read(completed[0])
                        try:
                            call("plan", mandate.intent(dict(req, run="2", phase="plan")), "2", 0)
                        except mandate.Held as exc:
                            # A validated signed predecessor already running this exact CI image.
                            if str(exc).split()[0] != "ALREADY_INSTALLED":
                                raise
                        if row["status"] == "READY":
                            return ready(modules.NEW)
                        f.assertEqual(row["rollback"], "ROLLED_BACK")
                        return ready(modules.OLD)
                    return classify(observe_completion)
                return classify(lambda: release("2"))
            trace.transaction(f.root, lambda: classify(lambda: release("1")), recover)
        for event in ("create", "signal:1", "signal:2", "migrate"):
            f.assertLessEqual(f.rt.events.count(event), 1, event)


def database_scenario(trace):
    with fixture(database.SemanticDatabase) as f:
        profile = dict(containerName="semantic", ipv4="fixture", image="image")
        cfg = dict(originalProfile=profile, queue={}, socket="/fixture", readinessPort=80, semanticDatabase={}, commit="b"*40)
        gen = dict(cid="cid", pid=1, startedAt="start")
        def run(run_id):
            req = dict(phase="plan", operation="semantic-database-migration", commit="b"*40, run=run_id, attempt="1")
            req["digest"] = mandate.intent(req)
            for phase in ("plan", "apply"):
                req["phase"] = phase
                review = authorize(req, cfg, f.root, int(phase == "apply"))
                op = pipeline.Cutover(cfg, f.root, req)
                op.engine = Mock()
                op.engine.inspect.return_value = dict(Id="cid", Image="image", State={"Pid":1, "StartedAt":"start"})
                op.engine.process.side_effect = lambda cid, target, kind: (
                    gen if (cid, target, kind) == ("cid", profile, "APPLICATION_RUNNING") else None)
                op.current_version = lambda: 29
                op.authority = lambda: "chain"
                op.supervisor = lambda version: {"semanticIngress": {"profile": profile}}
                result = op.database_operation(review)
                req["digest"] = result["digest"]
            f.assertEqual(result["readiness"], "UP")
            f.assertEqual(f.database.writes, 3)
            f.assertEqual(f.database.history()["history"], f.rows)
            return "RESUMED"
        with patch.object(database.db, "Database", return_value=f.database), patch.object(
                pipeline, "live_manifest", return_value=f.manifest), patch.object(
                pipeline.http.client, "HTTPConnection") as http:
            response = http.return_value.getresponse.return_value
            response.status = 200
            response.read.return_value = b'{"status":"UP"}'
            trace.transaction(f.root, lambda: run("101"), lambda: run("102"))
            http.return_value.request.assert_called_with("GET", "/actuator/health/readiness")


def a2_scenario(trace, mode):
    from test_privileged_executor import RoundTrip, runbooks, semantic
    from types import SimpleNamespace
    from contextlib import nullcontext
    import successor_image
    from test_privileged_executor_successor_image import SemanticArtifact

    case = RoundTrip()
    def exercise(f):
        next_release = mode.startswith("next")
        direction = "return" if "return" in mode else "forward"
        books_by_run = {}
        f.cfg["probe"] = dict.fromkeys(("C_R3_INPUTS", "C_R3_INPUTS_SHA256", "C_INSTALLATION_PROFILE",
                                        "C_INSTALLATION_PROFILE_SHA256"), "fixture")
        image = None
        def configure_image(stack, key, previous=None):
            nonlocal image
            image = stack.enter_context(fixture(SemanticArtifact))
            if previous is not None:
                image.spec["predecessorMigrations"] = previous
                image.blob = modules.artifact(image.spec, image.root, image_env=["ADDED=yes"],
                                              migrations=previous + ["V14__discovery.sql"])
                image.obj["digest"] = "sha256:" + image.spec["ci"]["zipSha256"]
            f.cfg[key] = image.spec
            f.engine.call.return_value["Id"] = image.spec["ci"]["imageId"]

        signals = []
        ingress = []
        f.cfg["readinessPort"] = 80
        # This host changes state only at an explicit simulated effect.
        elapsed = 0.0
        def sleep(seconds):
            nonlocal elapsed
            elapsed += seconds
        timer = SimpleNamespace(monotonic=lambda: elapsed, sleep=sleep, time_ns=pipeline.time.time_ns)
        def reconnect_missing(cid, name, endpoints, networks, *, rename, missing):
            doc = f.containers[cid]
            if rename:
                case.assertIsNone(f.engine.inspect(name, True))
                doc["Name"] = "/" + name
            case.assertEqual(doc["Name"], "/" + name)
            for net in missing:
                case.assertNotIn(net, doc["NetworkSettings"]["Networks"])
                doc["NetworkSettings"]["Networks"][net] = deepcopy(original_nets[net])
            return cid
        def generation(cid):
            return sum(call.args[0] == cid for call in f.engine.start_gate.call_args_list)
        process = f.engine.process.side_effect
        f.engine.process.side_effect = lambda cid, profile, kind: {
            **process(cid, profile, kind), "startedAt": generation(cid)}
        original_nets = deepcopy(f.containers[f.old]["NetworkSettings"]["Networks"])
        f.engine.reconnect_missing.side_effect = reconnect_missing

        def verified(sup, profile, cid, seq):
            case.assertFalse(f.head.waiting)
            case.assertEqual((sup["semanticIngress"]["profile"], seq), (profile, f.head.version))
            case.assertTrue(f.containers[cid]["State"]["Running"])
            ingress.append((cid, seq))
            return nullcontext(None)

        def send(fd, signum):
            case.assertIs(signum, sig.SIGUSR1)
            cid, = [cid for cid, kind in f.process_kinds.items()
                    if f.containers[cid]["State"]["Running"] and kind == "GATE_WAITING"]
            signals.append((cid, generation(cid)))
            case.assertEqual(len(signals), len(set(signals)))
            f.process_kinds[cid] = "APPLICATION_RUNNING"

        def dispatch(run, way, cid, *, following=False, gate=False, completed=None):
            req = dict(run=run, attempt="1", commit=f.cfg["commit"], phase="plan", queue="empty", direction=way)
            if following:
                req["release"] = "next"
            req["digest"] = mandate.intent(req)
            review = authorize(req, f.cfg, f.root, 0)
            c, pending, call = f.make_cutover(run, way, cid, following)
            c.ready = pipeline.Cutover.ready.__get__(c)
            books_by_run[run] = c.books
            collisions = 2 if mode == "renewal" else 0

            def book(op, seq, approved=None):
                nonlocal collisions
                if op == "stop" and approved and collisions:
                    collisions -= 1
                    raise runbooks.RenewalCollision()
                if not approved:
                    proposal = call(op, seq)
                    proposal["outputDirectory"] = str(f.root / ("host-" + run + "-" + op + "-" + str(collisions)))
                    proposal["planSha256"] = mandate.digest({k:v for k,v in proposal.items() if k != "planSha256"})
                    return proposal
                proposal = pending[op]
                if op == "stop":
                    result = f.stop(c.books, seq, proposal, None)
                else:
                    result = call(op, seq, approved)
                result.update(status=runbooks.SUCCESS[op], planSha256=approved)
                out = Path(proposal["outputDirectory"])
                out.mkdir(exist_ok=True)
                (out / "result.json").write_text(json.dumps(result))
                return result

            # Run the actual runbook adapter and its evidence writer. Only the
            # child process, script resolution and host renewal are simulated.
            def invoke(home, op, seq, approved=None, preflight=False):
                adapter = runbooks.Books(f.cfg, home)
                adapter.probe_source = c.books.probe_source
                adapter.binding = lambda role, version: Path(role)
                def launch(*args, **kwargs):
                    try:
                        data = book(op, seq, approved)
                    except runbooks.RenewalCollision:
                        denial = dict(status="HELD", reason="R3_PLAN_DIGEST_CHANGED", doNotRerunApply=False,
                                      outputCreated=False, dockerStopRequests=0)
                        return SimpleNamespace(stdout=json.dumps(denial).encode(), returncode=1)
                    auth = dict(sequence=seq, decision="OPERATE")
                    if not approved:
                        data.update(status="PLAN_READY", secretsRead=0)
                        if op == "probe":
                            data["observation"]["r3"] = {"authorization": auth}
                            if preflight:
                                data["observation"]["semantic"]["containerId"] = f.engine.inspect(c.name)["Id"]
                    if op in ("stop", "start"):
                        data.setdefault("lastObservation", {"authorization": auth})
                    if op == "issue" and approved:
                        data.update(sequence=seq, signaturesIssued=1, decision="OPERATE")
                    return SimpleNamespace(stdout=json.dumps(data).encode(), returncode=0)
                with patch.object(runbooks.subprocess, "run", side_effect=launch):
                    return adapter.call(op, seq, approved)
            c.books.call.side_effect = partial(invoke, c.path)
            def make_book(cfg, path):
                if path.name == "probe-preflight":
                    preflight = Mock()
                    preflight.call.side_effect = partial(invoke, path, preflight=True)
                    return preflight
                return books_by_run[path.name]
            c.probe_preflight = pipeline.Cutover.probe_preflight.__get__(c)
            def advance(phase, digest, count):
                c.req.update(phase=phase, digest=digest)
                return c.execute(authorize(c.req, f.cfg, f.root, count))

            with patch.object(pipeline, "Books", side_effect=make_book):
                try:
                    first = c.execute(review)
                except mandate.Held:
                    if not completed:
                        raise
                if completed:
                    pointer = store.read(f.root / ("completed-forward" if way == "forward" else "last-closed"))
                    case.assertEqual(pointer["run"], completed)
                    return terminal(c, cid, way, completed)
                stage = advance("apply", first["digest"], 1)
                if gate:
                    case.assertEqual(c.engine.process(cid, c.record("stage")["profile"], "GATE_WAITING")["cid"], cid)
                    return
                count = 2
                if "migrationCount" in stage:
                    stage = advance("migrate", stage["digest"], count)
                    count += 1
                done = advance("sign", stage["digest"], count)
                case.assertEqual((done["ingress"], done["readiness"]), ("VERIFIED", "UP"))
                return terminal(c, cid, way, run)

        def terminal(c, cid, way, run):
            stage = store.read(f.root / run / "stage")
            case.assertEqual(stage["cid"], cid)
            c.ready(cid, stage["profile"], stage["generation"])
            case.assertIn((cid, f.head.version), ingress)
            c.check_verified(c.supervisor(f.head.version), stage["profile"], cid, f.head.version)
            case.assertEqual(f.engine.inspect(c.name)["Id"], cid)
            return "RESUMED" if way == "forward" else "RETURNED"

        with patch.object(pipeline, "verified", side_effect=verified), patch.object(
                pipeline, "signal_once", semantic.signal_once), patch.object(semantic, "os", wraps=os) as syscalls, patch.object(
                semantic, "signal") as sig, patch.object(pipeline.http.client, "HTTPConnection") as http, patch.object(
                pipeline, "stop", runbooks.stop), patch.object(runbooks, "issued_probe_inputs", return_value={"C_R3_INPUTS":"fixture"}), ExitStack() as stack:
            stack.enter_context(patch.object(pipeline, "time", timer))
            if next_release or mode == "image":
                configure_image(stack, "successorImage")
                stack.enter_context(patch.object(pipeline, "admit", side_effect=lambda cfg, log, _:
                                                  successor_image.admit(cfg, log, image.get)))
            syscalls.pidfd_open = Mock(return_value=42)
            syscalls.close = Mock()
            sig.pidfd_send_signal.side_effect = send
            response = http.return_value.getresponse.return_value
            response.status = 200
            response.read.return_value = b'{"status":"UP"}'
            cid = f.new
            run = "101"
            if next_release:
                dispatch("103", "forward", f.new)
                predecessor, cid = f.configure_next()
                configure_image(stack, "nextSuccessorImage", ["V12__previous.sql", "V13__adoption.sql"])
                run = "202"
                if direction == "return":
                    dispatch(run, "forward", cid, following=True, gate=mode == "next_return_unsigned")
                    run, cid = "210", predecessor
            elif direction == "return":
                dispatch(run, "forward", cid, gate=True)
                run, cid = "102", f.old

            def recover():
                completed = run if (f.root / run / "result").exists() else None
                try:
                    return dispatch("401", direction, cid, following=next_release, completed=completed)
                except mandate.Held as exc:
                    context = getattr(exc, "public_context", "")
                    case.assertIn("owner=semantic residual=service=", context)
                    case.assertIn(" claim=", context)
                    for role, name in (("service", f.cfg["originalProfile"]["containerName"]),
                                       ("retained", f.cfg["retainedName"] + ("-v28" if next_release else "")),
                                       ("failed", f.cfg["failedName"])):
                        doc = f.engine.inspect(name, True)
                        residual = f"{doc['State']['Status']}({doc['Id']})" if doc else "absent"
                        case.assertIn(role + "=" + residual, context)
                    return "HELD " + str(exc)

            trace.transaction(f.root, lambda: dispatch(run, direction, cid, following=next_release), recover)
            case.assertLessEqual(f.engine.create.call_count, 2 if next_release else 1)
            case.assertEqual(len({seq for op, seq in f.counts if op == "issue"}),
                             sum(op == "issue" for op, seq in f.counts))

    case.round_trip(True, migrations=["V13__fixture.sql"] if mode == "image" or mode.startswith("next") else None,
                    exercise=exercise)


def authorize(req, cfg, root, count):
    workflow = {"gateway-release": ".github/workflows/gateway-release.yml",
                "semantic-database-migration": ".github/workflows/semantic-database-migration.yml"}.get(
                    req.get("operation"), mandate.WORKFLOW)
    policy = dict(cfg, repositoryId=17, environment="private", environmentId=4, reviewerIds=[8],
                  branch="protected", runner="fixture")
    run = dict(id=int(req["run"]), run_attempt=1, event="workflow_dispatch", status="in_progress",
               head_sha=req["commit"], head_branch=policy["branch"], path=workflow,
               repository={"id":17}, head_repository={"id":17})
    user = {"type":"User", "id":8}
    env = dict(id=4, name="private", protection_rules=[dict(type="required_reviewers",
               reviewers=[dict(type="User", reviewer=user)])])
    job = dict(status="in_progress", runner_name="fixture", name=req["phase"] + " " + req["digest"])
    reviews = [dict(state="approved", user=user, environments=[env])] * count
    return mandate.authorize(req, policy, Mock(side_effect=[run, {"jobs":[job]}, {"protected":True,
                             "commit":{"sha":req["commit"]}}, env, reviews]), root)


SCENARIOS = {
    **{"a2_" + mode: partial(a2_scenario, mode=mode) for mode in
       ("forward", "image", "return", "next_forward", "next_return_unsigned", "next_return_signed", "renewal")},
    **{"module_" + mode: partial(module_scenario, mode=mode)
       for mode in ("none", "dedicated", "spring", "error", "return")},
    "gateway_v1": partial(gateway_scenario, version=1),
    "gateway_v2": partial(gateway_scenario, version=2),
    "gateway_return": partial(gateway_scenario, version=2, returning=True),
    "semantic_database": database_scenario,
}


@unittest.skipUnless(sys.platform == "linux" and os.getenv("OUF_A2_NATIVE_ENGINE") == "1", "isolated Engine opt-in")
class NativeDetachRecovery(unittest.TestCase):
    def test_a2_detach_receipt_then_new_dispatch_to_gate(self):
        import uuid
        from test_privileged_executor import RoundTrip, semantic
        from interruption_sweep import ProcessLost

        def exercise(f):
            engine = semantic.Engine(os.environ["OUF_A2_FIXTURE_SOCKET"])
            self.assertIn("ouf.a2.fixture=true", engine.call("GET", "info")["Labels"])
            image = os.environ["OUF_A2_FIXTURE_IMAGE"]
            successor = engine.call("GET", "images/ouf-ci-gate:a2-successor/json")
            base = engine.call("GET", f"images/{image}/json")["Config"]
            for key in ("Entrypoint", "Labels", "Env"):
                self.assertNotEqual(base.get(key), successor["Config"].get(key))
            name = "a2-fixture-" + uuid.uuid4().hex
            net = engine.call("POST", "networks/create", {"Name": name, "Driver": "bridge", "Internal": True,
                              "IPAM": {"Config": [{"Subnet": "192.0.2.0/27"}]}})["Id"]
            self.addCleanup(engine.call, "DELETE", "networks/" + net)
            request = dict(Image=image, User="10001:10001", Entrypoint=semantic.ENTRY,
                           Cmd=["java", "-XX:MaxRAMPercentage=75", "-jar", "/app/application.jar"],
                           Env=["OUF_SCHEMA_GOV_ENABLED=true", "OUF_DISCOVERY_WORKER_ENABLED=false"],
                           HostConfig=dict(NetworkMode=name, RestartPolicy={"Name":"no","MaximumRetryCount":0}),
                           NetworkingConfig={"EndpointsConfig":{name:{"Aliases":[name],
                                                               "IPAMConfig":{"IPv4Address":"192.0.2.3"}}}})
            old = engine.create(name, request, image)
            self.addCleanup(engine.call, "DELETE", f"containers/{old}?force=1")
            engine.call("POST", f"containers/{old}/start")
            row = engine.inspect(old)
            profile = f.head.profile
            profile.update(containerName=name, network=name, networkId=net, image=image, ipv4="192.0.2.3",
                           configurationSha256=semantic.semantic_configuration(row))
            generation = pipeline.until(lambda: engine.process(old, profile, "GATE_WAITING"), 10, "BASELINE_GATE")
            semantic.signal_once(engine, store.Journal(f.root / "baseline"), old, profile, generation)
            pipeline.until(lambda: engine.process(old, profile, "APPLICATION_RUNNING"), 15, "BASELINE_JAVA")
            f.cfg.update(retainedName=name + "-saved", failedName=name + "-returned")
            f.cfg["successorImage"]["ci"]["imageId"] = successor["Id"]
            creates = []
            def create(*args):
                cid = engine.create(*args)
                creates.append(cid)
                self.addCleanup(engine.call, "DELETE", f"containers/{cid}?force=1")
                return cid
            roles = f.engine.inspect.side_effect
            f.engine.inspect.side_effect = lambda ident, absent=False: (
                roles(ident, absent) if ident in f.cfg["roleCids"] else engine.inspect(ident, absent))
            f.engine.call.side_effect = engine.call
            f.engine.detach.side_effect = engine.detach
            f.engine.create.side_effect = create
            f.engine.process.side_effect = engine.process
            f.engine.start_gate.side_effect = engine.start_gate

            def dispatch(run, crash):
                req = dict(run=run, attempt="1", phase="plan", commit=f.cfg["commit"], queue="empty", direction="forward")
                req["digest"] = mandate.intent(req)
                review = authorize(req, f.cfg, f.root, 0)
                c, pending, call = f.make_cutover(run, "forward", f.new, False)
                c.observe = lambda cid, profile, sup: {"cid":engine.inspect(cid)["Id"], "profile":profile}
                def book(op, seq, approved=None):
                    if op == "issue" and approved is None:
                        plan = c.record("plan")
                        target = semantic.allocated_profile(plan, creates[0])
                        proposal = dict(previousHead={"sequence":seq-1,"sha256":"previous"},
                                        payload={"sequence":seq,"supersedes":"previous"},
                                        compositionInputHashes={"semanticProfile":mandate.digest(target)}, privateKeysRead=0)
                        return dict(proposal, planSha256=mandate.digest(proposal))
                    return call(op, seq, approved)
                c.books.call.side_effect = book
                plan = c.execute(review)
                c.req.update(phase="apply", digest=plan["digest"])
                review = authorize(c.req, f.cfg, f.root, 1)
                effect = c.log.effect
                def boundary(name, claim, action):
                    result = effect(name, claim, action)
                    if name == "detach" and crash:
                        raise ProcessLost
                    return result
                c.log.effect = boundary
                c.execute(review)
                return c.record("stage")

            admitted = {"ci": f.cfg["successorImage"]["ci"], "migrations": ["V12__baseline.sql"], "newMigrations":[]}
            with patch.object(pipeline, "admit", return_value=admitted):
                with self.assertRaises(ProcessLost):
                    dispatch("101", True)
                self.assertTrue((f.root / "101/detach.receipt").is_file())
                self.assertFalse((f.root / "101/create.claim").exists())
                self.assertEqual(creates, [])
                stage = dispatch("102", False)
            self.assertEqual(creates, [stage["cid"]])
            self.assertEqual(engine.inspect(f.cfg["retainedName"])["Id"], old)
            self.assertEqual(stage["generation"], engine.process(stage["cid"], stage["profile"], "GATE_WAITING"))

        RoundTrip().round_trip(True, migrations=[], exercise=exercise)


def check_scenario(name):
    expected = json.loads(MATRIX.read_bytes())[name]
    rows = sweep(SCENARIOS[name], expected)
    unittest.TestCase().assertEqual(expected, rows, name)
    return len(rows) // 2


class InterruptionMatrix(unittest.TestCase):
    selected = ()
    results = None

    @classmethod
    def setUpClass(cls):
        if len(cls.selected) > 1:
            # Each process owns its mocks, host boundaries and temporary journals.
            pool = cls.enterClassContext(ProcessPoolExecutor(max_workers=min(4, os.cpu_count() or 1)))
            cls.results = {name: pool.submit(check_scenario, name) for name in cls.selected}

    def test_scenarios(self):
        self.assertEqual(set(json.loads(MATRIX.read_bytes())), set(SCENARIOS))


def matrix_test(name):
    def check(self):
        count = self.results[name].result() if self.results and name in self.results else check_scenario(name)
        print(f"{name}: {count} punti", flush=True)
    return check


for name in SCENARIOS:
    setattr(InterruptionMatrix, "test_" + name, matrix_test(name))


def load_tests(loader, tests, pattern):
    names = loader.getTestCaseNames(InterruptionMatrix)
    InterruptionMatrix.selected = [name for name in SCENARIOS if "test_" + name in names]
    return tests


def generate_scenario(name):
    return sweep(SCENARIOS[name])


def write_matrix():
    lines = []
    with ProcessPoolExecutor(max_workers=min(4, os.cpu_count() or 1)) as pool:
        for name, rows in zip(SCENARIOS, pool.map(generate_scenario, SCENARIOS)):
            formatted = ",\n".join("    " + json.dumps(row) for row in rows)
            lines.append(f'  "{name}": [\n{formatted}\n  ]')
            print(f"{name}: {len(rows)//2} punti", flush=True)
    MATRIX.write_text("{\n" + ",\n".join(lines) + "\n}\n", encoding="utf-8")


if __name__ == "__main__":
    if sys.argv[1:] == ["--write"]:
        write_matrix()
    else:
        unittest.main()
