"""Exercise the stopped discovery controller against a local HTTP Unix socket."""

from collections import deque
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler
import io
import json
from pathlib import Path
import runpy
from socketserver import UnixStreamServer
import subprocess
import sys
import tempfile
from threading import Event, Thread
from types import SimpleNamespace
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1] / "scripts/create-discovery-stopped-candidates-20261111.py"
PREFLIGHT_SOURCE = SOURCE.with_name("read-discovery-stopped-creation-preflight-20261110.py")
CONTROLLER = runpy.run_path(str(SOURCE))
GLOBALS = CONTROLLER["engine"].__globals__
CID = "a" * 64


class EngineHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self):
        self.request.settimeout(4)
        super().setup()

    def respond(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.server.requests.append((self.command, self.path, body))
        status, payload = self.server.responses.popleft()
        self.send_response_only(status)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = do_POST = do_DELETE = respond

    def finish(self):
        super().finish()
        self.server.connection_closed.set()

    def log_message(self, format, *args):
        pass


class StoppedCreationTransportTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="ouf-engine-")
        self.addCleanup(directory.cleanup)
        address = str(Path(directory.name) / "engine.sock")
        server = UnixStreamServer(address, EngineHandler)
        self.server = server
        self.addCleanup(server.server_close)
        server.responses = deque()
        server.requests = []
        server.connection_closed = Event()
        thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(server.shutdown)
        self.enterContext(patch.dict(GLOBALS, DOCKER_SOCKET=address))

    def test_inspect_over_unix_http_and_close_keepalive(self):
        path = f"/containers/{CID}/json"
        self.server.responses.append((200, json.dumps({"Id": CID}).encode()))
        self.assertEqual(CONTROLLER["engine"]("GET", path), {"Id": CID})
        self.assertEqual(self.server.requests, [("GET", "/v1.44" + path, b"")])
        self.assertTrue(self.server.connection_closed.wait(2))

    def test_create_payload_and_empty_delete_response(self):
        path = f"/containers/create?name={CONTROLLER['ADAPTER']}-successor"
        self.server.responses.extend(((201, json.dumps({"Id": CID}).encode()), (204, b"")))
        self.assertEqual(CONTROLLER["engine"]("POST", path, {"Image": "fixture"}), {"Id": CID})
        self.assertIsNone(CONTROLLER["engine"]("DELETE", f"/containers/{CID}"))
        self.assertEqual(self.server.requests, [
            ("POST", "/v1.44" + path, b'{"Image":"fixture"}'),
            ("DELETE", f"/v1.44/containers/{CID}", b""),
        ])

    def test_engine_rejection_closes_connection(self):
        self.server.responses.append((503, b'{"message":"fixture"}'))
        with self.assertRaisesRegex(CONTROLLER["Held"], "^ENGINE_RESPONSE_UNPROVEN$"):
            CONTROLLER["engine"]("GET", "/info")
        self.assertTrue(self.server.connection_closed.wait(2))

    def test_invalid_json_closes_connection(self):
        self.server.responses.append((200, b"{"))
        with self.assertRaises(json.JSONDecodeError):
            CONTROLLER["engine"]("GET", "/info")
        self.assertTrue(self.server.connection_closed.wait(2))

    def test_get_only_accepts_full_container_and_image_ids(self):
        for path in (f"/containers/sha256:{CID}/json", f"/images/{CID}/json",
                     "/containers/abc/json", "/images/sha256:abc/json"):
            with self.subTest(path=path), self.assertRaisesRegex(CONTROLLER["Held"], "ENGINE_OPERATION_OUT_OF_SCOPE"):
                CONTROLLER["engine"]("GET", path)
        self.assertEqual(self.server.requests, [])

    def prepare_plan_fixtures(self):
        adapter = CONTROLLER["ADAPTER"]
        southbound = CONTROLLER["SOUTHBOUND"]
        runtime = "ouf-test-runtime"
        namespaces = ("ouf-backend", "ouf-semantic-provider-internal", "ouf-semantic-provider-egress")
        networks = {name: (str(index) * 64,) for index, name in enumerate(namespaces, start=1)}
        paths = []
        frames = {}
        historical = {}
        work = tempfile.TemporaryDirectory(prefix="ouf-plan-")
        self.addCleanup(work.cleanup)
        routes = Path(work.name) / "apisix.yaml"
        local_config = Path(work.name) / "config.yaml"
        route = {"plugins": {"openid-connect": {
            "client_secret": "$ENV://" + CONTROLLER["OIDC_ENV"], "bearer_only": True,
            "use_jwks": True, "ssl_verify": True, "unauth_action": "deny",
        }}}
        routes.write_bytes(CONTROLLER["canonical"]({"routes": [route, route]}) + b"#END\n")
        local_config.write_bytes(b'{"fixture":true}\n')

        def reply(path, body):
            paths.append(("GET", "/v1.44" + path, b""))
            self.server.responses.append((200, json.dumps(body).encode()))

        for name, cid, digest in ((adapter, "a" * 64, "c" * 64), (southbound, "b" * 64, "d" * 64)):
            historical[name] = (cid, "exited")
            image_id = "sha256:" + digest
            env = ["PATH=/fixture-path", "NORMAL_SETTING=fixture-env-value"]
            config = {"Env": env, "User": "10006:10006", "Entrypoint": ["/fixture"], "Cmd": []}
            host = {"RestartPolicy": {"Name": "no"}, "Runtime": runtime, "Privileged": False,
                    "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges:true"], "ReadonlyRootfs": False}
            old = {"Id": cid, "Image": image_id, "Config": config, "HostConfig": host,
                   "Mounts": [], "State": {"Status": "exited"}}
            if name == southbound:
                config.update(User="636:636", Entrypoint=["/docker-entrypoint.sh"], Cmd=["docker-start"],
                              Env=env + [CONTROLLER["OIDC_ENV"] + "=fixture-oidc",
                                         CONTROLLER["HMAC_ENV"] + "=fixture-hmac"])
                old["Mounts"] = [{"Source": str(file), "Destination": dest, "Type": "bind", "RW": False,
                                  "Propagation": "rprivate"} for file, dest in (
                    (routes, CONTROLLER["ROUTES"]), (local_config, "/usr/local/apisix/conf/config.yaml")
                )]
            frame = {key: old.get(key) for key in CONTROLLER["FRAME_FIELDS"]}
            frame["State"] = {key: old["State"].get(key) for key in CONTROLLER["STATE_FIELDS"]}
            frames[name] = CONTROLLER["sha"](CONTROLLER["canonical"](frame) + b"\n")
            reply(f"/containers/{cid}/json", old)
            reply(f"/images/{image_id}/json", {"Id": image_id, "Config": {"Env": env}})
        reply("/info", {"Runtimes": {runtime: {}}})

        observed = {"blockers": []}
        guard_reads = []

        def read_docker():
            guard_reads.append(True)
            return observed

        preflight = SimpleNamespace(
            HISTORICAL=historical, NETWORKS=networks, boot_units=lambda: ({"docker": True}, True, True, True),
            service_references=lambda: ([], []), read_docker=read_docker,
        )
        review = SimpleNamespace(
            image_review=lambda **kwargs: {"checkSchemaAllowsBearerJwksWithoutSecret": True},
            kernel_review=lambda: {"noswapByKernelVersion": True},
        )
        self.enterContext(patch.dict(
            GLOBALS, HISTORICAL_FRAMES=frames, protected_file=lambda *_: None,
            ROUTES_SHA=CONTROLLER["sha"](routes.read_bytes()),
            CONFIG_SHA=CONTROLLER["sha"](local_config.read_bytes()),
            DOCKER_READBACK_SHA=CONTROLLER["sha"](CONTROLLER["canonical"](observed)),
            load_reader=lambda _, digest: preflight if digest == CONTROLLER["PREFLIGHT_SHA"] else review,
        ))
        return paths, guard_reads, observed

    def run_controller(self, *mode):
        argv = [str(SOURCE), "--preflight", "fixture", "--image-review", "fixture", *mode]
        with patch.object(GLOBALS["os"], "geteuid", return_value=0), patch.object(sys, "argv", argv):
            with redirect_stdout(io.StringIO()) as output:
                exit_code = CONTROLLER["main"]()
        return exit_code, json.loads(output.getvalue())

    def test_plan_reads_both_images_builds_requests_and_runs_guard(self):
        paths, guard_reads, _ = self.prepare_plan_fixtures()
        exit_code, report = self.run_controller("--plan")
        self.assertEqual(exit_code, 0)
        self.assertEqual(report["status"], "PLAN_READY")
        self.assertRegex(report["planSha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(report["createRequests"], 0)
        self.assertEqual(report["candidates"], [])
        self.assertEqual(self.server.requests, paths)
        self.assertEqual(len(guard_reads), 1)
        first, second = report["plannedRequests"]
        self.assertEqual(first["name"], CONTROLLER["ADAPTER"] + "-successor")
        self.assertEqual(second["name"], CONTROLLER["SOUTHBOUND"] + "-successor")
        self.assertEqual(first["networkMode"], "ouf-semantic-provider-internal")
        self.assertEqual(second["networkMode"], "ouf-backend")
        self.assertEqual(set(first["networks"]), {"ouf-semantic-provider-internal", "ouf-semantic-provider-egress"})
        self.assertEqual(set(second["networks"]), set(first["networks"]) | {"ouf-backend"})
        self.assertEqual(second["networks"]["ouf-backend"]["requestedIPv4"], "172.18.0.14")
        for private in ("fixture-env-value", "fixture-oidc", "fixture-hmac", "/ouf-plan-", "client_secret"):
            self.assertNotIn(private, json.dumps(report))

    def test_plan_stops_on_guard_drift_without_writes(self):
        paths, guard_reads, observed = self.prepare_plan_fixtures()
        observed["blockers"].append("fixture-drift")
        exit_code, report = self.run_controller("--plan")
        self.assertEqual(exit_code, 1)
        self.assertEqual(report["reason"], "IP_OR_ALIAS_READBACK_CHANGED")
        self.assertEqual(self.server.requests, paths)
        self.assertEqual(len(guard_reads), 1)

    def test_apply_rejects_changed_plan_without_writes(self):
        paths, _, _ = self.prepare_plan_fixtures()
        exit_code, report = self.run_controller("--apply", "--plan-sha256", "0" * 64)
        self.assertEqual(exit_code, 1)
        self.assertEqual(report["reason"], "PLAN_DIGEST_CHANGED")
        self.assertEqual(report["createRequests"], 0)
        self.assertEqual(self.server.requests, paths)

    def stopped_adapter_readback(self, *, mixed_keys):
        preflight = CONTROLLER["load_reader"](PREFLIGHT_SOURCE, CONTROLLER["PREFLIGHT_SHA"])
        name = CONTROLLER["ADAPTER"]
        transaction = "f" * 32
        host = {"Runtime": "ouf-test-runtime", "RestartPolicy": {"Name": "no"},
                "NetworkMode": "ouf-semantic-provider-internal", "Mounts": []}
        request = {"Image": "sha256:" + "c" * 64, "Env": [], "HostConfig": host}
        networks = {}
        for network, (ip, mac) in CONTROLLER["ENDPOINTS"][name].items():
            key = preflight.NETWORKS[network][0] if mixed_keys and network.endswith("-egress") else network
            networks[key] = {"IPAMConfig": {"IPv4Address": ip}, "Aliases": [name], "MacAddress": mac,
                             "NetworkID": "", "EndpointID": "", "IPAddress": ""}
        row = {"id": CID, "name": f"/{name}-successor", "networks": networks}
        doc = {"Id": CID, "Name": row["name"], "Image": request["Image"],
               "Config": {"Env": [], "Labels": {CONTROLLER["OWNER_LABEL"]: transaction}},
               "State": {"Status": "created", "Running": False, "Pid": 0, "StartedAt": "0001-01-01T00:00:00Z"},
               "HostConfig": host, "RestartCount": 0, "Mounts": [], "NetworkSettings": {"Networks": networks}}
        self.server.responses.append((200, json.dumps(doc).encode()))

        rows = [{"id": cid, "name": "/" + role, "state": state, "pid": 0, "running": False,
                 "restartPolicy": "no", "composeProject": None, "composeService": None, "networks": {}}
                for role, (cid, state) in preflight.HISTORICAL.items()]
        docker_networks = [
            {"Name": network, "Id": network_id, "Driver": "bridge", "Scope": "local", "Containers": {},
             "IPAM": {"Driver": "default", "Config": [{"Subnet": next(iter(targets)).rsplit(".", 1)[0] + ".0/24"}]}}
            for network, (network_id, targets) in preflight.NETWORKS.items()
        ]
        self.enterContext(patch.object(preflight, "containers", side_effect=lambda: rows))
        self.enterContext(patch.object(preflight, "command", return_value=json.dumps(docker_networks)))
        self.enterContext(patch.object(preflight, "boot_units", return_value=({"docker": True}, True, True, True)))
        self.enterContext(patch.object(preflight, "service_references", return_value=([], [])))
        baseline = preflight.read_docker()
        self.assertEqual(baseline["blockers"], [])
        self.enterContext(patch.dict(GLOBALS, DOCKER_READBACK_SHA=CONTROLLER["sha"](CONTROLLER["canonical"](baseline))))
        rows.append(row)
        return preflight, request, transaction

    def test_mixed_network_keys_rejected_by_inspect_and_second_guard(self):
        preflight, request, transaction = self.stopped_adapter_readback(mixed_keys=True)
        with self.assertRaisesRegex(CONTROLLER["Held"], "^CANDIDATE_NETWORK_SET_CHANGED$"):
            CONTROLLER["inspect_created"](CID, CONTROLLER["ADAPTER"], request, transaction)
        with self.assertRaisesRegex(CONTROLLER["Held"], "^FIRST_CANDIDATE_NETWORK_STATE_CHANGED$"):
            CONTROLLER["guard"](preflight, {"id": CID, "name": CONTROLLER["ADAPTER"] + "-successor"})

    def test_named_network_keys_keep_egress_reservation_visible_to_second_guard(self):
        preflight, request, transaction = self.stopped_adapter_readback(mixed_keys=False)
        candidate = CONTROLLER["inspect_created"](CID, CONTROLLER["ADAPTER"], request, transaction)
        egress = preflight.read_docker()["networks"]["ouf-semantic-provider-egress"]
        self.assertEqual([claim["id"] for claim in egress["targets"]["172.22.0.3"]["containerClaims"]], [CID])
        CONTROLLER["guard"](preflight, candidate)

    def test_subprocess_failure_after_first_create_retains_id(self):
        runtime = "ouf-test-runtime"
        self.server.responses.extend((
            (200, json.dumps({"Runtimes": {runtime: {}}}).encode()),
            (201, json.dumps({"Id": CID}).encode()),
        ))
        review = SimpleNamespace(
            image_review=lambda **kwargs: {"checkSchemaAllowsBearerJwksWithoutSecret": True},
            kernel_review=lambda: {"noswapByKernelVersion": True},
        )

        def guard(_preflight, first):
            if first:
                subprocess.run([sys.executable, "-I", "-B", "-c", "raise SystemExit(7)"],
                               check=True, capture_output=True)

        request = {"HostConfig": {"Runtime": runtime}}
        plan_sha = CONTROLLER["sha"](CONTROLLER["canonical"](
            {name: request for name in CONTROLLER["ENDPOINTS"]}
        ))
        with patch.dict(GLOBALS, load_reader=lambda *_: review, guard=guard,
                        build_request=lambda *_: request,
                        inspect_created=lambda *_: {"state": "created", "neverStarted": True}):
            exit_code, report = self.run_controller("--apply", "--plan-sha256", plan_sha)
        self.assertEqual(exit_code, 1)
        self.assertEqual(report["status"], "HELD")
        self.assertEqual(report["reason"], "CalledProcessError")
        self.assertEqual(report["createRequests"], 1)
        self.assertEqual([row["id"] for row in report["candidates"]], [CID])
        self.assertFalse(report["replayAllowed"])
        self.assertEqual([method for method, _, _ in self.server.requests], ["GET", "POST"])


if __name__ == "__main__":
    unittest.main()
