"""D-052 synthetic routes, custody, and retained-frame regression tests."""

from contextlib import nullcontext
import copy
import os
from pathlib import Path, PurePosixPath
import re
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.semantic_provider_routes import b1, custody as C, publication as P, routes as R
import test_semantic_provider_b1_recipes as legacy
from tools.semantic_successor_recipes import creation_launch as L


PLACEHOLDER = "SYNTHETIC_SECRET_PLACEHOLDER"



ADAPTER_FIXTURE_HOST = "fixture-adapter.invalid"

# Same shape as ouf-api-gateway tools/materialize_semantic_provider(_tls).py (real route source).
STRIP_LUA = ("return function(conf,ctx) for name,_ in pairs(ngx.req.get_headers(0)) do "
             "if name:lower():sub(1,6)=='x-ouf-' then ngx.req.clear_header(name) end end end")
ADMIT_LUA = ("return function(conf,ctx)\nlocal cjson = require('cjson.safe')\n"
             "local d=require('resty.openssl.digest').new('sha256')\n"
             "local key=os.getenv(RECEIPT_KEY_ENV)\n"
             "local h=require('resty.openssl.hmac').new(key,'sha256')\n"
             "ngx.req.set_header('X-OUF-R', require('resty.string').to_hex(d:final('x')))\nend")


def api_bytes(post_lua=ADMIT_LUA):
    upstream = {"type": "roundrobin", "scheme": "https", "nodes": {ADAPTER_FIXTURE_HOST + ":9443": 1},
                "upstream_host": ADAPTER_FIXTURE_HOST, "pass_host": "rewrite",
                "timeout": {"connect": 3, "send": 4, "read": 25}, "retries": 0}
    plugins = {"client-control": {"max_body_size": 65536},
               "limit-count": {"count": 20, "time_window": 60, "key_type": "var", "key": "remote_addr",
                               "policy": "local", "rejected_code": 429},
               "serverless-pre-function": {"phase": "rewrite", "functions": [STRIP_LUA]},
               "openid-connect": {"client_id": "synthetic-client", "client_secret": PLACEHOLDER,
                                  "discovery": "https://issuer.example:8444/test/.well-known/openid-configuration",
                                  "issuer": "https://issuer.example/test", "ssl_verify": True,
                                  "bearer_only": True, "use_jwks": True, "unauth_action": "deny",
                                  "required_scopes": ["gateway.test"],
                                  "claim_validator": {"audience": {"required": True, "match_with_client_id": True}},
                                  "set_access_token_header": False, "set_id_token_header": False,
                                  "set_userinfo_header": False},
               "serverless-post-function": {"phase": "access", "functions": [post_lua]}}
    lab = {"ouf-managed": "true", "ouf-installation": "fixture", "ouf-mediation": "semantic-provider-transport-v1"}
    return encode({"routes": [{"id": "s", "uri": "/search", "methods": ["POST"], "labels": lab,
                               "upstream": upstream, "plugins": plugins},
                              {"id": "f", "uri": "/fetch", "methods": ["GET"], "labels": lab,
                               "upstream": upstream, "plugins": plugins}],
                   "ssls": [{"id": "sb", "type": "server", "status": 1, "snis": ["gateway.example"],
                             "cert": "TEST_CERT", "key": "TEST_KEY", "ssl_protocols": ["TLSv1.2", "TLSv1.3"],
                             "labels": {"ouf-managed": "true"}}]})


def encode(doc):
    return R.canonical(doc) + b"\n" + R.TRAILER


def inputs(destination="192.0.2.82", port=10449):
    south = {"ipv4": "192.0.2.1", "bindingRef": "southbound-internal", "bridge": "br-test"}
    adapter = {"ipv4": destination, "bindingRef": "adapter-internal", "bridge": "br-test"}
    peer = {"containerId": "a" * 64, "networkBindings": [adapter]}
    static = {"purpose": "GATEWAY_ADAPTER", "source": south["ipv4"], "destination": destination,
              "protocol": "tcp", "port": port}
    flow = static | {"peerIngress": {"kind": "CREATED_CANDIDATE", "declaration": peer,
                                     "bindingRef": adapter["bindingRef"]}}
    coordinator = {"kernel": {"generation": 2, "providerFlowMatch": "ORIGINAL_TUPLE", "staticFlows": [static]}}
    return ({"candidate": {"networkBindings": [south], "transport": [flow]}},
            {"candidate": peer}, coordinator)


class Routes(unittest.TestCase):
    def test_projection_only_network_fields(self):
        view = R.project("/fixture/apisix.yaml", api_bytes())
        encoded = R.canonical(view)
        for secret in ("ssls", "client_secret", PLACEHOLDER, "TEST_CERT", "TEST_KEY", "openid-configuration"):
            self.assertNotIn(secret.encode(), encoded)
        route = view["routes"][0]
        self.assertEqual(route["openid-connect"]["discovery"], {"host": "issuer.example", "port": 8444})
        self.assertEqual(route["openid-connect"]["issuer"], {"host": "issuer.example", "port": 443})
        self.assertEqual(route["upstream"]["timeout"], {"connect": 3, "send": 4, "read": 25})
        self.assertEqual((view["sha256"], view["bytes"]), (R.sha(api_bytes()), len(api_bytes())))

    def test_serverless_lua_closed_module_set_without_network(self):
        view = R.project("/fixture/apisix.yaml", api_bytes())
        self.assertEqual([s["plugin"] for s in view["routes"][0]["serverless"]],
                         ["serverless-pre-function", "serverless-post-function"])
        self.assertNotIn(b"resty.openssl", R.canonical(view))
        for lua in ("return function() local s=ngx.socket.tcp() end",
                    "return function() local h=require('resty.http') end",
                    "return function() local x=require('socket') end",
                    "return function() ngx.location.capture('/x') end",
                    "return function() os.execute('id') end",
                    "return function() local r=require(name) end",
                    "return function() loadstring('x')() end"):
            with self.subTest(lua=lua), self.assertRaisesRegex(R.Held, R.UNPROVEN):
                R.project("/fixture/apisix.yaml", api_bytes(post_lua=lua))

    def test_invalid_and_unknown_egress_denied(self):
        raw = api_bytes()
        for altered in (raw[:-1], raw.replace(b'"ssl_verify":true', b'"ssl_verify":true,"ssl_verify":true'),
                        raw.replace(b'"read":25', b'"read":1e999'), b'\xff' + raw):
            with self.subTest(altered=altered[:20]), self.assertRaises(R.Held):
                R.project("/fixture/apisix.yaml", altered)
        for field, value in [("upstream", {"discovery_type": "dns"}), ("openid-connect", {"proxy_opts": {}}),
                             ("plugins", {"http-logger": {"uri": "https://example.test"}}),
                             ("limit-count", {"policy": "redis"}), ("top", {"upstreams": []}),
                             ("route", {"upstream_id": "unknown"})]:
            doc = R.parse_routes(raw)
            route = doc["routes"][0]
            plugins = route["plugins"]
            objs = {"top": doc, "route": route, "upstream": route["upstream"],
                    "plugins": plugins, "openid-connect": plugins["openid-connect"], "limit-count": plugins["limit-count"]}
            objs[field].update(value)
            with self.subTest(field=field), self.assertRaisesRegex(R.Held, R.UNPROVEN):
                R.project("/fixture/apisix.yaml", encode(doc))

    def test_only_two_nodes_change_using_declared_ip_and_port(self):
        original = R.parse_routes(api_bytes())
        raw = encode(original)
        # A route towards any other peer is an undeclared egress: the closed set is denied.
        unrelated = copy.deepcopy(original["routes"][0])
        unrelated["upstream"].update(upstream_host="other.example", nodes={"other.example:7443": 1})
        mixed = copy.deepcopy(original); mixed["routes"].append(unrelated)
        literal = copy.deepcopy(original)
        for route in literal["routes"]:
            route["upstream"].update(upstream_host="192.0.2.9", nodes={"192.0.2.9:9443": 1})
        for bad in (mixed, literal):
            with self.assertRaisesRegex(R.Held, "ADAPTER_ROUTE_SET_UNPROVEN"):
                R.regenerate("/fixture/apisix.yaml", encode(bad), R.sha(encode(bad)),
                             R.declared_destination(*inputs()))
        for address, number in (("192.0.2.82", 10449), ("198.51.100.23", 11431)):
            with self.subTest(address=address, port=number):
                destination = R.declared_destination(*inputs(address, number))
                updated, diff, before, after = R.regenerate("/fixture/apisix.yaml", raw, R.sha(raw), destination)
                new = R.parse_routes(updated)
                for index, change in enumerate(diff):
                    self.assertEqual(change["path"], f"/routes/{index}/upstream/nodes")
                    self.assertEqual(new["routes"][index]["upstream"]["nodes"], {f"{address}:{number}": 1})
                    new["routes"][index]["upstream"]["nodes"] = change["before"]
                self.assertEqual(len(diff), 2)
                self.assertEqual(encode(new), raw)
                self.assertEqual((before["sha256"], after["sha256"]), (R.sha(raw), R.sha(updated)))

    def test_unpinned_or_nonidentical_bytes_denied(self):
        raw = b" " + api_bytes()
        target = R.declared_destination(*inputs())
        with self.assertRaisesRegex(R.Held, "ROUTES_BYTE_IDENTITY_UNPROVEN"):
            R.regenerate("/fixture/apisix.yaml", raw, R.sha(raw), target)
        with self.assertRaisesRegex(R.Held, "ROUTES_SHA256_MISMATCH"):
            R.regenerate("/fixture/apisix.yaml", raw, "a" * 64, target)

    def test_declaration_requires_independent_internal_bindings_and_g2(self):
        for index in range(5):
            south, adapter, coordinator = copy.deepcopy(inputs())
            transport = south["candidate"]["transport"]
            static = coordinator["kernel"]["staticFlows"]
            if index == 0:
                transport.append(copy.deepcopy(transport[0]))
            elif index == 1:
                adapter["candidate"]["networkBindings"][0]["bridge"] = "foreign"
            elif index == 2:
                static[0]["port"] += 1
            elif index == 3:
                transport[0]["protocol"] = static[0]["protocol"] = "udp"
            else:
                coordinator["kernel"]["generation"] = 1
            with self.subTest(index=index), self.assertRaisesRegex(R.Held, "DECLARED_ROUTE_FLOW_UNPROVEN"):
                R.declared_destination(south, adapter, coordinator)


class FakeDocker:
    def __init__(self, source):
        self.rows = {cid: {"Id": cid, "State": copy.deepcopy(b1.CREATED_STATE),
                          "HostConfig": {"RestartPolicy": {"Name": "no"}}, "Mounts": []}
                     for cid in P.CIDS.values()}
        self.rows[P.CIDS["southbound"]]["Mounts"].append(
            {"Source": str(source), "Destination": P.TARGET, "RW": False, "Type": "bind"})

    def ids(self):
        return sorted(self.rows)

    def inspect(self, cid):
        return copy.deepcopy(self.rows[cid])


class Safety(unittest.TestCase):
    def test_mounts_and_states(self):
        source = PurePosixPath(P.SOURCE.as_posix())
        docker = FakeDocker(source)
        authority = ({"decision": "OPERATE", "sequence": 1, "sha256": "a" * 64},) * 2
        journal = {"state": "QUIESCED", "leaseAuthorized": False, "startAuthorized": False}

        def provenance(_):
            return {"authorization": P.checked_head(authority), "lease": P.checked_lease(R.canonical(journal), {})}

        with (patch.object(P, "observe_r3", side_effect=provenance),
              patch.object(P, "SOURCE", source), patch.object(C, "mount_source", side_effect=PurePosixPath)):
            P.safety(docker, {})
            journal["state"] = "LEASE_READY"
            with self.assertRaisesRegex(R.Held, "R3_LEASE_NOT_QUIESCED"):
                P.safety(docker, {})
            journal["state"] = "QUIESCED"
            authority[0]["decision"] = "STOP"
            with self.assertRaisesRegex(R.Held, "R3_OPERATE_HEAD_UNPROVEN"):
                P.safety(docker, {})
            authority[0]["decision"] = "OPERATE"
            state = docker.rows[P.CIDS["adapter"]]["State"]
            state.update(Status="running", Running=True, Pid=123)
            with self.assertRaisesRegex(R.Held, "PROVIDER_NOT_STOPPED"):
                P.safety(docker, {})
            state.update(b1.CREATED_STATE)
            stranger = "f" * 64
            docker.rows[stranger] = copy.deepcopy(docker.rows[P.CIDS["southbound"]])
            docker.rows[stranger]["State"].update(Status="running", Running=True, Pid=123)
            for mounted in (source, source.parent):
                docker.rows[stranger]["Mounts"][0]["Source"] = str(mounted)
                with self.assertRaisesRegex(R.Held, "ROUTES_MOUNT_IN_USE"):
                    P.safety(docker, {})


NATIVE = sys.platform == "linux" and os.geteuid() == os.getegid() == 0
if os.environ.get("OUF_D052_NATIVE") == "1" and not NATIVE:
    raise RuntimeError("D-052 native tests require Linux root:root")


@unittest.skipUnless(NATIVE, "requires native Linux root:root filesystem custody")
class NativePublication(unittest.TestCase):
    def setUp(self):
        self.addCleanup(os.umask, os.umask(0o077))
        directory = tempfile.TemporaryDirectory(dir="/root")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.source = self.root / "apisix.yaml"
        self.claim = self.root / "claim"
        self.original = api_bytes()
        C.write_once(self.source, self.original, P.SOURCE_META)
        for name, value in (("SOURCE", self.source), ("OLD_SHA", R.sha(self.original)), ("CLAIM", self.claim)):
            patcher = patch.object(P, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        declarations = {}
        for name, doc in zip(("southbound", "adapter", "coordinator"), inputs()):
            path = self.root / (name + ".json")
            C.write_document(path, doc)
            declarations[name] = path, R.sha(path.read_bytes())
        for name, kwargs in [("DECLARATIONS", {"new": declarations}), ("fenced", {"side_effect": nullcontext}),
                             ("observe_r3", {"return_value": {"sequence": 1, "state": "QUIESCED"}})]:
            patcher = patch.object(P, name, **kwargs)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.docker = FakeDocker(self.source)

    def test_publication_backup_and_exact_restore(self):
        proposed = P.execute("plan", docker=self.docker)
        self.assertFalse(self.claim.exists())
        with self.assertRaisesRegex(R.Held, "PLAN_DIGEST_MISMATCH"):
            P.execute("apply", "a" * 64, docker=self.docker)
        inode = self.source.stat().st_ino
        result = P.execute("apply", proposed["planSha256"], docker=self.docker)
        self.assertNotEqual(inode, self.source.stat().st_ino)
        self.assertEqual(R.sha(self.source.read_bytes()), result["newSha256"])
        self.assertEqual(C.read(self.claim / "original.apisix.yaml"), self.original)
        self.assertNotIn(PLACEHOLDER.encode(), R.canonical(result))
        self.assertEqual(b1.published_routes(R.sha((self.claim / "result.json").read_bytes()))[0],
                         result["newSha256"])
        self.assertEqual(P.execute("restore", proposed["planSha256"], docker=self.docker)["restoredSha256"],
                         R.sha(self.original))
        self.assertEqual(C.read(self.source, metadata=P.SOURCE_META), self.original)
        with self.assertRaisesRegex(R.Held, "RESTORE_ALREADY_RECORDED"):
            P.execute("restore", docker=self.docker)

    def test_custody_hash_owner_and_mode_denials(self):
        for name, mutate, undo, reason in [
                ("hash", lambda: self.source.write_bytes(b"changed"), lambda: self.source.write_bytes(self.original),
                 "INPUT_SHA256_MISMATCH"),
                ("owner", lambda: os.chown(self.source, 637, 636), lambda: os.chown(self.source, 636, 636),
                 "FILE_CUSTODY_UNPROVEN"),
                ("mode", lambda: self.source.chmod(0o644), lambda: self.source.chmod(0o600),
                 "FILE_CUSTODY_UNPROVEN")]:
            with self.subTest(field=name):
                mutate()
                try:
                    with self.assertRaisesRegex(R.Held, reason):
                        P.execute("plan", docker=self.docker)
                    self.assertFalse(self.claim.exists())
                finally:
                    undo()

    def test_interrupted_publication_restores_from_prepared_claim(self):
        plan = P.execute("plan", docker=self.docker)
        original = C.write_document  # captured before patching, else it is the mock itself
        with patch.object(C, "write_document", wraps=original) as write:

            def fail_receipt(path, doc):
                if path.name == "result.json":
                    raise OSError("synthetic interruption")
                original(path, doc)

            write.side_effect = fail_receipt
            with self.assertRaises(OSError):
                P.execute("apply", plan["planSha256"], docker=self.docker)
        self.assertFalse((self.claim / "result.json").exists())
        self.assertNotEqual(self.source.read_bytes(), self.original)
        P.execute("restore", docker=self.docker)
        self.assertEqual(self.source.read_bytes(), self.original)


class Recipes(unittest.TestCase):
    def test_retained_state_is_distinct_from_exact_a2_config(self):
        for role in b1.ROLES:
            request = legacy.synthetic_request(role)
            row = legacy.synthetic_inspect(role, request)
            config = row["Config"]
            row.update(State=copy.deepcopy(b1.CREATED_STATE), Path=config["Entrypoint"][0],
                       Args=config["Entrypoint"][1:] + config["Cmd"])
            prior = {"containerId": row["Id"], "name": row["Name"], "image": row["Image"],
                     "transaction": config["Labels"][b1.OWNER_LABEL]}
            row["State"].update(Status="exited", StartedAt="2026-10-11T11:22:33.123Z",
                                FinishedAt="2026-10-11T11:23:33Z", ExitCode=143)
            launch = L.creation_launch(request, role, legacy.baseline[role]["launch"]["manifest"].get("tmpfs"),
                                       hash_source=legacy.fake_source)
            # Previously started and stopped: accepted; network/runtime-only views are not compared.
            self.assertEqual(b1.retained_frame(row, prior)["status"], "exited")
            self.assertEqual(b1.retained_config(row, role, launch), {"recipeLaunchEqual": True})
            drifted = copy.deepcopy(row); drifted["NetworkSettings"]["Networks"] = {}
            self.assertEqual(b1.retained_config(drifted, role, launch), {"recipeLaunchEqual": True})
            for change, code in (
                    (lambda r: r["HostConfig"].update(Memory=r["HostConfig"]["Memory"] + 1),
                     "RETAINED_DOCKER_CONFIGURATION_CHANGED"),
                    (lambda r: r["HostConfig"].update(ReadonlyRootfs=not r["HostConfig"]["ReadonlyRootfs"]),
                     "RETAINED_DOCKER_CONFIGURATION_CHANGED"),
                    (lambda r: r["HostConfig"]["Mounts"][0].update(ReadOnly=False), "RETAINED_MOUNTS_CHANGED"),
                    (lambda r: r["HostConfig"]["Mounts"][0].update(Source="/other/source"),
                     "RETAINED_DOCKER_CONFIGURATION_CHANGED"),
                    (lambda r: r["Config"].update(Cmd=["changed"]), "RETAINED_PROCESS_CONFIGURATION_CHANGED"),
                    (lambda r: r["Config"].update(WorkingDir="/elsewhere"), "RETAINED_PROCESS_CONFIGURATION_CHANGED"),
                    (lambda r: r["Config"].update(Env=[]), "RETAINED_DOCKER_CONFIGURATION_CHANGED"),
                    (lambda r: r["HostConfig"].update(Tmpfs={"/x": "rw"}), "RETAINED_DOCKER_CONFIGURATION_CHANGED")):
                changed = copy.deepcopy(row)
                change(changed)
                with self.subTest(role=role, code=code), self.assertRaisesRegex(R.Held, code):
                    b1.retained_config(changed, role, launch)
            changed = copy.deepcopy(row)
            changed["State"]["Running"] = True
            with self.assertRaisesRegex(R.Held, "PROVIDER_NOT_STOPPED"):
                b1.retained_frame(changed, prior)

    @patch.object(P, "SOURCE", PurePosixPath(P.SOURCE.as_posix()))
    def test_preserves_template_and_context_and_compiles_only_sources(self):
        for role in b1.ROLES:
            req = legacy.synthetic_request(role)
            baseline = legacy.baseline[role]
            compiler = legacy.C

            def fake_source(mount, uid, gid):
                result = legacy.fake_source(mount, uid, gid)
                if mount["Target"] == P.TARGET:
                    result["sha256"] = P.OLD_SHA
                return result

            for mount in req["HostConfig"]["Mounts"]:
                if mount["Target"] == P.TARGET:
                    mount["Source"] = str(P.SOURCE)
            launch = legacy.L.creation_launch(req, role, baseline["launch"]["manifest"].get("tmpfs"),
                                               hash_source=fake_source)
            builder = legacy.T if role == "southbound" else legacy.B
            template = builder.build_role_template(baseline["template"], baseline["launch"], launch,
                                                   baseline["approvedUser"], mount_ordering=baseline["mountOrdering"])
            context = {"schema": "ouf.semantic-docker-frame-context.v1", "containerId": legacy.CID[role],
                       "bundleParent": "/run/containerd", "metadataParent": "/var/lib/docker/containers",
                       "networkNamespaceParent": "/run/docker/netns", "networkNamespaceName": None,
                       "cgroupDriver": "systemd", "storageParent": "/var/lib/docker",
                       "rootfsPath": "/var/lib/docker/rootfs/overlayfs/" + legacy.CID[role]}
            policy = compiler.compile_policy(template, launch, context)
            previous = {key: R.canonical(value) + b"\n" for key, value in (
                ("template", template), ("launch", launch), ("context", context), ("policy", policy))}
            new_hash = R.sha(b"synthetic new route bytes")
            revised = b1.revise(role, previous, new_hash, compiler)
            self.assertEqual(revised["template"], previous["template"])
            self.assertEqual(revised["context"], previous["context"])
            if role == "adapter":
                self.assertEqual(revised, previous)
                continue
            for part in ("launch", "policy"):
                value = R.decode(revised[part])
                route = next(item for item in value["sources"] if item["target"] == P.TARGET)
                self.assertEqual(route["sha256"], new_hash)
                route["sha256"] = P.OLD_SHA
                self.assertEqual(R.canonical(value) + b"\n", previous[part])

    def test_d042_comparison_requires_the_observed_rootfs_seal(self):
        for role in ("adapter", "southbound"):
            cid = P.CIDS[role]
            docker_root = Path("/fixture/docker")
            root = docker_root / "rootfs/overlayfs" / cid
            context = {"containerId": cid, "rootfsPath": str(root)}
            old = {"sha256": "a" * 64}
            image_id = "sha256:" + "f" * 64
            oci = {"root": {"path": str(root)}}
            inputs = {
                "oci": oci,
                "offline": {"manifestDigest": image_id, "rootfsLimits": {}},
                "comparison": {"ociConfig": P.binding("oci", "1" * 64), "nodeRootfsPath": str(root),
                               "containerId": cid, "imageId": image_id, "rule": "D-042",
                               "nodeRootfsSeal": old, "effectiveSeal": old, "expectedSeal": old},
            }
            rf = {"containerId": cid, "imageId": image_id, "effectiveSeal": old,
                  "offlineDockerReceipt": P.binding("offline", "2" * 64),
                  "comparison": P.binding("comparison", "3" * 64)}
            result = {"rule": "D-042", "sourceManifestSha256": b1.SEALER_SHA,
                      "engine": {"dockerSocket": C.DOCKER_SOCKET, "dockerRoot": str(docker_root)}}
            sealer = SimpleNamespace(load_sealer=lambda *_: lambda *_: old, Budget=object)
            export = SimpleNamespace(stopped_export_view=lambda *_: nullcontext(root))
            with (patch.object(C, "read", side_effect=lambda path, _: R.canonical(inputs[path])),
                  patch.object(C, "absolute", side_effect=Path),
                  patch.object(b1, "load_modules", return_value=(sealer, export))):
                self.assertEqual(b1.verify_rootfs(role, context, {"expectedOci": oci}, rf, result), old)
                live = {"sha256": "b" * 64}
                sealer.load_sealer = lambda *_: lambda *_: live
                if role == "adapter":
                    # No volatiles in the adapter: any live drift from D-042 is denied.
                    with self.assertRaisesRegex(R.Held, "RETAINED_ROOTFS_CHANGED_FROM_D042"):
                        b1.verify_rootfs(role, context, {"expectedOci": oci}, rf, result)
                else:
                    # Southbound after a run: D-047 at R3 start stays the rootfs gate.
                    self.assertEqual(b1.verify_rootfs(role, context, {"expectedOci": oci}, rf, result),
                                     {"liveSeal": live, "matchesD042": False, "rootfsGate": "D-047"})


class Runbooks(unittest.TestCase):
    def test_delivery_pins_and_g6_reuses_g5_software_and_d042(self):
        for name, count in (("routes-d052.sh", 5), ("b1-recipes-v3.sh", 9), ("acceptance-v51-g6.sh", 0)):
            script = (ROOT / "ops/vps" / name).read_text()
            self.assertRegex(script, r"(?m)^C=[0-9a-f]{40}$")
            pins = re.findall(r"^fetch (\S+) ([0-9a-f]{64})$", script, re.M)
            self.assertEqual(len(pins), count)
            for path, digest in pins:
                self.assertEqual(R.sha((ROOT / path).read_bytes().replace(b"\r\n", b"\n")), digest, path)
        g5 = (ROOT / "ops/vps/acceptance-v51-g5.sh").read_text()
        g6 = (ROOT / "ops/vps/acceptance-v51-g6.sh").read_text()
        self.assertEqual(re.findall(r"^[A-Z0-9]+=([0-9a-f]{64})$", g6, re.M),
                         re.findall(r"^[A-Z0-9]+=([0-9a-f]{64})$", g5, re.M))
        self.assertIn("--generation 6", g6)
        self.assertIn("rootfs_sha=" + b1.ROOTFS_SHA, g6)


if __name__ == "__main__":
    unittest.main()
