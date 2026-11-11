"""Tests for the installation/transaction split and exact profile publication."""

from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import runpy
import stat
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/prepare-semantic-provider-installation.py"
if not SCRIPT.exists():
    SCRIPT = Path(__file__).with_name(SCRIPT.name)
P = runpy.run_path(str(SCRIPT))
MODULE = P["main"].__globals__


class ProfileTests(unittest.TestCase):
    def test_role_projection_excludes_engine_identifiers_and_aliases(self):
        network_id = "a" * 64
        networks = {"back": (network_id, {"bridge": "ouf-test", "internal": False, "subnets": ["10.15.0.0/24"]})}
        endpoint = {"NetworkID": network_id, "IPAddress": "10.15.0.2", "MacAddress": "02:00:00:00:00:02",
                    "Aliases": ["semantic", "a123456789ab"], "DNSNames": ["semantic", "b123456789ab"],
                    "EndpointID": "c" * 64}
        docs = {"semantic": {"Name": "/semantic", "Id": "d" * 64,
                             "NetworkSettings": {"Networks": {"back": endpoint}}}}
        profile = P["role_profiles"](docs, networks)
        self.assertEqual(profile["semantic"]["networks"]["back"], {
            "ipv4": "10.15.0.2", "mac": "02:00:00:00:00:02", "aliases": ["semantic"], "dnsNames": ["semantic"],
        })
        endpoint["NetworkID"] = "e" * 64
        with self.assertRaisesRegex(P["Held"], "^SEMANTIC_NETWORK_ID_CHANGED$"):
            P["role_profiles"](docs, networks)

    def test_explicit_ports_come_from_matching_observations(self):
        def role(addresses, names):
            return {"networks": {str(index): {"ipv4": addr, "dnsNames": names}
                                 for index, addr in enumerate(addresses)}}
        roles = {"semantic": role(["10.15.0.2"], []), "southbound": role(["10.15.0.3", "10.16.0.3"], ["gate"]),
                 "adapter": role(["10.16.0.4"], [])}
        docs = {"semantic": {"Config": {"Env": [
            "OUF_SCHEMA_GOV_GATEWAY_BASE_URL=https://gate:15443",
            "OUF_SCHEMA_GOV_TOKEN_ENDPOINT=https://identity.example:1443/token",
            "UNRELATED_SECRET=ignore",
        ]}}}
        workload = {"purpose": "WORKLOAD_GATEWAY", "source": "10.15.0.2", "destination": "10.15.0.3",
                    "protocol": "tcp", "port": 15443, "peerIngress": {"ifindex": 971}}
        relay = {"purpose": "GATEWAY_ADAPTER", "source": "10.16.0.3", "destination": "10.16.0.4",
                 "protocol": "tcp", "port": 19443}
        templates = {"southbound": {"candidate": {"transport": [workload, relay]}},
                     "adapter": {"candidate": {"transport": [relay]}}}
        owner = {"kernel": {"providerFlows": [
            {"source": "10.16.0.4", "endpoint": "https://public.example:2443/"},
            {"source": "10.16.0.3", "endpoint": "https://identity.example:1443/keys"},
        ]}}
        peer = {"proposedIngress": {"sourceIpv4": "10.15.0.2", "destinationIpv4": "10.15.0.3",
                                    "destinationPort": 15443}}
        adapter = {"listenAddress": "10.16.0.4", "listenPort": 19443,
                   "provider": {"endpoint": "https://public.example:2443/query"}}
        listener = {"ip": "0.0.0.0", "port": 15443}
        ports, endpoints = P["stable_transport"](docs, roles, templates, owner, peer, "gate", adapter, listener)
        self.assertEqual(ports, {"southbound": 15443, "adapter": 19443})
        self.assertEqual(endpoints, {"provider": {"host": "public.example", "port": 2443, "sourceRole": "adapter"},
                                     "iam": {"host": "identity.example", "port": 1443, "sourceRole": "southbound"}})
        with self.assertRaisesRegex(P["Held"], "^OBSERVED_LISTENER_OR_SERVICE_ENDPOINT_CHANGED$"):
            P["stable_transport"](docs, roles, templates, owner, peer, "gate", adapter, listener | {"port": 15444})

    def test_bound_guard_and_empty_lock(self):
        pointer = {"schema": "ouf.semantic-coordinated-boot-pointer.v1", "receiptFile": "/etc/site/receipt.json",
                   "receiptHash": "a" * 64, "observerFile": "/etc/site/observer.py", "observerHash": "b" * 64}
        receipt = {"schema": "ouf.discovery-successor-boot-installation.v1", "state": "INSTALLED",
                   "leaseAuthorized": False, "startAuthorized": False, "observerHash": "b" * 64,
                   "stageDirectory": "/etc/site/stage", "bootProfileHash": "c" * 64, "configurationHash": "d" * 64}
        profile = {"coordinatedConfiguration": "/etc/site/owner.json", "coordinatedConfigurationHash": "d" * 64,
                   "bootConfiguration": "/etc/site/boot.json", "bootConfigurationHash": "e" * 64}
        owner = {"kernel": {"tableName": "site_guard"}, "commonLockFile": "/etc/site/lock",
                 "journalFile": "/etc/site/journal.json", "binding": {"configurationHash": "f" * 64}}
        boot = {"kernel": owner["kernel"], "lockFile": owner["commonLockFile"], "journalFile": "/etc/site/boot-journal.json"}
        journal = {"state": "QUIESCED", "leaseAuthorized": False, "startAuthorized": False,
                   "leaseAddresses": [[], []], **owner["binding"]}
        documents = {"/etc/site/pointer.json": pointer, "/etc/site/receipt.json": receipt,
                     "/etc/site/stage/boot-profile.json": profile, "/etc/site/owner.json": owner,
                     "/etc/site/boot.json": boot, "/etc/site/journal.json": journal}
        def read(path, expected=None, **kwargs):
            if str(path) == "/etc/site/lock":
                self.assertEqual(kwargs["minimum"], 0)
                return b""
            return b"fixture"
        reader = types.SimpleNamespace(document=lambda path, *args: documents[str(path)], read=read)
        args = types.SimpleNamespace(guard_pointer="/etc/site/pointer.json")
        self.assertEqual(P["boot_guard"](reader, args)[2]["lock"], "/etc/site/lock")
        journal["leaseAddresses"] = [["203.0.113.19"], []]
        with self.assertRaisesRegex(P["Held"], "^QUIESCED_COORDINATION_JOURNAL_REQUIRED$"):
            P["boot_guard"](reader, args)

    def test_file_publication_does_not_replace_existing_file(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "ouf" / "fixture"
            target = path / "semantic-provider.json"
            writes = {"profileFile": str(target), "directoriesIfMissing": [str(path.parent), str(path)]}
            with patch.dict(MODULE, directory=lambda _: None), patch.object(os, "fchown", wraps=os.fchown if os.geteuid() == 0 else lambda *args: None):
                P["publish"](writes, b'{"profile":1}\n')
                with self.assertRaises(FileExistsError):
                    P["publish"](writes | {"directoriesIfMissing": []}, b'{"profile":2}\n')
            self.assertEqual(target.read_bytes(), b'{"profile":1}\n')
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            self.assertEqual(list(path.iterdir()), [target])
            if os.geteuid() == 0:
                self.assertEqual((target.stat().st_uid, target.stat().st_gid), (0, 0))

    def test_plan_outputs_canonical_profile_and_mismatch_cannot_publish(self):
        profile = {"schema": P["SCHEMA"], "installationRef": "test"}
        proposal = {"profile": profile, "profileSha256": P["digest"](P["canonical"](profile) + b"\n"),
                    "planSha256": "a" * 64, "writes": {}}
        flags = {"installation-ref": "test", **{name: "/fixture" for name in (
            "installation-root", "a-root", "guard-pointer", "docker-socket", "generation-receipt", "authority-profile", "trust-policy"
        )}, **{name: "a" * 64 for name in (
            "a-plan-sha256", "generation-receipt-sha256", "authority-sha256", "trust-policy-sha256"
        )}}
        common = [part for name, value in flags.items() for part in ("--" + name, value)]
        def forbidden(*args):
            self.fail("publication was attempted")
        with patch.dict(MODULE, observe=lambda _: proposal, publish=forbidden), patch.object(
            os, "geteuid", return_value=0
        ), patch.object(os, "getegid", return_value=0):
            for arguments, code, expected in (
                (["--plan"], 0, "PLAN_READY"),
                (["--apply", "--plan-sha256", "b" * 64], 1, "HELD"),
            ):
                stdout = io.StringIO()
                with patch.object(sys, "argv", ["profile", *common, *arguments]), redirect_stdout(stdout):
                    self.assertEqual(P["main"](), code)
                report = json.loads(stdout.getvalue())
                self.assertEqual(report["status"], expected)
                self.assertEqual(report["profile"], profile)
                self.assertEqual(stdout.getvalue().encode(), P["canonical"](report) + b"\n")
