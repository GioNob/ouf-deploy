import hashlib
import json
import os
from pathlib import Path
import stat
import unittest
from unittest.mock import Mock, patch

from test_module_install import setup_profile
from tools.module_release import frame_spec as spec
from tools.module_release.contract import ENTRY


class Grammar(unittest.TestCase):
    def setUp(self):
        self.p = setup_profile(str(Path.cwd()))
        self.section = self.p["install"]
        self.facts = {"imageId": "sha256:" + "a"*64, "Config": {"Volumes": {"/tmp": {}}},
                      "networks": {"example-net": {"NetworkID": "b"*64, "ips": [], "aliases": []}}}

    def build(self):
        with patch.object(spec, "bind_facts", return_value=({}, {"ino": 42})):
            return spec.build_create(self.p, self.facts, "c"*64)

    def test_exact_request_and_image_volume(self):
        create = self.build()
        self.assertEqual(create["Entrypoint"], ENTRY)
        self.assertEqual(create["Cmd"], self.p["gate"]["command"])
        self.assertEqual(create["Labels"], {"ouf.install.plan": "c"*64})
        self.assertEqual(create["HostConfig"]["RestartPolicy"], {"Name": "no"})
        self.assertIn("/tmp", create["HostConfig"]["Tmpfs"])
        self.section["tmpfs"] = []
        with self.assertRaises(spec.SpecHeld) as exc:
            self.build()
        self.assertEqual(exc.exception.code, "IMAGE_VOLUME_UNCOVERED")
        self.section["binds"][0]["target"] = "/tmp"
        self.build()
        self.assertEqual(json.loads(spec.canonical(create)), create)

    def test_forbidden_create_controls_each_fail_closed(self):
        forbidden = {"privileged": True, "Privileged": True, "CapAdd": ["SYS_ADMIN"],
                     "PortBindings": {}, "PublishAllPorts": True, "HostIp": "192.0.2.5", "NetworkMode": "host",
                     "PidMode": "host", "IpcMode": "host", "Volumes": {"store": {}},
                     "RestartPolicy": {"Name": "always"}, "MacAddress": "injected", "unknown": 1}
        for key, value in forbidden.items():
            with self.subTest(key=key), patch.dict(self.section, {key: value}), self.assertRaises(spec.SpecHeld):
                self.build()
        mount = self.section["binds"][0]
        for bad in ({"Type": "volume"}, {"source": "named-volume"}, {"source": "/var/run/docker.sock"},
                    {"source": "/opt/ouf-a2"}, {"source": "/var/lib/docker"}, {"source": "/etc"},
                    {"source": "/srv/example/inbox"}, {"source": "/srv/example/journal"},
                    {"source": "/srv/example/custom-engine.sock"}):
            p = {**self.p, "inbox": "/srv/example/inbox", "journal": "/srv/example/journal",
                 "dockerSocket": "/srv/example/custom-engine.sock"}
            with self.subTest(bad=bad), patch.dict(self.section, bindRoots=["/srv/example", "/var", "/opt", "/etc"],
                    binds=[{**mount, **bad}]), self.assertRaises(spec.SpecHeld):
                spec.build_create(p, self.facts, "c"*64)

    def test_environment_and_user(self):
        valid = [{"name": "FLAG", "value": "0"}]
        self.assertEqual(spec.validate_env(valid, ["FLAG"]), ["FLAG=0"])
        for entries, allowed in ((valid, []), (valid*2, None), ([{"name":"A-B", "value":"x"}], None),
                                 ([{"name":"API_TOKEN", "value":"inline"}], None),
                                 ([{"name":"URL", "value":"https://user:password@example.invalid"}], None)):
            with self.subTest(entries=entries), self.assertRaises(spec.SpecHeld):
                spec.validate_env(entries, allowed)
        self.section["env"] = [{"name": "TOKEN_FILE", "value": "/data"}]
        with self.assertRaisesRegex(spec.SpecHeld, "FILE_ENV_REQUIRES_RO_BIND"):
            self.build()
        self.section["binds"][0]["mode"] = "ro"
        self.build()
        for user in ("root", "0", "0:1", "1:0", "0000", "", "4294967295"):
            with self.subTest(user=user), patch.dict(self.section, user=user), self.assertRaises(spec.SpecHeld):
                self.build()

    def test_direct_bind_excludes_profile_paths_and_their_ancestors(self):
        profile = {"journal": "/srv/tenant/history", "inbox": "/srv/packages/accepted",
                   "dockerSocket": "/srv/engine/control"}
        roots = ["/srv", "/opt", "/var", "/etc"]
        for protected in [*profile.values(), "/var/lib/docker", "/opt/ouf-a2", "/etc/systemd"]:
            for source in (protected, protected + "/child", protected.rsplit("/", 1)[0]):
                row = {"source": source, "target": "/data", "mode": "ro"}
                with self.subTest(source=source), self.assertRaisesRegex(spec.SpecHeld, "BIND_SOURCE_DENIED"):
                    spec.validate_bind(row, roots, profile=profile)
        row = {"source": "/srv/data", "target": "/data", "mode": "ro"}
        with self.assertRaisesRegex(spec.SpecHeld, "BIND_POLICY_REQUIRED"):
            spec.validate_bind(row, roots)
        with self.assertRaisesRegex(spec.SpecHeld, "BIND_POLICY_REQUIRED"):
            spec.validate_bind(row, roots, profile={"journal": profile["journal"]})

    def test_file_env_checks_the_composed_mounts(self):
        env = spec.validate_env([{"name": "TOKEN_FILE", "value": "/config/id"}], ["TOKEN_FILE"])
        bind = {"Type": "bind", "Source": "/srv/private/id", "Target": "/config/id", "ReadOnly": True}
        spec.check_file_env(env, [bind])
        for mounts in ([], [{**bind, "ReadOnly": False}], [{**bind, "Type": "volume"}]):
            with self.subTest(mounts=mounts), self.assertRaisesRegex(spec.SpecHeld, "FILE_ENV_REQUIRES_RO_BIND"):
                spec.check_file_env(env, mounts)

    def test_network_ownership_and_tmpfs_options(self):
        live = self.facts["networks"]
        ep = live["example-net"]
        for delta in ({"ips": ["192.0.2.2"]}, {"aliases": ["example-service"]}):
            with self.subTest(delta=delta), patch.dict(ep, delta), self.assertRaises(spec.SpecHeld):
                self.build()
        for name in ("host", "none", "bridge", "missing"):
            with self.subTest(net=name), self.assertRaises(spec.SpecHeld):
                spec.validate_networks({name: self.p["networks"]["example-net"]}, live)
        for options in ("bind", "exec", "size=1m,size=1g", "rw,ro"):
            with self.subTest(options=options), self.assertRaises(spec.SpecHeld):
                spec.validate_tmpfs({"target": "/tmp", "options": options})

    def test_descriptor_walk_and_content_pin(self):
        source = {"source": "/srv/fixture/config", "target": "/config", "mode": "ro",
                  "sha256": hashlib.sha256(b"fixture").hexdigest()}
        roots = {"bindRoots": ["/srv/fixture"], "journal": "/srv/journal", "inbox": "/srv/inbox",
                 "dockerSocket": "/srv/run/engine"}
        kernel = Mock(wraps=os, O_RDONLY=0, O_NOFOLLOW=32, O_DIRECTORY=64, O_NONBLOCK=128)
        kernel.close = Mock()
        metadata = Mock(st_uid=0, st_gid=0, st_mode=stat.S_IFDIR | 0o750)
        leaf = Mock(st_uid=0, st_gid=0, st_mode=stat.S_IFREG | 0o640,
                    st_dev=1, st_ino=42, st_ctime_ns=1)
        kernel.open.side_effect = lambda name, flags, dir_fd=None: {"/":1, "srv":2, "fixture":3, "config":4}[name]
        kernel.fstat.side_effect = lambda fd: leaf if fd == 4 else metadata
        kernel.read.side_effect = [b"fixture", b""]
        with patch.object(spec, "os", kernel):
            self.assertEqual(spec.validate_bind(source, roots)["Type"], "bind")
            self.assertTrue(all(c.args[1] & kernel.O_NOFOLLOW for c in kernel.open.call_args_list))
            self.assertEqual([c.kwargs["dir_fd"] for c in kernel.open.call_args_list], [None, 1, 2, 3])
            kernel.read.side_effect = [b"modified", b""]
            with self.assertRaisesRegex(spec.SpecHeld, "BIND_DIGEST_CHANGED"):
                spec.validate_bind(source, roots)
            leaf.st_uid = 42
            with self.assertRaisesRegex(spec.SpecHeld, "BIND_SOURCE_CUSTODY"):
                spec.validate_bind(source, roots)
            leaf.st_uid = 0
            metadata.st_mode |= 0o020
            with self.assertRaisesRegex(spec.SpecHeld, "BIND_PARENT_CUSTODY"):
                spec.validate_bind(source, roots)
            kernel.open.side_effect = OSError("symlink")
            with self.assertRaisesRegex(spec.SpecHeld, "BIND_CUSTODY_UNPROVEN"):
                spec.validate_bind(source, roots)
