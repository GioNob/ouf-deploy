"""Opt-in Linux Engine test. Fixture creation and cleanup are outside the controller."""
import hashlib
import ipaddress
import json
import os
import re
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "tests"), str(ROOT / "tools")]

from tools.platform_restart.controller import Controller
from tools.platform_restart.docker import Docker
from tools.platform_restart.profile import canonical, load_profile, sha


# A local scratch image serves TCP and runs its own Docker health probe. No pull or registry.
SERVER = r"""
#include <arpa/inet.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static void shutdown_server(int sig) { (void)sig; _exit(0); }
int main(int argc, char **argv) {
    const char *port = getenv("PORT");
    if (!port) return 1;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 2;
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(atoi(port))};
    if (argc == 2 && strcmp(argv[1], "health") == 0) {
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        return connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0;
    }
    int reuse = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) || listen(fd, 8)) return 3;
    signal(SIGTERM, shutdown_server);
    for (;;) {
        int client = accept(fd, NULL, NULL);
        if (client >= 0) {
            if (getenv("HTTP_READY")) {
                char request[1024];
                const char reply[] = "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n";
                if (read(client, request, sizeof(request)) > 0) write(client, reply, sizeof(reply) - 1);
            }
            close(client);
        }
    }
}
"""


@unittest.skipUnless(os.environ.get("OUF_PLATFORM_RESTART_NATIVE") == "1", "opt-in Linux Docker fixture")
class NativeRestart(unittest.TestCase):
    def test_real_gated_release_receipts(self):
        from test_platform_restart import ReleaseJournal, configuration
        from tools.module_release import frame
        from tools.module_release.docker import Docker as ReleaseDocker
        from tools.module_release.operation import park
        if os.geteuid() != 0:
            # setns and /proc/<pid>/cmdline need the same privileges as the installed unit.
            subprocess.run(["sudo", "-n", "env", "OUF_PLATFORM_RESTART_NATIVE=1",
                            "OUF_TEST_DOCKER_SOCKET=" + os.environ.get("OUF_TEST_DOCKER_SOCKET", "/run/docker.sock"),
                            sys.executable, "-I", "-B", __file__, self.__class__.__name__ + "." + self._testMethodName],
                           check=True, timeout=180)
            return

        binary = Path(shutil.which("docker")).resolve(strict=True)
        sock = Path(os.environ.get("OUF_TEST_DOCKER_SOCKET", "/run/docker.sock")).resolve(strict=True)
        root = Path(self.enterContext(tempfile.TemporaryDirectory(dir="/var/lib")))
        prefix = "gate-test-" + uuid.uuid4().hex[:12]
        def docker(*args):
            return subprocess.check_output([binary, "--host", "unix://" + str(sock), *args],
                                           text=True, timeout=90).strip()

        build = root / "build"
        build.mkdir()
        fs = build / "rootfs"
        (fs / "bin").mkdir(parents=True)
        busybox = Path(shutil.which("busybox") or "/usr/lib/initramfs-tools/bin/busybox")
        shutil.copyfile(busybox, fs / "bin/busybox")
        (fs / "bin/busybox").chmod(0o755)
        for applet in ("sh", "sleep"):
            (fs / "bin" / applet).symlink_to("/bin/busybox")
        # Ubuntu also ships a dynamically linked busybox. Include its local loader and libraries.
        ldd = subprocess.run(["ldd", str(busybox)], capture_output=True, text=True, check=False)
        for lib in re.findall(r"(/[^\s()]+)", ldd.stdout):
            target = fs / lib.lstrip("/")
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(lib, target)
        (build / "server.c").write_text(SERVER)
        subprocess.run(["cc", "-static", "-O2", "-o", fs / "fixture", build / "server.c"], check=True)
        (build / "Dockerfile").write_text('FROM scratch AS predecessor\nCOPY rootfs /\nENTRYPOINT ["/fixture"]\n'
                                          'ENV PORT=12345 HTTP_READY=yes PATH=/bin\nFROM predecessor AS candidate\n'
                                          'LABEL ouf.fixture="gate"\nENV RELEASE_FIXTURE=candidate\n')
        def build_image(target):
            tag = prefix + ":" + target
            docker("build", "--network=none", "--pull=false", "-q", "--target", target, "-t", tag, str(build))
            self.addCleanup(docker, "image", "rm", tag)
            return docker("image", "inspect", "--format", "{{.Id}}", tag)
        previous_image = build_image("predecessor")
        image = build_image("candidate")
        self.assertNotEqual(previous_image, image)

        entry, command = frame.ENTRY, ["/fixture"]
        name = prefix + "-app"
        rt = ReleaseDocker(dict(dockerSocket=str(sock), gate=dict(command=command),
                                nsenter=shutil.which("nsenter"), readiness=dict(port=12345, path="/ready")))
        def create(container, body):
            cid = rt.create(container, body)
            self.addCleanup(docker, "rm", "-f", cid)
            return cid

        def release_for_fixture(cid):
            rt.start(cid)
            until = time.monotonic() + 12
            while not rt.process(rt.inspect(cid), gated=True):
                self.assertLess(time.monotonic(), until, "gate did not arm")
                time.sleep(0.05)
            rt.signal(cid)
            while not (rt.process(rt.inspect(cid), gated=False) and rt.probe(rt.inspect(cid))[0] == 204):
                self.assertLess(time.monotonic(), until, "application did not become ready")
                time.sleep(0.05)
            return rt.inspect(cid)

        cfg = configuration()
        cfg.update(docker=dict(path=str(binary), sha256=sha(binary.read_bytes())), dockerSocket=str(sock))
        for key in ("incidents", "receipts"):
            path = root / key
            path.mkdir(mode=0o700)
            cfg[key] = str(path)
        cfg["governedElsewhere"] = [prefix + "-peer-a", prefix + "-peer-b"]
        for peer in cfg["governedElsewhere"]:
            create(peer, dict(Image=previous_image, HostConfig=dict(NetworkMode="none")))
        adapter = Docker(cfg)
        net = prefix + "-net"
        subnet = os.environ.get("OUF_TEST_SUBNETS", "192.0.2.0/28").split(",")[0]
        net_id = docker("network", "create", "--internal", "--subnet", subnet, net)
        self.addCleanup(docker, "network", "rm", net_id)
        old_cid = create(name, dict(Image=previous_image, Entrypoint=entry, Cmd=command, HostConfig=dict(NetworkMode=net)))
        old = release_for_fixture(old_cid)
        create_request = frame.request(old, image)
        park(rt, old_cid, prefix + "-retained", old["NetworkSettings"]["Networks"])
        cid = create(name, create_request)
        new = rt.inspect(cid)
        defaults = rt.image_defaults(image)
        self.assertEqual(defaults["Entrypoint"], ["/fixture"])
        frame.check_body(old, new, image, image, created=True, image_defaults=defaults)
        for doc in (old, new):
            self.assertEqual((doc["Config"]["Entrypoint"], doc["Config"]["Cmd"]), (entry, command))
        self.assertEqual(new["Config"]["Labels"]["ouf.fixture"], "gate")
        self.assertIn("RELEASE_FIXTURE=candidate", new["Config"]["Env"])
        journal = ReleaseJournal(root / "executor", old, new, str(sock), create_request, ready=False)
        member = dict(containerName=name, gate=dict(entrypoint=entry, identity=journal.binding),
                      readiness=dict(type="actuator", address="127.0.0.1", port=12345, path="/ready",
                                     timeoutSeconds=1, budgetSeconds=12, acceptStatus=[204]))
        cfg["levels"] = [dict(timeoutSeconds=15, containers=[member])]
        def controller():
            raw = canonical(cfg)
            return Controller(load_profile(raw, sha(raw)), sha(raw), adapter)
        lock = journal.tx.parent / "example.lock"
        lock.mkdir()
        for mode in ("plan", "apply", "boot"):
            report = controller().run(mode, "start", "0" * 64, str(uuid.uuid4()))
            self.assertEqual(report["reason"], "RELEASE_TRANSACTION_OPEN", report)
            self.assertEqual(report["events"], [])
            self.assertEqual(docker("inspect", "--format", "{{.State.Status}}", cid), "created")
        incident_path, = Path(cfg["incidents"]).glob("incident-*.json")
        incident = json.loads(incident_path.read_bytes())
        self.assertEqual((incident["code"], incident["reason"], incident["container"], incident["level"]),
                         ("PLATFORM_BOOT_START_FAILED", "RELEASE_TRANSACTION_OPEN", name, 1))
        new = release_for_fixture(cid)
        journal.publish_ready(new)
        lock.rmdir()

        # An exited, previously started generation is eligible for a governed restart.
        docker("stop", "--time", "1", cid)
        def start(binding):
            member["gate"]["identity"] = binding
            ctrl = controller()
            plan = ctrl.run("plan", "start")
            return ctrl.run("apply", "start", plan["planSha256"])
        # The receipt and its plan consistently attest another image for this CID.
        other_image = "sha256:" + "f" * 64
        wrong = ReleaseJournal(root / "different", old, {**new, "Image": other_image}, str(sock),
                               frame.request(old, other_image))
        self.assertEqual(start(wrong.binding)["reason"], "RELEASE_IMAGE_MISMATCH")
        self.assertEqual(docker("inspect", "--format", "{{.State.Status}}", cid), "exited")
        unsigned = ReleaseJournal(root / "unsigned", old, new, str(sock), create_request, signing=False)
        for binding in (journal.binding, unsigned.binding):
            result = start(binding)
            self.assertEqual(result["status"], "SUCCEEDED", result)
            self.assertTrue(any(e.get("outcome") == "UP" for e in result["events"]))
            docker("stop", "--time", "1", cid)

    def test_real_start_stop_retained_and_collision(self):
        prefix = "restart-test-" + uuid.uuid4().hex[:12]
        binary = Path(shutil.which("docker")).resolve(strict=True)
        # Development-only default. Use the canonical local socket path for custody.
        local_socket = Path(os.environ.get("OUF_TEST_DOCKER_SOCKET", "/run/docker.sock")).resolve(strict=True)
        def docker(*args):
            return subprocess.check_output([str(binary), "--host", f"unix://{local_socket}", *args],
                                           text=True, timeout=120).strip()

        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        (root / "server.c").write_text(SERVER)
        subprocess.run(["cc", "-static", "-O2", "-o", str(root / "fixture"), str(root / "server.c")],
                       check=True, timeout=60)
        (root / "Dockerfile").write_text('FROM scratch\nCOPY fixture /fixture\nENTRYPOINT ["/fixture"]\n'
                                         'HEALTHCHECK --interval=1s --timeout=1s CMD ["/fixture","health"]\n')
        docker("build", "--network=none", "--pull=false", "-q", "-t", prefix, str(root))
        self.addCleanup(docker, "image", "rm", prefix)
        subnets = [ipaddress.IPv4Network(s) for s in
                   os.environ.get("OUF_TEST_SUBNETS", "192.0.2.0/28,198.51.100.0/28").split(",")]
        self.assertEqual(len(subnets), 2)
        nets = []
        for i, net in enumerate(subnets):
            name = f"{prefix}-net-{i}"
            net_id = docker("network", "create", "--subnet", str(net), name)
            self.addCleanup(docker, "network", "rm", net_id)
            nets.append(name)
        with socket.socket() as probe:
            probe.bind(("", 0))
            port = probe.getsockname()[1]
        names = [prefix + "-" + role for role in ("stable", "health", "tcp", "retained", "private-a", "private-b")]
        ids = []
        for name, (net, host) in zip(names, [(0, 2), (0, 3), (1, 2), (0, 2), (1, 3), (1, 4)], strict=True):
            cid = docker("create", "--name", name, "--network", nets[net], "--ip", str(subnets[net][host]),
                         "--env", f"PORT={port}", prefix)
            self.addCleanup(docker, "rm", "-f", cid)
            ids.append(cid)
        for d in ("receipts", "incidents"):
            (root / d).mkdir(mode=0o700)
        with binary.open("rb") as stream:
            docker_hash = hashlib.file_digest(stream, "sha256").hexdigest()
        probes = [dict(type="running", stableSeconds=1), dict(type="healthy"),
                  dict(type="tcp", network=nets[1], port=port, timeoutSeconds=1)]
        cfg = dict(schema="ouf.platform-restart-profile.v1", docker=dict(path=str(binary), sha256=docker_hash),
                   dockerSocket=str(local_socket), governedElsewhere=names[-2:], stopTimeoutSeconds=3, inventoryTimeoutSeconds=30,
                   receipts=str(root / "receipts"), incidents=str(root / "incidents"), bootRetryDelaysSeconds=[1, 2],
                   levels=[dict(timeoutSeconds=30, containers=[dict(containerName=n, readiness=p)])
                           for n, p in zip(names[:3], probes, strict=True)])
        raw = canonical(cfg)
        ctrl = Controller(load_profile(raw, sha(raw)), sha(raw), Docker(cfg))
        def operate(action):
            plan = ctrl.run("plan", action)
            self.assertEqual(plan["status"], "PLAN_READY", plan)
            report = ctrl.run("apply", action, plan["planSha256"])
            self.assertEqual(report["status"], "SUCCEEDED", report)
            return [e["container"] for e in report["events"] if e.get("operation") == action]

        self.assertEqual(operate("start"), names[:3])
        # The TCP barrier may finish before that member's first Docker healthcheck.
        # Let this independent state settle before testing the exact stop plan hash.
        until = time.monotonic() + 15
        while docker("inspect", "--format", "{{.State.Health.Status}}", ids[2]) != "healthy":
            self.assertLess(time.monotonic(), until)
            time.sleep(0.25)
        self.assertEqual(operate("stop"), names[:3][::-1])
        for cid in ids:
            self.assertEqual(docker("inspect", "--format", "{{.State.Running}}", cid), "false")
        docker("start", ids[3])  # Operator starts the retained fixture with the original's static IPv4.
        denied = ctrl.run("plan", "start")
        self.assertEqual(denied["reason"], "IPV4_CONFLICT", denied)
        self.assertEqual(ctrl.run("apply", "start", denied["planSha256"])["status"], "HELD")
        docker("stop", ids[3])
        self.assertEqual(operate("start"), names[:3])
        for cid in ids[3:]:
            self.assertEqual(docker("inspect", "--format", "{{.State.Running}}", cid), "false")


if __name__ == "__main__":
    unittest.main()
