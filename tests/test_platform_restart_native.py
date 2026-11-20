"""Opt-in Linux Engine test. Fixture creation and cleanup are outside the controller."""
import hashlib
import ipaddress
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
import uuid

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
        if (client >= 0) close(client);
    }
}
"""


@unittest.skipUnless(os.environ.get("OUF_PLATFORM_RESTART_NATIVE") == "1", "opt-in Linux Docker fixture")
class NativeRestart(unittest.TestCase):
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
