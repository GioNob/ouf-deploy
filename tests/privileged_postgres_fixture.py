"""Temporary PostgreSQL process using the hosted runner's own distribution."""
from contextlib import contextmanager
import os
from pathlib import Path
import subprocess
import tempfile
import time


@contextmanager
def postgres_fixture(cli, name, network="none", *, jdbc=False):
    postgres_bin = Path(subprocess.check_output(["pg_config", "--bindir"], text=True).strip())
    if not (postgres_bin / "initdb").is_file():
        raise RuntimeError("Hosted PostgreSQL installation required")
    with tempfile.TemporaryDirectory() as directory:
        passwd = Path(directory) / "passwd"
        passwd.write_text("fixture:x:10001:10001:fixture:/tmp:/bin/sh\n")
        passwd.chmod(0o644)
        # The reader uses the private socket. Only the JDBC fixture needs the isolated bridge.
        access = ""
        listen = ""
        if jdbc:
            assert subprocess.check_output([*cli, "network", "inspect", "--format", "{{.Internal}}",
                                            network], text=True).strip() == "true"
            access = "echo 'host all fixture samenet trust' >> /tmp/data/pg_hba.conf && "
            listen = "*"
        subprocess.run([*cli, "run", "-d", "--network", network, "--name", name, "--user", "10001:10001",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "-e", "HOME=/tmp",
            "-e", f"PATH={postgres_bin}:/usr/bin:/bin", "-v", "/usr:/usr:ro", "-v", "/usr/lib:/lib:ro",
            "-v", f"{passwd}:/etc/passwd:ro", os.environ["OUF_A2_FIXTURE_IMAGE"], "/bin/sh", "-ec",
            "initdb -D /tmp/data --no-locale -E UTF8 --auth-local=trust --auth-host=reject && "
            + access + f"exec postgres -D /tmp/data -k /tmp -c listen_addresses='{listen}'"],
            check=True, stdout=subprocess.DEVNULL)
        try:
            setup = [*cli, "exec", "-i", name, "psql", "-X", "-w", "-q", "-v", "ON_ERROR_STOP=1",
                     "-h", "/tmp", "-U", "fixture", "-d", "postgres"]
            for _ in range(60):
                if subprocess.run(setup, input=b"SELECT 1;", stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL).returncode == 0:
                    break
                time.sleep(.5)
            else:
                raise RuntimeError("Local PostgreSQL socket did not become ready")
            yield setup
        finally:
            subprocess.run([*cli, "rm", "-f", name], check=False, stdout=subprocess.DEVNULL)
