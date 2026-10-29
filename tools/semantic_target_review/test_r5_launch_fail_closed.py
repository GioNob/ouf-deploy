"""Nonprivileged CLI failures must never reach sudo; mocks are CI only."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

class R5LaunchTests(unittest.TestCase):
    def test_download_and_digest_failure_never_reach_sudo(self):
        launch=Path(__file__).resolve().parents[2]/'releases/provider-v2-broker-source-recovery-20261009.sh'
        for scenario in ('download-fails','wrong-digest','repair-download-fails'):
            with self.subTest(scenario=scenario),tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
                root=Path(directory);bin=root/'bin';bin.mkdir();work=root/'download';work.mkdir()
                marker=root/'sudo-was-called'
                helper=Path(__file__).with_name('execute_broker_source_recovery.py')
                scripts={
                    'gh':'#!/bin/sh\n'+('exit 42\n' if scenario=='download-fails' else (f'case \"$2\" in *repair_broker_sources*) exit 42;; *) base64 \"{helper}\";; esac\n' if scenario=='repair-download-fails' else "printf 'd3JvbmctYnl0ZXM=\\n'\n")),
                    'mktemp':f'#!/bin/sh\nprintf "%s\\n" "{work}"\n',
                    'sudo':f'#!/bin/sh\ntouch "{marker}"\nexit 99\n',
                    # Only replace the known prior-file prerequisite, absent in
                    # CI. Check the downloaded new file with the actual tool.
                    'sha256sum':"#!/bin/sh\nread line\ncase \"$line\" in\ne3253513*|5ff0a5ac*) exit 0;;\n*) printf '%s\\n' \"$line\" | /usr/bin/sha256sum -c -;;\nesac\n"}
                for name,raw in scripts.items():
                    p=bin/name;p.write_text(raw);p.chmod(0o755)
                result=subprocess.run(['/bin/bash',str(launch)],env={**os.environ,'PATH':str(bin)+':/usr/bin:/bin'},
                    stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
                self.assertEqual(result.returncode,42 if scenario in ('download-fails','repair-download-fails') else 1)
                self.assertFalse(marker.exists())
                self.assertIn(b'OUF_R5_RECOVERY_EXIT=',result.stdout)

if __name__=='__main__':unittest.main()
