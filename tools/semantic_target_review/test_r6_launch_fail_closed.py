"""Transfer and digest failures stop before root; mocks are CI-only."""
import os,subprocess,tempfile,unittest
from pathlib import Path
class R6LaunchTests(unittest.TestCase):
    def test_all_download_and_digest_failures_stop_before_sudo(self):
        launch=Path(__file__).resolve().parents[2]/'releases/provider-v2-post-terminal-admission-20261009.sh'
        helper=Path(__file__).with_name('execute_post_terminal_admission_recovery.py')
        repair=Path(__file__).resolve().parents[1]/'semantic_transaction_profiles/repair_broker_sources.py'
        for scenario in ('download-fails','wrong-digest','repair-download-fails','preflight-download-fails'):
            with self.subTest(scenario=scenario),tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
                root=Path(directory);bin=root/'bin';bin.mkdir();work=root/'download';work.mkdir();marker=root/'sudo-called'
                if scenario=='download-fails':gh='exit 42\n'
                elif scenario=='wrong-digest':gh="printf 'd3JvbmctYnl0ZXM=\\n'\n"
                elif scenario=='repair-download-fails':gh=f'case "$2" in *repair_broker_sources*) exit 42;; *) base64 "{helper}";; esac\n'
                else:gh=f'case "$2" in *execute_post_terminal_admission*) base64 "{helper}";; *repair_broker_sources*) base64 "{repair}";; *) exit 42;; esac\n'
                scripts={'gh':'#!/bin/sh\n'+gh,'mktemp':f'#!/bin/sh\nprintf "%s\\n" "{work}"\n',
                    'sudo':f'#!/bin/sh\ntouch "{marker}"\nexit 99\n',
                    'sha256sum':"#!/bin/sh\nread line\ncase \"$line\" in\ne3253513*|5ff0a5ac*) exit 0;;\n*) printf '%s\\n' \"$line\" | /usr/bin/sha256sum -c -;;\nesac\n"}
                for name,raw in scripts.items():
                    p=bin/name;p.write_text(raw);p.chmod(0o755)
                result=subprocess.run(['/bin/bash',str(launch)],env={**os.environ,'PATH':str(bin)+':/usr/bin:/bin'},
                    stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
                self.assertEqual(result.returncode,1 if scenario=='wrong-digest' else 42)
                self.assertFalse(marker.exists());self.assertIn(b'OUF_R6_RECOVERY_EXIT=',result.stdout)
if __name__=='__main__':unittest.main()
