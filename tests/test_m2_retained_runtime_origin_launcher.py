"""Exercise the download-to-execution boundary without any target input call."""
import hashlib,json,os,subprocess,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
LAUNCHER=ROOT/'scripts/launch-m2-retained-runtime-origins-20261101.sh'
CAPSULE=ROOT/'scripts/prepare-m2-retained-runtime-origins-20261101.py'


class ImageInputLauncher(unittest.TestCase):
    def prepared(self,content=None,kind='regular'):
        tmp=tempfile.TemporaryDirectory(dir=ROOT);self.addCleanup(tmp.cleanup)
        root=Path(tmp.name);root.chmod(0o700);bin_dir=root/'bin';bin_dir.mkdir()
        source=root/'fixture.py';source.write_bytes(CAPSULE.read_bytes() if content is None else content)
        curl=bin_dir/'curl';curl.write_text('''#!/bin/sh
set -eu
printf '%s\\n' "$@" > "$OUF_TEST_CURL_ARGUMENTS"
out=''
while [ "$#" -gt 0 ]; do
 case "$1" in --output) out="$2"; shift 2 ;; *) shift ;; esac
done
case "$OUF_TEST_DOWNLOAD_KIND" in
 regular) /bin/cp -- "$OUF_TEST_CAPSULE" "$out" ;;
 symlink) /bin/ln -s -- "$OUF_TEST_CAPSULE" "$out" ;;
 hardlink) /bin/ln -- "$OUF_TEST_CAPSULE" "$out" ;;
 directory) /bin/mkdir -- "$out" ;;
 failure) exit 22 ;;
esac
''');curl.chmod(0o755)
        env={**os.environ,'PATH':str(bin_dir)+':/usr/bin:/bin','TMPDIR':str(root),
            'OUF_TEST_CAPSULE':str(source),'OUF_TEST_DOWNLOAD_KIND':kind,
            'OUF_TEST_CURL_ARGUMENTS':str(root/'curl.args')}
        return root,env

    def invoke(self,env,*args):
        return subprocess.run(['/bin/bash',str(LAUNCHER),*args],env=env,stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15)

    def test_exact_download_inspects_twenty_three_sources_without_runtime_authority(self):
        root,env=self.prepared();result=self.invoke(env,'--inspect-source')
        self.assertEqual(result.returncode,0,result.stderr);body=json.loads(result.stdout)
        self.assertEqual(body['sourceRevisionClaim'],'cbbc127690e1ebe24dc437a97790c6356d360aae')
        self.assertEqual(body['sourceCount'],23)
        for key in ('publisherTrustAccepted','runtimeAuthorityIssued','targetApplyAuthorized'):
            self.assertIs(body[key],False)
        self.assertEqual(list(root.glob('ouf-retained-runtime-origins.*')),[])

    def test_tampered_empty_and_oversized_downloads_do_not_execute_in_either_mode(self):
        for raw in (b'print("UNTRUSTED_BODY_EXECUTED")',b'',b'x'*393217):
            for args in ((),('--inspect-source',)):
                with self.subTest(size=len(raw),args=args):
                    root,env=self.prepared(raw);result=self.invoke(env,*args)
                    self.assertNotEqual(result.returncode,0)
                    self.assertNotIn(b'UNTRUSTED_BODY_EXECUTED',result.stdout+result.stderr)
                    self.assertEqual(json.loads(result.stdout)['reasonCode'],'EXACT_RUNTIME_ORIGIN_JOIN_DOWNLOAD_UNPROVEN')
                    self.assertEqual(list(root.glob('ouf-retained-runtime-origins.*')),[])

    def test_symlink_hardlink_and_directory_downloads_are_rejected(self):
        for kind in ('symlink','hardlink','directory'):
            with self.subTest(kind=kind):
                _,env=self.prepared(kind=kind);result=self.invoke(env,'--inspect-source')
                self.assertNotEqual(result.returncode,0)
                self.assertEqual(json.loads(result.stdout)['reasonCode'],'EXACT_RUNTIME_ORIGIN_JOIN_DOWNLOAD_UNPROVEN')

    def test_download_failure_stops_and_cleans_up_before_execution(self):
        root,env=self.prepared(kind='failure');result=self.invoke(env,'--inspect-source')
        self.assertEqual(result.returncode,22);self.assertEqual(result.stdout,b'')
        self.assertEqual(list(root.glob('ouf-retained-runtime-origins.*')),[])

    def test_unknown_or_extra_arguments_are_rejected_before_download_without_echo(self):
        root,env=self.prepared();sentinel='PRIVATE_ARGUMENT_MUST_NOT_ECHO'
        for args in (('--unknown',sentinel),('--inspect-source',sentinel),('',)):
            result=self.invoke(env,*args);self.assertNotEqual(result.returncode,0)
            self.assertNotIn(sentinel.encode(),result.stdout+result.stderr)
            self.assertEqual(json.loads(result.stdout)['reasonCode'],'EXACT_RUNTIME_ORIGIN_JOIN_MODE_REQUIRED')
        self.assertFalse((root/'curl.args').exists())

    def test_download_uses_only_immutable_https_and_bounded_nonretrying_transport(self):
        root,env=self.prepared();self.assertEqual(self.invoke(env,'--inspect-source').returncode,0)
        args=(root/'curl.args').read_text().splitlines()
        for option,value in (('--proto','=https'),('--proto-redir','=https'),('--retry','0'),
                ('--max-redirs','3'),('--max-filesize','393216'),('--max-time','30')):
            self.assertEqual(args[args.index(option)+1],value)
        self.assertIn('https://raw.githubusercontent.com/GioNob/ouf-deploy/710edec8526bcff7aebd3e90e23370ed41214833/scripts/prepare-m2-retained-runtime-origins-20261101.py',args)

    def test_delivered_capsule_bytes_and_shell_syntax(self):
        self.assertEqual(hashlib.sha256(CAPSULE.read_bytes()).hexdigest(),
            '65092df60fa500e774c88aae801ce7452a8204a12dd2ab96b73664e356670b4f')
        subprocess.run(['/bin/bash','-n',str(LAUNCHER)],check=True,timeout=5)


if __name__=='__main__':unittest.main()
