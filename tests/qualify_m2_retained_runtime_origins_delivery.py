"""Real immutable public HTTPS delivery; source inspection only, no VPS input."""
import hashlib,json,os,subprocess,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
LAUNCHER='scripts/launch-m2-retained-runtime-origins-20261101.sh'


class PublicDelivery(unittest.TestCase):
    def test_current_published_wrapper_and_immutable_capsule_are_exact(self):
        revision=os.environ.get('OUF_DELIVERY_REVISION','')
        self.assertRegex(revision,r'^[a-f0-9]{40}$')
        self.assertEqual(os.environ.get('GITHUB_ACTIONS'),'true')
        with tempfile.TemporaryDirectory() as folder:
            target=Path(folder)/'run.sh'
            subprocess.run(['/usr/bin/curl','--fail','--silent','--show-error','--location',
                '--proto','=https','--proto-redir','=https','--max-redirs','3','--tlsv1.2',
                '--connect-timeout','10','--max-time','30','--retry','0','--max-filesize','16384',
                'https://raw.githubusercontent.com/GioNob/ouf-deploy/'+revision+'/'+LAUNCHER,
                '--output',str(target)],check=True,timeout=35)
            expected=(ROOT/LAUNCHER).read_bytes();self.assertEqual(target.read_bytes(),expected)
            env={k:v for k,v in os.environ.items() if k not in ('GH_TOKEN','GITHUB_TOKEN','PYTHONPATH','PYTHONHOME')}
            result=subprocess.run(['/bin/bash',str(target),'--inspect-source'],env=env,
                stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60)
            self.assertEqual(result.returncode,0,result.stderr)
            body=json.loads(result.stdout)
            self.assertEqual(body['sourceRevisionClaim'],'cbbc127690e1ebe24dc437a97790c6356d360aae')
            self.assertEqual(body['sourceCount'],23)
            for key in ('runtimeAuthorityIssued','targetApplyAuthorized','publisherTrustAccepted'):
                self.assertIs(body[key],False)
            print(json.dumps({'status':'IMMUTABLE_RUNTIME_ORIGIN_JOIN_DELIVERY_INSPECTED_NO_TARGET_EXECUTION',
                'wrapperSourceRevision':revision,'wrapperSha256':hashlib.sha256(expected).hexdigest(),
                'capsuleSha256':'65092df60fa500e774c88aae801ce7452a8204a12dd2ab96b73664e356670b4f',
                'targetInputExecuted':False,'runtimeAuthorityIssued':False},sort_keys=True))


if __name__=='__main__':unittest.main()
