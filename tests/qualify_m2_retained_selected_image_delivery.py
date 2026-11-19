"""Real immutable public HTTPS delivery; source inspection only, no VPS input."""
import hashlib,json,os,subprocess,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
LAUNCHER='scripts/launch-m2-retained-selected-image-20261101.sh'


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
            self.assertEqual(body['sourceRevisionClaim'],'59784ccbdb895d79abf9a399175180273ae15dcc')
            self.assertEqual(body['sourceCount'],21)
            for key in ('runtimeAuthorityIssued','targetApplyAuthorized','publisherTrustAccepted'):
                self.assertIs(body[key],False)
            print(json.dumps({'status':'IMMUTABLE_SELECTED_RUNTIME_BYTE_VERIFICATION_DELIVERY_INSPECTED_NO_TARGET_EXECUTION',
                'wrapperSourceRevision':revision,'wrapperSha256':hashlib.sha256(expected).hexdigest(),
                'capsuleSha256':'d7e433b2d42c89aa8cdd8ccf49ce5dd97f0deb17479cba844c666270ff7a0f12',
                'targetInputExecuted':False,'runtimeAuthorityIssued':False},sort_keys=True))


if __name__=='__main__':unittest.main()
