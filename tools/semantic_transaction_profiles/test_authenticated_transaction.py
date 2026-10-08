"""Disposable keys and signed synthetic documents: no target acceptance."""
import copy
import importlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

HERE = Path(__file__).resolve().parent
DRAFT = HERE.parent / 'semantic_cohort_admission/cohort-draft'
sys.path.insert(0, str(DRAFT))
sys.path.insert(0, str(HERE.parent / 'semantic_frame_compiler'))
from authenticate_provider_transaction import (AUTHORITIES, TARGETS, TransactionDenied,
    authenticate_role, build_install_plan, digest, encoded)
from compile_creation_frame_policy import compile_policy
from tools.semantic_provider_deployment_authentication import DetachedAuthenticator, signing_bytes


class AuthenticatedTransactionTest(unittest.TestCase):
    def setUp(self):
        # The production verifier requires root-owned ancestors, as target does.
        self.assertEqual(os.geteuid(), 0, 'run these native-custody tests as root')
        self.temp = tempfile.TemporaryDirectory(dir=Path.cwd(), prefix='transaction-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.root.chmod(0o700)
        self.signatures = self.root/'signatures'; self.signatures.mkdir(mode=0o700)
        self.now = int(time.time()); self.clock = lambda: self.now
        self.openssl = str(Path(shutil.which('openssl')).resolve())
        self.keys = {}; grants = []
        for role, issuer, roles in [('installer', AUTHORITIES['approvalIssuerRef'], ['DEPLOYMENT_INTENT','FINAL_DEPLOYMENT_APPROVAL']),
                                  ('attestor', AUTHORITIES['attestorRef'], ['CREATION_ATTESTATION'])]:
            path = self.root/(role+'.pem')
            self.run_native('genpkey','-algorithm','ED25519','-out',str(path)); path.chmod(0o600)
            public = self.run_native('pkey','-in',str(path),'-pubout','-outform','DER')
            self.keys[role] = path
            grants.append({'keyRef': role+'-test-key', 'issuerRef': issuer, 'roles': roles,
                           'publicKey': public[12:].hex(), 'notBefore': self.now-30,
                           'expiresAt': self.now+600, 'state': 'ACTIVE'})
        self.policy = self.root/'trust.json'
        self.private(self.policy, encoded({'schema':'ouf.semantic-deployment-trust-policy.v1',
                     'installationRef':AUTHORITIES['installationRef'], 'entityRef':AUTHORITIES['entityRef'], 'keys':grants}))
        self.crypto = {'policyBinding':self.bind(self.policy), 'signatureDirectory':str(self.signatures),
            'opensslBinding':{**self.bind(Path(self.openssl)),
                'version':self.run_native('version').decode().split()[1]}}
        self.verifier = DetachedAuthenticator(**{'policy_binding':self.crypto['policyBinding'],
            'signature_directory':self.crypto['signatureDirectory'], 'openssl_binding':self.crypto['opensslBinding']},clock=self.clock)
        self.authority = {'authorities':copy.deepcopy(AUTHORITIES),
            'keyBindings':{role:self.bind(path) for role,path in self.keys.items()},
            'keyRefs':{role:role+'-test-key' for role in self.keys}}
        self.sources = {str(p.relative_to(DRAFT)):p.read_bytes() for p in DRAFT.rglob('*.py')}
        self.observer = b'# signed observer bytes for this disposable fixture\n'
        self.python = self.bind(Path(sys.executable).resolve())
        self.runtime = {'path':'/usr/bin/runc','sha256':'a'*64}
        self.records = {role:self.make_records(role) for role in TARGETS}
        self.adapter = {'schema':'ouf.semantic-docker-runtime-adapter.v4', 'sourceHash':'b'*64,
            'runtimePath':self.runtime['path'],'runtimeSha256':self.runtime['sha256'],
            'pythonPath':self.python['path'],'pythonSha256':self.python['sha256'],
            'driverPath':'/old/driver','driverSha256':'c'*64, 'admissionPath':'/old/broker','admissionSha256':'d'*64,
            'registryRoot':'/old/registry','runtimeStateRoot':'/run/docker','candidates':{}}

    def run_native(self,*args):
        return subprocess.run([self.openssl,*args],check=True,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL).stdout

    def private(self,path,raw):
        path.write_bytes(raw); path.chmod(0o600)

    def bind(self,path):return {'path':str(path),'sha256':digest(path.read_bytes())}

    def sign(self,raw,role,issuer):
        key = 'attestor' if role == 'CREATION_ATTESTATION' else 'installer'
        header = {'schema':'ouf.semantic-deployment-detached-signature.v1','algorithm':'Ed25519',
            'keyRef':key+'-test-key','role':role,'issuerRef':issuer,
            'installationRef':AUTHORITIES['installationRef'],'entityRef':AUTHORITIES['entityRef'],'payloadHash':digest(raw)}
        frame = self.root/'frame.bin';self.private(frame,signing_bytes(raw,header))
        signature = self.run_native('pkeyutl','-sign','-rawin','-inkey',str(self.keys[key]),'-in',str(frame))
        self.private(self.signatures/(digest(raw)+'.'+role+'.json'),encoded({**header,'signature':signature.hex()}))

    def make_records(self,role):
        target = TARGETS[role];cid = target['containerId']
        baseline = __import__('json').loads((HERE.parent/'semantic_frame_compiler/containerd-overlayfs-adapter.json').read_bytes())
        template = baseline['template']
        # Synthetic source, launch and complete frame, not the private target.
        source = '/approved-source'
        startup = {'uid':10006,'gid':10006,'umask':None,'args':['/bin/fixture'],'env':['PATH=/bin','HOSTNAME=$OUF_HOSTNAME'],'cwd':'/'}
        template['expectedOci']['process'].update({k:startup[k] for k in ('args','env','cwd')})
        template['expectedOci']['process']['env']=['PATH=/bin','HOSTNAME=$OUF_HOSTNAME']
        launch = {'schema':'ouf.semantic-creation-frame-launch.v1', 'startup':startup,
            'manifest':{'user':'10006:10006','readOnlyRoot':True,'memoryBytes':268435456,'pidsLimit':128,
                        'mounts':[{'source':source,'target':source,'readOnly':True}]},
            'sources':[{'source':source,'target':source,'readOnly':True,'uid':10006,'gid':10006,'mode':384,'maxBytes':131072,'sha256':'e'*64}]}
        for mount in template['expectedOci']['mounts']:
            if mount['destination']==source:mount['source']=source
        context = {'schema':'ouf.semantic-docker-frame-context.v1','containerId':cid,
            'bundleParent':'/run/docker/runtime-runc/moby','metadataParent':'/var/lib/docker/containers',
            'networkNamespaceParent':'/run/docker/netns','networkNamespaceName':None,
            'cgroupDriver':'systemd','rootfsPath':'/var/lib/docker/rootfs/overlayfs/'+cid,'storageParent':'/var/lib/docker'}
        policy = compile_policy(template,launch,context)
        candidate = {'containerId':cid,'transactionId':digest(role.encode()),'networkBindings':[],
                     'transport':[{'purpose':'DNS','authorityRef':'fixture','source':'172.22.0.3',
                                   'destination':'46.38.225.230','protocol':'udp','port':53,'peerIngress':{'kind':'HOST'}}],
                     'tableName':'fixture','runtimeBinding':self.runtime}
        preparer = {'schema':'ouf.semantic-admission-preparer-template.v1', 'candidate':candidate,
            'commands':{'ip':'/usr/bin/ip','nsenter':'/usr/bin/nsenter'},
            'commandHashes':{'ip':'1'*64,'nsenter':'2'*64},'pythonPath':self.python['path'],'pythonHash':self.python['sha256']}
        values = {'template':template,'launch':launch,'context':context,'framePolicy':policy,'preparerTemplate':preparer,
            'deploymentConstraints':{'fixtureOnly':True},'provenanceEvidence':{'fixturePublisher':'disposable'},
            'dependencyEvidence':{'fixtureScan':'disposable'}}
        records = {k:encoded(v) for k,v in values.items()}
        review = {'schema':'ouf.semantic-provider-target-review.v1','issuerRef':AUTHORITIES['approvalIssuerRef'],
            'installationRef':AUTHORITIES['installationRef'],'entityRef':AUTHORITIES['entityRef'],'role':role,**target,
            **{k+'Hash':digest(raw) for k,raw in records.items()},
            'sourceClosureHash':digest(encoded({**{p:digest(raw) for p,raw in self.sources.items()},'frame-observer.py':digest(self.observer)})),
            'decision':'ACCEPT_PROVIDER_IMAGE_AND_COMPLETE_FRAME','state':'ACTIVE','issuedAt':self.now,'expiresAt':self.now+240}
        intent = {'schema':'ouf.semantic-deployment-intent.v1','issuerRef':AUTHORITIES['intentIssuerRef'],
            'installationRef':AUTHORITIES['installationRef'],'entityRef':AUTHORITIES['entityRef'],
            'containerId':cid,'transactionId':candidate['transactionId'],'artifactHash':digest(records['framePolicy']),
            'deploymentConstraintsHash':digest(records['deploymentConstraints']),
            'transportHash':digest(encoded({k:candidate[k] for k in ('networkBindings','transport','tableName')})),
            'runtimeExecutableHash':self.runtime['sha256'],'issuedAt':self.now,'expiresAt':self.now+240,
            'infrastructureAuthorized':True,'creationAuthorized':True,'applicationStartAuthorized':False}
        records.update(review=encoded(review),intent=encoded(intent))
        scope = {k:intent[k] for k in ('installationRef','entityRef','containerId','transactionId','artifactHash',
                                      'deploymentConstraintsHash','transportHash','runtimeExecutableHash')}
        scope['intentHash']=digest(records['intent'])
        values['liveAuthorization'] = {'schema':'ouf.semantic-node-live-acceptance-authorization.v1',
            'issuerRef':AUTHORITIES['attestorRef'],**scope,'applicationHash':digest(encoded(policy['expectedOci'])),
            'rootfsSeal':target['runtimeSeal'],'generationBinding':'OBSERVED_CREATED','state':'ACTIVE',
            'mandateIssuanceAuthorized':True,'attestationAuthorized':True,'completeCreationAccepted':True,
            'issuedAt':self.now,'expiresAt':self.now+240}
        values['finalMandate'] = {'schema':'ouf.semantic-final-approval-mandate.v1','issuerRef':AUTHORITIES['approvalIssuerRef'],
            **scope,'approvalRef':'disposable-ci','state':'ACTIVE','issuanceAuthorized':True,'applicationStartAuthorized':True,
            'issuedAt':self.now,'expiresAt':self.now+240}
        records.update({k:encoded(values[k]) for k in ('liveAuthorization','finalMandate')})
        for name, signature_role, issuer in [('review','FINAL_DEPLOYMENT_APPROVAL',AUTHORITIES['approvalIssuerRef']),
            ('intent','DEPLOYMENT_INTENT',AUTHORITIES['intentIssuerRef']),
            ('liveAuthorization','CREATION_ATTESTATION',AUTHORITIES['attestorRef']),
            ('finalMandate','FINAL_DEPLOYMENT_APPROVAL',AUTHORITIES['approvalIssuerRef'])]:
            self.sign(records[name],signature_role,issuer)
        return records

    def validate(self,role='adapter'):
        return authenticate_role(role,self.records[role],self.authority,self.sources,self.observer,self.verifier,self.clock)

    def alter(self,name,key,value,role='adapter',resign=False):
        import json
        record=json.loads(self.records[role][name]);record[key]=value;raw=encoded(record);self.records[role][name]=raw
        if resign:
            signing_role='CREATION_ATTESTATION' if name=='liveAuthorization' else 'FINAL_DEPLOYMENT_APPROVAL'
            self.sign(raw,signing_role,record['issuerRef'])

    def test_real_signed_complete_input_and_staged_plan(self):
        before = {p:p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        plan = build_install_plan('/private/transaction','/private/reviewed-source',self.records,self.authority,self.sources,
            self.observer,self.python,self.crypto,self.verifier,self.adapter,self.clock)
        self.assertEqual(set(plan['adapterConfiguration']['candidates']),{v['containerId'] for v in TARGETS.values()})
        self.assertFalse(plan['startAuthorized']);self.assertEqual(plan['targetWrites'],0)
        self.assertEqual(before,{p:p.read_bytes() for p in self.root.rglob('*') if p.is_file()})
        adapter_module=importlib.import_module('scripts.semantic_provider_docker_runtime')
        import json
        for cid in plan['adapterConfiguration']['candidates']:
            journal=json.loads(plan['files']['/private/transaction/registry/'+cid+'/adapter.json'])
            self.assertEqual(journal['configurationHash'],adapter_module.binding(plan['adapterConfiguration'],cid))
            self.assertEqual(journal['state'],'STAGED')

    def test_unsigned_ci_booleans_cannot_authorize(self):
        path=self.signatures/(digest(self.records['adapter']['liveAuthorization'])+'.CREATION_ATTESTATION.json');path.unlink()
        with self.assertRaises(TransactionDenied) as raised:self.validate()
        self.assertFalse(raised.exception.diagnosis['secretValuesPrinted'])

    def test_complete_context_drift(self):
        self.alter('context','rootfsPath','/var/lib/docker/rootfs/foreign')
        with self.assertRaises(TransactionDenied) as raised:self.validate()
        self.assertEqual(raised.exception.diagnosis['differentFields'],['contextHash'])

    def test_portable_seal_substitution_even_with_real_signature(self):
        seal=copy.deepcopy(TARGETS['adapter']['runtimeSeal']);seal['sha256']='f'*64
        self.alter('liveAuthorization','rootfsSeal',seal,resign=True)
        with self.assertRaises(TransactionDenied) as raised:self.validate()
        self.assertEqual(raised.exception.diagnosis['differentFields'],['rootfsSeal'])

    def test_independent_config_digest_not_manifest_substitution(self):
        self.alter('review','imageConfigDigest',TARGETS['adapter']['imageManifestDigest'],resign=True)
        with self.assertRaises(TransactionDenied) as raised:self.validate()
        self.assertEqual(raised.exception.diagnosis['differentFields'],['imageConfigDigest'])

    def test_source_byte_drift_rejected(self):
        self.sources['tools/semantic_provider_node_attestor.py']+=b'\n# altered\n'
        with self.assertRaises(TransactionDenied) as raised:self.validate()
        self.assertEqual(raised.exception.diagnosis['differentFields'],['sourceClosureHash'])

    def test_expired_authority_rejected(self):
        self.now+=241
        with self.assertRaises(TransactionDenied):self.validate()

    def test_tampered_signature_rejected(self):
        import json
        path=self.signatures/(digest(self.records['adapter']['review'])+'.FINAL_DEPLOYMENT_APPROVAL.json')
        value=json.loads(path.read_bytes());value['signature']='00'*64;self.private(path,encoded(value))
        with self.assertRaisesRegex(TransactionDenied,'DETACHED_SIGNATURE_INVALID'):self.validate()

    def test_publisher_evidence_drift_rejected(self):
        self.alter('provenanceEvidence','fixturePublisher','changed')
        with self.assertRaises(TransactionDenied) as raised:self.validate()
        self.assertEqual(raised.exception.diagnosis['differentFields'],['provenanceEvidenceHash'])

    def test_missing_role_cannot_create_partial_plan(self):
        del self.records['southbound']
        with self.assertRaisesRegex(TransactionDenied,'EXACT_TWO_TARGET_ROLES_REQUIRED'):
            build_install_plan('/private/transaction','/private/source',self.records,self.authority,self.sources,
                self.observer,self.python,self.crypto,self.verifier,self.adapter,self.clock)


if __name__ == '__main__':unittest.main()
