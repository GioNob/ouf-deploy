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
from unittest.mock import patch

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
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TRANSACTION_TEST_ROOT',Path.cwd()), prefix='transaction-test-')
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
            'dependencyEvidence':self.dependency_evidence(role)}
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

    def dependency_evidence(self,role):
        from datetime import datetime,timezone
        built=datetime.fromtimestamp(self.now-60,timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        return {'schema':'ouf.semantic-provider-dependency-evidence.v1','role':role,
            'imageConfigDigest':TARGETS[role]['imageConfigDigest'],
            'databasePin':{'status':'active','schemaVersion':'v6.1.10','built':built,
                           'path':'disposable-ci-db.tar.zst','checksum':'sha256:'+'a'*64},
            'reportSha256':'b'*64,'inventorySha256':'c'*64,'sourceArtifactSha256':'d'*64,
            'scanDatabaseBuilt':built,'scanDatabaseSchemaVersion':'v6.1.10',
            'severityCounts':{key:0 for key in ('Critical','High','Medium','Low','Negligible','Unknown')},
            'packageAlertCount':0,'ignoredMatchCount':0}

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

    def installation(self):
        from publish_provider_transaction import publish_plan
        root=self.root/'installed'
        plan=build_install_plan(str(root),str(root/'source'),self.records,self.authority,self.sources,
            self.observer,self.python,self.crypto,self.verifier,self.adapter,self.clock)
        return root,plan,publish_plan

    def test_durable_publication_and_replay_denial(self):
        root,plan,publish=self.installation()
        report=publish(root,plan,self.sources,self.observer)
        self.assertFalse(report['runtimeConfigurationChanged'])
        self.assertTrue((root/'installation-receipt.json').is_file())
        for name,sha in report['fileHashes'].items():
            self.assertEqual(digest(Path(name).read_bytes()),sha)
            self.assertEqual(Path(name).stat().st_mode & 0o777,0o600)
        with self.assertRaisesRegex(TransactionDenied,'EXISTING_TRANSACTION_EVIDENCE_PRESERVED'):
            publish(root,plan,self.sources,self.observer)

    def test_failed_publication_preserves_claim_and_diagnosis(self):
        root,plan,publish=self.installation()
        import publish_provider_transaction as module
        actual=module.publish_once
        def fail(path,raw):
            if path.name=='broker.json':raise OSError('private data must never appear in the diagnosis')
            return actual(path,raw)
        with patch.object(module,'publish_once',side_effect=fail):
            with self.assertRaises(TransactionDenied) as raised:publish(root,plan,self.sources,self.observer)
        self.assertTrue((root/'installation-claim.json').is_file())
        self.assertTrue(raised.exception.diagnosis['doNotRerunApply'])
        self.assertNotIn('private data',(root/'installation-denial.json').read_text())

    def test_switch_custody_rechecks_authenticated_published_profiles(self):
        from guarded_runtime_switch import verify_installed_plan
        root,plan,publish=self.installation();publish(root,plan,self.sources,self.observer)
        self.assertEqual(verify_installed_plan(plan)['configurationHash'],digest(encoded(plan['adapterConfiguration'])))
        path=next(Path(p) for p in plan['files'] if p.endswith('/broker.json'))
        self.private(path,b'{}')
        with self.assertRaisesRegex(TransactionDenied,'INSTALLED_PROFILE_OR_JOURNAL_DRIFT'):verify_installed_plan(plan)

    def activation(self,root,commands=None,wrapper=None):
        from docker_cohort_activation import activate
        return activate(root,self.records,self.authority,self.sources,self.observer,self.python,self.crypto,
            self.adapter,self.activation_receipt if hasattr(self,'activation_receipt') else {},
            getattr(self,'activation_owner_hash','0'*64),commands or {},wrapper or str(self.root/'wrapper'))

    def test_cohort_missing_signature_never_requests_docker(self):
        root,plan,publish=self.installation();publish(root,plan,self.sources,self.observer)
        (self.signatures/(digest(self.records['adapter']['review'])+'.FINAL_DEPLOYMENT_APPROVAL.json')).unlink()
        with self.assertRaisesRegex(TransactionDenied,'SIGNED_TARGET_RECORD_MISSING') as raised:self.activation(root)
        self.assertEqual(raised.exception.diagnosis['dockerStartRequests'],0)
        self.assertFalse((root/'cohort-activation-claim.json').exists())

    def test_cohort_uninstalled_wrapper_never_requests_docker(self):
        root,plan,publish=self.installation();publish(root,plan,self.sources,self.observer)
        wrapper=self.root/'wrapper';wrapper.write_bytes(b'#!/bin/sh\nexit 99\n');wrapper.chmod(0o755)
        with self.assertRaisesRegex(TransactionDenied,'AUTHENTICATED_RUNTIME_WRAPPER_NOT_INSTALLED') as raised:self.activation(root)
        self.assertEqual(raised.exception.diagnosis['dockerStartRequests'],0)

    def test_cohort_claim_cannot_be_replayed(self):
        root,plan,publish=self.installation();publish(root,plan,self.sources,self.observer)
        self.private(root/'cohort-activation-claim.json',b'{"state":"ACTIVATING"}')
        with self.assertRaisesRegex(TransactionDenied,'DO_NOT_REPLAY_DOCKER_COHORT') as raised:self.activation(root)
        self.assertTrue(raised.exception.diagnosis['doNotRerunApply'])
        self.assertEqual(raised.exception.diagnosis['dockerStartRequests'],0)

    def test_cohort_partial_command_failure_retains_uncertain_claim_without_retry(self):
        # Real signatures, files and child processes; guard/Docker behavior are
        # synthetic here. This is orchestration fault proof, NOT native admission.
        from guarded_runtime_switch import wrapper_bytes
        root,plan,publish=self.installation();publish(root,plan,self.sources,self.observer)
        wrapper=self.root/'wrapper';raw=wrapper_bytes(self.python['path'],root/'source',root/'runtime-configuration-proposal.json')
        wrapper.write_bytes(raw);wrapper.chmod(0o755)
        self.private(root/'runtime-switch-receipt.json',encoded({'status':'WRAPPER_SWITCHED','installedWrapperHash':digest(raw)}))
        lock=root/'guard.lock';self.private(lock,b'')
        owner=root/'owner.json';self.private(owner,encoded({'commonLockFile':str(lock)}));self.activation_owner_hash=digest(owner.read_bytes())
        # activate resolves this exact filename under the receipt directory.
        configured=root/'coordinated-configuration.json';self.private(configured,owner.read_bytes())
        receipt=root/'guard-receipt.json';self.private(receipt,encoded({'directory':str(root)}));self.activation_receipt=self.bind(receipt)
        failed=TARGETS['adapter']['containerId']
        script=root/'docker-fixture'
        script.write_text('#!'+self.python['path']+'\nimport sys,json\nfrom pathlib import Path\ncid=sys.argv[-1]\n'
            'if "start" in sys.argv:\n print(cid);sys.exit(1 if cid=='+repr(failed)+' else 0)\n'
            'print(json.dumps({"id":cid,"image":"fixture","runtime":"ci-only","state":{"Status":"created","Running":False,"Pid":0,"StartedAt":"0001-","Error":"private secret must not appear"}}))\n')
        script.chmod(0o755)
        commands={'docker':self.bind(script)}
        with patch('docker_cohort_activation.make_locked_switch_verifier',return_value=lambda fd,phase:None):
            with self.assertRaisesRegex(TransactionDenied,'COHORT_ADMITTED_RUNNING_STATE_UNPROVEN') as raised:
                self.activation(root,commands)
        self.assertEqual(raised.exception.diagnosis['dockerStartRequests'],2)
        self.assertFalse(raised.exception.diagnosis['automaticRetryPerformed'])
        self.assertTrue(raised.exception.diagnosis['doNotRerunApply'])
        self.assertFalse((root/'cohort-activation-receipt.json').exists())
        denial=(root/'cohort-activation-denial.json').read_text()
        self.assertNotIn('private secret',denial)
        self.assertEqual(__import__('json').loads(denial)['cohortOutcome'],'UNPROVEN')

    def test_switch_custody_rejects_published_source_drift(self):
        from guarded_runtime_switch import verify_installed_plan
        root,plan,publish=self.installation();publish(root,plan,self.sources,self.observer)
        self.private(root/'source'/'frame-observer.py',b'changed')
        with self.assertRaisesRegex(TransactionDenied,'INSTALLED_SOURCE_CLOSURE_DRIFT'):verify_installed_plan(plan)

    def test_publication_path_escape_refused_before_writes(self):
        root,plan,publish=self.installation()
        plan['files'][str(root/'..'/'outside.json')]=b'{}'
        with self.assertRaisesRegex(TransactionDenied,'PRIVATE_PUBLICATION_PATH_OR_SIZE_DENIED'):
            publish(root,plan,self.sources,self.observer)
        self.assertFalse(root.exists())

    def source_package(self):
        import json
        package=self.root/'package';package.mkdir(mode=0o700)
        manifest_path=HERE/'intake-source-closure.json'
        manifest=json.loads(manifest_path.read_bytes())
        self.private(package/'intake-source-closure.json',manifest_path.read_bytes())
        for name in manifest['sourceHashes']:
            if name.startswith('source/'):origin=DRAFT/name.removeprefix('source/')
            elif name.startswith('utility/'):
                module=Path(name).name
                origin=(HERE.parent/'semantic_frame_compiler' if module=='compile_creation_frame_policy.py' else HERE)/module
            else:origin=HERE.parent/'semantic_frame_compiler/frame-observer.py'
            destination=package/name;destination.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            self.private(destination,origin.read_bytes())
        return package

    def load_subprocess(self,package):
        script=HERE/'provider_transaction_intake.py'
        code="import runpy;from pathlib import Path;module=runpy.run_path("+repr(str(script))+" );module['load'](Path("+repr(str(package))+"))"
        return subprocess.run([sys.executable,'-I','-B','-c',code],stdout=subprocess.PIPE,stderr=subprocess.PIPE)

    def test_isolated_source_loader_accepts_closed_bytes(self):
        package=self.source_package();result=self.load_subprocess(package)
        self.assertEqual(result.returncode,0,result.stderr.decode())

    def test_isolated_source_loader_refuses_modified_code_before_execution(self):
        package=self.source_package()
        self.private(package/'utility/assemble_provider_profiles.py',b"raise RuntimeError('UNREVIEWED_EXECUTION')")
        result=self.load_subprocess(package)
        self.assertNotEqual(result.returncode,0)
        self.assertIn(b'PRIVATE_INTAKE_HASH_DRIFT',result.stderr)
        self.assertNotIn(b'UNREVIEWED_EXECUTION',result.stderr)

    def issue_inputs(self):
        from issue_provider_transaction_authority import INPUTS,SCOPES,issue_role_authority
        role='adapter';inputs={name:raw for name,raw in self.records[role].items() if name in INPUTS}
        import json
        intent=json.loads(self.records[role]['intent'])
        mandate={'schema':'ouf.semantic-provider-transaction-role-mandate.v1','role':role,
            'installationRef':AUTHORITIES['installationRef'],'entityRef':AUTHORITIES['entityRef'],**TARGETS[role],
            'inputHashes':{name:digest(raw) for name,raw in inputs.items()},
            'sourceClosureHash':digest(encoded({**{name:digest(raw) for name,raw in self.sources.items()},'frame-observer.py':digest(self.observer)})),
            'roleSigningScopes':SCOPES,'state':'ACTIVE','decision':'ACCEPT_PROVIDER_IMAGE_AND_COMPLETE_FRAME_AND_CONTROLLED_ADMISSION',
            'transactionId':intent['transactionId'],'approvalRef':'explicit-ci-root-approval','issuedAt':self.now,'expiresAt':self.now+240}
        path=self.root/'root-role-mandate.json';self.private(path,encoded(mandate))
        output=self.root/'authority-output';output.mkdir(mode=0o700)
        # Remove the preceding fixture signatures so this tests the actual
        # production signing primitive and its exact issuance/custody path.
        for path in self.signatures.iterdir():path.unlink()
        return issue_role_authority,inputs,mandate,self.bind(self.root/'root-role-mandate.json'),output

    def test_existing_keys_issue_only_explicit_root_scopes(self):
        issue,inputs,mandate,binding,output=self.issue_inputs()
        result=issue('adapter',binding,binding['sha256'],inputs,self.authority,self.sources,self.observer,self.verifier,output,self.clock)
        self.assertEqual(result['signaturesIssued'],4)
        self.assertFalse(result['startPerformed'])
        records={**inputs,**{name:Path(item['path']).read_bytes() for name,item in result['records'].items()}}
        authenticate_role('adapter',records,self.authority,self.sources,self.observer,self.verifier,self.clock)
        with self.assertRaisesRegex(Exception,'EXISTING_ROLE_AUTHORITY_EVIDENCE_PRESERVED'):
            issue('adapter',binding,binding['sha256'],inputs,self.authority,self.sources,self.observer,self.verifier,output,self.clock)

    def test_no_implicit_root_signing_without_explicit_approved_hash(self):
        issue,inputs,mandate,binding,output=self.issue_inputs()
        with self.assertRaisesRegex(TransactionDenied,'EXPLICIT_APPROVED_ROOT_MANDATE_HASH_REQUIRED'):
            issue('adapter',binding,None,inputs,self.authority,self.sources,self.observer,self.verifier,output,self.clock)
        self.assertEqual(list(output.iterdir()),[])

    def test_root_mandate_preflight_never_reads_keys_or_publishes(self):
        from unittest.mock import patch
        issue,inputs,mandate,binding,output=self.issue_inputs()
        with patch('issue_provider_transaction_authority.ExistingEd25519Signer',side_effect=AssertionError('KEY_READ')):
            result=issue('adapter',binding,binding['sha256'],inputs,self.authority,self.sources,
                         self.observer,self.verifier,output,self.clock,validate_only=True)
        self.assertEqual(result['privateKeysRead'],0)
        self.assertEqual(result['signaturesIssued'],0)
        self.assertEqual(list(output.iterdir()),[])
        self.assertEqual(list(self.signatures.iterdir()),[])

    def denied_dependency_before_signing(self,offset,critical=0):
        from datetime import datetime,timezone
        import json
        issue,inputs,mandate,binding,output=self.issue_inputs()
        value=json.loads(inputs['dependencyEvidence'])
        built=datetime.fromtimestamp(self.now+offset,timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        value['databasePin']['built']=value['scanDatabaseBuilt']=built
        value['severityCounts']['Critical']=critical
        inputs['dependencyEvidence']=encoded(value)
        mandate['inputHashes']['dependencyEvidence']=digest(inputs['dependencyEvidence'])
        path=Path(binding['path']);self.private(path,encoded(mandate));binding=self.bind(path)
        with patch('issue_provider_transaction_authority.ExistingEd25519Signer',side_effect=AssertionError('KEY_READ')):
            with self.assertRaises(TransactionDenied) as raised:
                issue('adapter',binding,binding['sha256'],inputs,self.authority,self.sources,
                      self.observer,self.verifier,output,self.clock)
        self.assertEqual(list(output.iterdir()),[])
        self.assertEqual(raised.exception.diagnosis['stage'],'VERIFY_REVIEWED_DEPENDENCY_FRESHNESS')
        return raised.exception.diagnosis['reason']

    def test_expired_database_denied_even_with_matching_root_mandate(self):
        self.assertEqual(self.denied_dependency_before_signing(-48*3600),
                         'DATABASE_FRESHNESS_DOES_NOT_COVER_AUTHORITY_WINDOW')

    def test_future_database_denied_before_signing(self):
        self.assertEqual(self.denied_dependency_before_signing(1),
                         'DATABASE_FRESHNESS_DOES_NOT_COVER_AUTHORITY_WINDOW')

    def test_database_must_cover_entire_approved_window(self):
        self.assertEqual(self.denied_dependency_before_signing(-48*3600+120),
                         'DATABASE_FRESHNESS_DOES_NOT_COVER_AUTHORITY_WINDOW')

    def test_critical_dependency_cannot_be_overridden_by_root_mandate(self):
        self.assertEqual(self.denied_dependency_before_signing(-60,1),
                         'REVIEWED_DEPENDENCY_THRESHOLD_NOT_MET')

    def test_valid_review_signature_cannot_extend_expired_database(self):
        import json
        from datetime import datetime,timezone
        value=json.loads(self.records['adapter']['dependencyEvidence'])
        built=datetime.fromtimestamp(self.now-48*3600,timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        value['databasePin']['built']=value['scanDatabaseBuilt']=built
        self.records['adapter']['dependencyEvidence']=encoded(value)
        self.alter('review','dependencyEvidenceHash',digest(encoded(value)),resign=True)
        with self.assertRaisesRegex(TransactionDenied,'DATABASE_FRESHNESS_DOES_NOT_COVER_AUTHORITY_WINDOW'):
            self.validate()

    def test_root_review_input_drift_rejected_before_key_read(self):
        issue,inputs,mandate,binding,output=self.issue_inputs()
        inputs['dependencyEvidence']=b'{"changed":true}'
        with self.assertRaisesRegex(TransactionDenied,'ROOT_ROLE_REVIEW_SCOPE_DRIFT'):
            issue('adapter',binding,binding['sha256'],inputs,self.authority,self.sources,self.observer,self.verifier,output,self.clock)
        self.assertEqual(list(output.iterdir()),[])

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
