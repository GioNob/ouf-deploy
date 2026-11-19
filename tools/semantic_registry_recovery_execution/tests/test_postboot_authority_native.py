"""Actual new issuer/load_runtime and Ed25519 in disposable private custody.

Current context collection, source/executable custody and terminal HUMAN are
explicit substitutes. No target, owner grant, JVM or full recovery qualification.
"""
from pathlib import Path
import json
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[3]
CHILD = r'''
import copy,hashlib,importlib.util,json,os,pathlib,shutil,subprocess,sys,tempfile,time
from unittest.mock import patch
root=pathlib.Path(sys.argv[1])
spec=importlib.util.spec_from_file_location('crypto_postboot_delivery_fixture',root/'tools/semantic_registry_recovery_execution/delivery.py')
d=importlib.util.module_from_spec(spec);spec.loader.exec_module(d)
loader,loader_raw=d.loader_module(root);sources=d.collect_sources(root,loader);commit='a'*40
declaration=loader.declaration(commit,sources,loader_raw,{'ouf-deploy':commit})
entry,manifest=loader.load_entry(commit,sources,loader_raw,loader.digest(declaration),{'ouf-deploy':commit})
from tools.semantic_registry_recovery_execution import postboot_authority as m
from file_only_profile import FileOnlyProfile
enc=m.encoded
sha=lambda raw:hashlib.sha256(raw).hexdigest()
openssl=pathlib.Path(shutil.which('openssl')).resolve(strict=True)
def native(*args):return subprocess.check_output([str(openssl),*args],stderr=subprocess.PIPE,timeout=10)
def write(path,value):path.write_bytes(value);path.chmod(0o600)
def binding(path):return {'path':str(path),'sha256':sha(path.read_bytes())}
with tempfile.TemporaryDirectory(dir=root,prefix='postboot-issuer-crypto-fixture-') as temporary:
 parent=pathlib.Path(temporary);parent.chmod(0o700)
 prepared=parent/('semantic-registry-postboot-inputs-'+'a'*64);prepared.mkdir(mode=0o700)
 now=int(time.time());keys={};public={}
 for label in ('installer','attestor'):
  path=parent/(label+'.pem');native('genpkey','-algorithm','ED25519','-out',str(path));path.chmod(0o600)
  keys[label]=binding(path);public[label]=native('pkey','-in',str(path),'-pubout','-outform','DER')[12:].hex()
 context={'installationRef':'disposable-installation','entityRef':'disposable-entity',
  'intentIssuerRef':'disposable-installer','approvalIssuerRef':'disposable-installer','attestorRef':'disposable-attestor'}
 policy={'schema':'ouf.semantic-deployment-trust-policy.v1','installationRef':context['installationRef'],
  'entityRef':context['entityRef'],'keys':[{'keyRef':'disposable-'+label,'issuerRef':context[key],
   'roles':roles,'publicKey':public[label],'notBefore':now-30,'expiresAt':now+3600,'state':'ACTIVE'}
   for label,key,roles in [('installer','intentIssuerRef',['DEPLOYMENT_INTENT','FINAL_DEPLOYMENT_APPROVAL']),
                          ('attestor','attestorRef',['CREATION_ATTESTATION'])]]}
 policy_path=parent/'policy.json';write(policy_path,enc(policy));policy_binding=binding(policy_path)
 profile={'schema':'ouf.semantic-existing-installation-authority-bindings.v1','authorities':context,
  'policyBinding':policy_binding,'keyRefs':{label:'disposable-'+label for label in keys},'keyBindings':keys}
 profile_path=parent/'profile.json';write(profile_path,enc(profile));profile_binding=binding(profile_path)
 config={'source':'/fixture/config','target':'/fixture/configtree','readOnly':True,'uid':10001,'gid':10001,
  'directoryMode':0o500,'fileName':'OUF_SEM_DB_PASSWORD','fileMode':0o400,'maxBytes':4096,'sha256':'b'*64}
 request={'Image':'sha256:'+'c'*64,'User':'10001:10001','Entrypoint':['java','-XX:MaxRAMPercentage=75','-jar','/app/application.jar'],'Cmd':[],
  'Env':['OUF_SCHEMA_GOV_ENABLED=false','OUF_DISCOVERY_WORKER_ENABLED=false','SPRING_CONFIG_IMPORT=configtree:/fixture/configtree/'],
  'HostConfig':{'RestartPolicy':{'Name':'no','MaximumRetryCount':0},'Binds':['/fixture/config:/fixture/configtree:ro']}}
 execution=FileOnlyProfile(request,config)
 openssl_binding={**binding(openssl),'version':native('version').decode().split()[1]}
 inputs={'authorityProfile':profile_binding,'trustPolicy':policy_binding,'context':context,
  'executables':{'python':binding(pathlib.Path(sys.executable).resolve()),'docker':binding(openssl),'openssl':openssl_binding},
  'stdlibHash':'d'*64,'stdlibFileCount':1}
 review={'schema':m.SCHEMA,'intakeHash':'1'*64,'sourceClosureHash':m.digest(manifest),'creationRequestHash':m.digest(request),
  'predecessorHistoryHash':'2'*64,'predecessorIncidentRef':'3'*64,'executionProfileHash':execution.sha256,
  'deploymentProfile':m.PROFILE,'maximumElapsedSeconds':900,'bootId':'00000000-1111-2222-3333-444444444444',
  'currentContext':{'plan':{'logicalOperationRef':'4'*64}},'ownerContext':{'lineageReceipt':{'logicalOwnerScopeHash':'5'*64},
   'budget':{'maximumGrantAttempts':1}},'authorityInputs':inputs,
  'scopes':{key:{'explicitFixtureOnly':True} for key in m.KEYS}}
 review['scopes']['semanticRegistryPostbootOwner']['predecessorGrantAttempts']=319
 review_hash=m.digest(review);review_binding={'path':str(prepared/'review.json'),'sha256':review_hash}
 decision={'schema':'ouf.semantic-registry-postboot-terminal-decision.v1','approvalRef':'registry-postboot-'+review_hash[:24]+'-'+str(now),
  'approvedReviewHash':review_hash,'approvedSourceClosureHash':review['sourceClosureHash'],'approvedAt':now,'expiresAt':now+900,
  'decision':m.DECISION,'state':'ACTIVE'}
 with patch.object(m,'PARENT',parent),patch.object(m.governance,'PROFILE',profile_binding),patch.object(m.governance,'POLICY',policy_binding),\
      patch.object(m.governance,'CONTEXT',context),patch.object(m,'read_review',side_effect=lambda *_:copy.deepcopy(review)),\
      patch.object(m,'retained',return_value={'creationRequest':request,'configtree':config}),\
      patch.object(m,'execution_custody',return_value=None),patch.object(m,'terminal_decision',return_value=decision) as terminal:
  receipt=m.issue(prepared,review_binding,review_hash)
  assert receipt['runtimeAuthorityIssued'] and not receipt['releaseAcceptance']
  gate,raw,verifier,signer=m.load_runtime(prepared,review_binding)
  assert type(gate) is m.CutoverAuthority and type(verifier) is m.DetachedAuthenticator and type(signer) is m.ExistingEd25519Signer
  assert gate(raw) is True and gate.expected['intakeHash']==review['intakeHash']
  evidence=b'{"disposableNodeEvidence":true}'
  signed=signer.sign(evidence)
  assert verifier.verify_detached(evidence,signed,'CREATION_ATTESTATION',context['attestorRef'],context['installationRef'],context['entityRef']) is True
  try:m.issue(prepared,review_binding,review_hash)
  except RuntimeError as error:assert str(error)=='POSTBOOT_ISSUANCE_ALREADY_CONSUMED'
  else:raise AssertionError('duplicate issuance accepted')
  assert terminal.call_count==1
  signature_path=prepared/'authority'/(sha(raw)+'.FINAL_DEPLOYMENT_APPROVAL.json')
  signature=json.loads(signature_path.read_bytes());signature['role']='DEPLOYMENT_INTENT';write(signature_path,enc(signature))
  try:m.load_runtime(prepared,review_binding)
  except Exception:pass
  else:raise AssertionError('role-swapped signature accepted')
 print(json.dumps({'actualDualRoleSignatures':2,'actualAttestorSignature':1,'duplicateIssuanceBlockedBeforePrompt':True,
  'roleSwapRejected':True,'targetEffects':0,'syntheticCurrentContextAndHuman':True}))
'''


class NativeIssuer(unittest.TestCase):
    def test_actual_issuer_current_dual_role_verification_attestor_and_consumed_claim(self):
        result = subprocess.run([sys.executable, '-I', '-B', '-S', '-', str(ROOT)], input=CHILD.encode(),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45, cwd='/')
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stderr, b'')
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt['actualDualRoleSignatures'], 2)
        self.assertEqual(receipt['actualAttestorSignature'], 1)
        self.assertTrue(receipt['duplicateIssuanceBlockedBeforePrompt'])
        self.assertTrue(receipt['roleSwapRejected'])
        self.assertEqual(receipt['targetEffects'], 0)


if __name__ == '__main__':
    unittest.main()
