"""Real scoped Ed25519; observation/HUMAN/installation are synthetic fixtures.
Crypto/report consistency is not a full native node acceptance qualification.
"""
import copy,json,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tests'),str(ROOT/'tools/semantic_application_cutover')]
import test_cutover_authority_native as signed_fixture
from paused_node_acceptance import PausedNodeAcceptance,REVIEWED
from tools.semantic_provider_deployment_authentication import DetachedAuthenticator,signing_bytes
from tools.semantic_provider_preexec import PreexecDenied

class Acceptance(unittest.TestCase):
    def setUp(self):
        signed_fixture.SignedCutover.setUp(self)
        self.expected_node={k:'a'*64 for k in REVIEWED};self.cid='b'*64
        policy=json.loads(self.policy.read_bytes());self.attestor=policy['keys'][1];self.attestor['publicKey']=self.grant['publicKey']
        self.write(self.policy,signed_fixture.encoded(policy));self.verifier.policy_binding=self.binding(self.policy)
        self.ctx={k:self.context[k] for k in ('installationRef','entityRef','attestorRef')}
        self.seal={'schema':'ouf.semantic-rootfs-seal.v1','sha256':'c'*64,'entries':3,'bytes':64}
        self.payload={'schema':'ouf.semantic-paused-node-acceptance-authorization.v1','issuerRef':self.ctx['attestorRef'],
                      'installationRef':self.ctx['installationRef'],'entityRef':self.ctx['entityRef'],**self.expected_node,
                      'containerId':self.cid,'generationBinding':'OBSERVED_PAUSED_GATED','rootfsSeal':self.seal,
                      'issuedAt':self.now,'expiresAt':self.now+120,'state':'ACTIVE','attestationAuthorized':True,'completeCreationAccepted':True}
        generation={'pid':1234,'startTicks':23,'namespaceInode':24}
        self.report={'schema':'ouf.semantic-paused-node-observation.v1','applicationHash':'a'*64,'rootfsSeal':copy.deepcopy(self.seal),
                     'creationFrameHash':'d'*64,'state':{'id':self.cid,'status':'paused','pid':1234},'generation':generation,
                     'nativeStateContract':{'stateContract':'RUNC_PAUSED_ENGINE_PAUSED','containerId':self.cid,'pid':1234}}
        self.sign_node()
    sign=signed_fixture.SignedCutover.sign
    native=signed_fixture.SignedCutover.native
    write=signed_fixture.SignedCutover.write
    binding=signed_fixture.SignedCutover.binding
    def sign_node(self):
        self.raw=signed_fixture.encoded(self.payload);h=signed_fixture.sha(self.raw)
        header={'schema':'ouf.semantic-deployment-detached-signature.v1','algorithm':'Ed25519','keyRef':self.attestor['keyRef'],
                'role':'CREATION_ATTESTATION','issuerRef':self.ctx['attestorRef'],'installationRef':self.ctx['installationRef'],
                'entityRef':self.ctx['entityRef'],'payloadHash':h}
        frame=self.root/'node-frame';self.write(frame,signing_bytes(self.raw,header));signature=self.native('pkeyutl','-sign','-rawin','-inkey',str(self.key),'-in',str(frame))
        self.write(self.signatures/(h+'.CREATION_ATTESTATION.json'),signed_fixture.encoded({**header,'signature':signature.hex()}))
    def gate(self):return PausedNodeAcceptance(self.verifier,self.ctx,self.expected_node,self.clock)
    def test_actual_scoped_signature_and_exact_report_match_without_native_proof_claim(self):
        result=self.gate().verify(self.raw,self.report,self.cid);self.assertTrue(result['currentRoleSignatureVerified'])
        self.assertFalse(result['observedReportAuthenticatedHere']);self.assertFalse(result['nativeObservationPerformedHere']);self.assertFalse(result['startAuthorized'])
    def test_wrong_oci_rootfs_generation_or_created_contract_cannot_use_paused_acceptance(self):
        for drift in ('oci','rootfs','pid','state'):
            report=copy.deepcopy(self.report)
            if drift=='oci':report['applicationHash']='e'*64
            if drift=='rootfs':report['rootfsSeal']['sha256']='e'*64
            if drift=='pid':report['generation']['pid']=1235
            if drift=='state':report['state']['status']='created'
            with self.assertRaises(ValueError):self.gate().verify(self.raw,report,self.cid)
    def test_missing_corrupt_or_revoked_scoped_signature_denies(self):
        path=self.signatures/(signed_fixture.sha(self.raw)+'.CREATION_ATTESTATION.json');value=json.loads(path.read_bytes());value['signature']='0'*128;self.write(path,signed_fixture.encoded(value))
        with self.assertRaises(PreexecDenied):self.gate().verify(self.raw,self.report,self.cid)
        path.unlink()
        with self.assertRaises((PreexecDenied,OSError)):self.gate().verify(self.raw,self.report,self.cid)
        self.sign_node();self.now+=121
        with self.assertRaises(ValueError):self.gate().verify(self.raw,self.report,self.cid)
    def test_noop_verifier_or_wrong_reviewed_frame_is_not_authority(self):
        with self.assertRaises(ValueError):PausedNodeAcceptance(lambda *_:True,self.ctx,self.expected_node,self.clock)
        expected={**self.expected_node,'artifactHash':'e'*64}
        with self.assertRaises(ValueError):PausedNodeAcceptance(self.verifier,self.ctx,expected,self.clock).verify(self.raw,self.report,self.cid)

if __name__=='__main__':unittest.main()
