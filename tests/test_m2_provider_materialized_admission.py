"""Real protocol signatures; prior native provider admission is explicitly modeled."""
import copy,hashlib,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import test_m2_provider_profiles as profiles
import test_m2_discovery_lease_installation_template as workers
from tools.m2_discovery_installation_profile import provider_materialized_admission as m
from tools.m2_discovery_installation_profile import lease_attestation as worker_issuance
from tools.m2_discovery_installation_profile.provider_profiles import ProviderInitialIssuer
from tools.m2_discovery_installation_profile.provider_creation import ProviderCreation
from tools.m2_discovery_installation_profile.provider_profile_publication import ProviderProfilePublication
from tools.semantic_provider_deployment_protocol import validate_final

class Admission(unittest.TestCase):
    def fixture(self):
        case=profiles.Profiles();old,w,auth,state,calls,*_=case.fixture();self.addCleanup(case.doCleanups)
        c,r,s,p,options=workers.Template().fixture();options['source_closure_hash']=old.template['sourceClosureHash']
        options['expected_images']['provider']=old.template['expectedImageId']
        options['expected_node_profiles']['provider']=m.provider_templates.expected_node_profile(old.template)
        options['signing_key_paths']=[str(auth.key)]
        c['verification']['context']={k:auth.context[k] for k in ('installationRef','entityRef','attestorRef')}
        lease=workers.m.template(c,r,p,**options)
        scope=m.admission_scope(lease,old.template,old.creation.scope,old.scope)
        component=copy.deepcopy(old.creation.component);component['admission']=scope
        auth.review['components']['providerInstallation']=component;parent=auth.fixture()
        w.parent=parent;w.parent_hash=parent.sha
        creation=ProviderCreation(parent=parent,window=w,template=old.template,journal_directory=old.creation.root,installation_component=component)
        issuer=ProviderInitialIssuer(creation=creation,scope=old.scope,signers=old.signers)
        pub=ProviderProfilePublication(issuer);reader=m.MaterializedProviderAdmission(publication=pub,lease_template=lease)
        with w.peer_window():
            creation.create_once();issuer.issue_once();pub.apply();material=pub.material()
        root=Path(material['root']);intent=material['payloads']['intent'];ctx=auth.context
        generation={'pid':2345,'startTicks':6789,'namespaceInode':101}
        frame={'schema':'ouf.semantic-container-creation-acceptance.v2','containerId':intent['containerId'],
            'applicationHash':material['materialized']['applicationHash'],'transportHash':intent['transportHash'],
            'accepted':True,'artifactHash':intent['artifactHash'],'creationFrameHash':'7'*64}
        att={'schema':'ouf.semantic-created-candidate-attestation.v2','attestorRef':ctx['attestorRef'],
            **{k:intent[k] for k in ('installationRef','entityRef','containerId','transactionId','artifactHash',
                'deploymentConstraintsHash','transportHash','runtimeExecutableHash')},'intentHash':material['intentHash'],
            'applicationHash':frame['applicationHash'],'generation':generation,'observedAt':auth.now,'creationAcceptance':frame}
        approval={'schema':'ouf.semantic-deployment-admission-approval.v1','issuerRef':ctx['approvalIssuerRef'],
            **{k:intent[k] for k in ('installationRef','entityRef','containerId','transactionId','transportHash')},
            'approvalRef':'SYNTHETIC_PRIOR_NODE_AND_INSTALLER_ADMISSION','applicationHash':frame['applicationHash'],
            'creationAcceptanceHash':m.digest(frame),'issuedAt':auth.now,'expiresAt':auth.now+80,'state':'ACTIVE',
            'infrastructureAuthorized':True,'applicationStartAuthorized':True}
        mandate={'schema':'ouf.semantic-node-creation-acceptance-mandate.v1','issuerRef':ctx['attestorRef'],
            **{k:att[k] for k in ('installationRef','entityRef','containerId','transactionId','intentHash','artifactHash',
                'deploymentConstraintsHash','applicationHash','transportHash','runtimeExecutableHash','generation')},
            'rootfsSeal':issuer.template['expectedRootfsSeal'],'issuedAt':auth.now,'expiresAt':auth.now+80,
            'state':'ACTIVE','attestationAuthorized':True,'completeCreationAccepted':True}
        def signed(name,value,which):
            raw=profiles.m.encoded(value);role=profiles.m.ROLES[which][0];envelope=issuer.signers[which].sign(raw)
            auth.write(auth.signatures/(hashlib.sha256(raw).hexdigest()+'.'+role+'.json'),envelope)
            auth.write(root/name,raw);return raw
        att_raw=signed('attestation.json',att,'live');approval_raw=signed('approval.json',approval,'approval')
        signed('node-acceptance.json',mandate,'live')
        evidence=validate_final(profiles.m.encoded(intent),att_raw,approval_raw,ctx,auth.verifier,parent.clock)
        consumption={'schema':'ouf.semantic-deployment-consumption.v1',
            **{k:intent[k] for k in ('installationRef','entityRef','containerId','transactionId')},
            'intentHash':material['intentHash'],'configurationHash':m.digest(material['profiles']['broker.json']),
            'state':'STARTED','bundleHash':frame['applicationHash'],'generation':generation,
            'evidenceHash':m.digest(evidence),'approvalHash':evidence['approvalHash'],'driverHash':'8'*64}
        auth.write(root/'deployment.json',profiles.m.encoded(consumption))
        adapter=profiles.m.decode(material['files'][str(root/'adapter.json')]);adapter.update(state='STARTED',
            runtimeRoot='/fixture/runc/runtime',bundleHash=frame['applicationHash'],driverHash=consumption['driverHash'])
        auth.write(root/'adapter.json',profiles.m.encoded(adapter))
        snapshot={'desiredProfileHash':lease['configurationTemplate']['desiredProfileHash'],
            'peers':{'provider':{'containerId':intent['containerId'],'imageId':issuer.template['expectedImageId'],
                'pid':generation['pid'],'startTicks':generation['startTicks'],'namespace':{'identity':[1,generation['namespaceInode']]}}},
            'profiles':{'provider':{**lease['expectedNodeProfiles']['provider'],'applicationHash':frame['applicationHash']}}}
        return reader,snapshot,auth,root,consumption,adapter
    def test_owned_new_provider_protocol_is_read_only_and_usable_by_worker_scope(self):
        reader,snapshot,auth,root,*_=self.fixture()
        before={p:p.read_bytes() for p in root.iterdir() if p.is_file()}
        proof=reader.current(snapshot)
        self.assertEqual(proof['containerId'],'9'*64);self.assertFalse(proof['nativeObservationPerformedHere'])
        self.assertFalse(proof['providerReadinessProven']);self.assertEqual(proof['signaturesIssued'],0)
        self.assertTrue(all(p.read_bytes()==raw for p,raw in before.items()))
        scope=worker_issuance.issuance_scope(reader.template,reader.scope,directory=str(auth.root/'worker-issuance'),
            signature_directory=str(auth.root/'worker-signatures'),observation_root=str(auth.root/'worker-observations'),
            key_binding=auth.binding(auth.key),key_ref='synthetic-attestor-key')
        self.assertEqual(scope['providerAdmission'],reader.scope)
    def test_started_consumption_and_adapter_are_both_mandatory_without_reset(self):
        reader,snapshot,auth,root,consumption,adapter=self.fixture()
        for filename,value in [('deployment.json',{**consumption,'state':'READY'}),('adapter.json',{**adapter,'state':'CREATED'})]:
            p=root/filename;old=p.read_bytes();auth.write(p,profiles.m.encoded(value))
            with self.assertRaises((ValueError,RuntimeError)):reader.current(snapshot)
            self.assertEqual(p.read_bytes(),profiles.m.encoded(value));auth.write(p,old)
    def test_wrong_generation_and_old_provider_cannot_be_adopted(self):
        reader,snapshot,*_=self.fixture()
        for field,value in [('containerId','e'*64),('pid',3456),('startTicks',1)]:
            wrong=copy.deepcopy(snapshot);wrong['peers']['provider'][field]=value
            with self.assertRaisesRegex(ValueError,'SAME_OWNED_PROVIDER'):reader.current(wrong)
    def test_missing_signature_or_wrong_rootfs_mandate_cannot_reach_worker_admission(self):
        reader,snapshot,auth,root,*_=self.fixture()
        p=root/'node-acceptance.json';old=p.read_bytes();value=profiles.m.decode(old);value['rootfsSeal']['sha256']='f'*64
        auth.write(p,profiles.m.encoded(value))
        with self.assertRaisesRegex(ValueError,'SIGNED_NEW_PROVIDER_ROOTFS'):reader.current(snapshot)
        auth.write(p,old);p=auth.signatures/(hashlib.sha256((root/'attestation.json').read_bytes()).hexdigest()+'.CREATION_ATTESTATION.json');p.unlink()
        with self.assertRaises(FileNotFoundError):reader.current(snapshot)

if __name__=='__main__':unittest.main()
