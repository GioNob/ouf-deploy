"""Real Ed25519/protocol/custody/claims, synthetic native admissions and boot.

Disposable signed provider records model completed prior creation/consumption.
These tests do not create/admit a real provider or assert target readiness.
"""
import copy,hashlib,sys,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_application_cutover'),
    str(ROOT/'tools/semantic_frame_compiler'),str(ROOT/'tools/semantic_lease_recovery'),
    str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
import test_m2_discovery_lease_file_installation as files
from tools.m2_discovery_installation_profile import lease_attestation as m,provider_admission as p
from tools.semantic_provider_deployment_protocol import validate_final
from tools.semantic_provider_deployment_authentication import signing_bytes


class Attest(unittest.TestCase):
    def fixture(self):
        recipe={'schema':'ouf.discovery-provider-independent-node-recipe.v1','sourceClosureHash':'f'*64,
            'qualifiedPackageHash':'7'*64,'imageConfigurationHash':'c'*64,
            'expectedRootfsSeal':{'schema':'ouf.semantic-rootfs-seal.v1','sha256':'9'*64,'entries':3,'bytes':64},
            'expectedImageId':'sha256:'+'4'*64,'artifactHash':'2'*64,'deploymentConstraintsHash':'3'*64,
            'transportHash':'4'*64,'runtimeExecutableHash':'5'*64}
        f=files.Files();install,intent,auth,material,calls=f.fixture(provider_recipe=recipe);self.addCleanup(f.doCleanups)
        for k in m.PAYLOADS:(auth.signatures/(m.digest(material[k])+'.'+m.ROLE+'.json')).unlink()
        for name in ('provider-admission','attestation-transaction'):(auth.root/name).mkdir(mode=0o700)
        snapshot=material['proposal']['nativeObservation'];peer=snapshot['peers']['provider'];ctx=auth.context
        generation={'pid':peer['pid'],'startTicks':peer['startTicks'],'namespaceInode':peer['namespace']['identity'][1]}
        def signed(value,role):
            raw=m.encoded(value);issuer=ctx['attestorRef'] if role==m.ROLE else ctx['intentIssuerRef']
            ref='synthetic-attestor-key' if role==m.ROLE else 'synthetic-installer-key'
            header={'schema':'ouf.semantic-deployment-detached-signature.v1','algorithm':'Ed25519','keyRef':ref,
                'role':role,'issuerRef':issuer,'installationRef':ctx['installationRef'],'entityRef':ctx['entityRef'],
                'payloadHash':hashlib.sha256(raw).hexdigest()}
            frame=auth.root/'provider-frame';auth.write(frame,signing_bytes(raw,header))
            signature=auth.native('pkeyutl','-sign','-rawin','-inkey',str(auth.key),'-in',str(frame))
            auth.write(auth.signatures/(header['payloadHash']+'.'+role+'.json'),m.encoded({**header,'signature':signature.hex()}))
            return raw
        pi={'schema':'ouf.semantic-deployment-intent.v1','issuerRef':ctx['intentIssuerRef'],
            'installationRef':ctx['installationRef'],'entityRef':ctx['entityRef'],'containerId':peer['containerId'],
            'transactionId':'6'*64,**{k:recipe[k] for k in ('artifactHash','deploymentConstraintsHash','transportHash','runtimeExecutableHash')},
            'issuedAt':auth.now,'expiresAt':auth.now+85,'infrastructureAuthorized':True,'creationAuthorized':True,
            'applicationStartAuthorized':False}
        pi_raw=signed(pi,'DEPLOYMENT_INTENT');application=snapshot['profiles']['provider']['applicationHash']
        acceptance={'schema':'ouf.semantic-container-creation-acceptance.v2','containerId':peer['containerId'],
            'applicationHash':application,'transportHash':recipe['transportHash'],'accepted':True,
            'artifactHash':recipe['artifactHash'],'creationFrameHash':'8'*64}
        att={'schema':'ouf.semantic-created-candidate-attestation.v2','attestorRef':ctx['attestorRef'],
            **{k:pi[k] for k in ('installationRef','entityRef','containerId','transactionId','artifactHash',
                'deploymentConstraintsHash','transportHash','runtimeExecutableHash')},
            'intentHash':hashlib.sha256(pi_raw).hexdigest(),'applicationHash':application,'generation':generation,
            'observedAt':auth.now,'creationAcceptance':acceptance}
        att_raw=signed(att,m.ROLE)
        approval={'schema':'ouf.semantic-deployment-admission-approval.v1','issuerRef':ctx['approvalIssuerRef'],
            **{k:pi[k] for k in ('installationRef','entityRef','containerId','transactionId','transportHash')},
            'approvalRef':'SYNTHETIC_PROVIDER_APPROVAL','applicationHash':application,'creationAcceptanceHash':m.digest(acceptance),
            'issuedAt':auth.now,'expiresAt':auth.now+85,'state':'ACTIVE','infrastructureAuthorized':True,'applicationStartAuthorized':True}
        approval_raw=signed(approval,'FINAL_DEPLOYMENT_APPROVAL')
        mandate={'schema':'ouf.semantic-node-creation-acceptance-mandate.v1','issuerRef':ctx['attestorRef'],
            **{k:att[k] for k in ('installationRef','entityRef','containerId','transactionId','intentHash','artifactHash',
                'deploymentConstraintsHash','applicationHash','transportHash','runtimeExecutableHash','generation')},
            'rootfsSeal':recipe['expectedRootfsSeal'],'issuedAt':auth.now,'expiresAt':auth.now+85,
            'state':'ACTIVE','attestationAuthorized':True,'completeCreationAccepted':True}
        mandate_raw=signed(mandate,m.ROLE)
        evidence=validate_final(pi_raw,att_raw,approval_raw,ctx,auth.verifier,lambda:auth.now)
        consumption={'schema':'ouf.semantic-deployment-consumption.v1',
            **{k:pi[k] for k in ('installationRef','entityRef','containerId','transactionId')},'intentHash':att['intentHash'],
            'configurationHash':'a'*64,'state':'STARTED','bundleHash':application,'generation':generation,
            'evidenceHash':m.digest(evidence),'approvalHash':evidence['approvalHash'],'driverHash':'b'*64}
        records={k:str(auth.root/'provider-admission'/(k+'.json')) for k in p.RECORDS}
        for k,raw in [('intent',pi_raw),('attestation',att_raw),('approval',approval_raw),
            ('acceptanceMandate',mandate_raw),('consumption',m.encoded(consumption))]:auth.write(Path(records[k]),raw)
        provider_scope=p.admission_scope(install.start.template,recipe,records,'a'*64)
        issuance=m.issuance_scope(install.start.template,provider_scope,directory=str(auth.root/'attestation-transaction'),
            signature_directory=str(auth.signatures),observation_root=str(install.probe.root),
            key_binding=auth.binding(auth.key),key_ref='synthetic-attestor-key')
        auth.review['components']['providerInstallation']=provider_scope
        auth.review['components']['operationalLeaseInstallation']=m.attested_component(install.start.template,
            install.start.installation_component,issuance)
        parent=auth.fixture();base=install.start
        start=files.starts.m.LeaseStartAdapter(parent=parent,authority=base.authority,authority_raw=base.authority_raw,
            transition=base.transition,store=base.store,node_owner=base.node_owner,template=base.template,proposal=base.proposal,
            scope=base.scope,intent=intent,publication_directory=base.publication_directory,attestation_scope=issuance)
        installer=files.m.LeaseFileInstallation(start,material,verifier=install.verifier,probe=install.probe)
        provider=p.RetainedProviderAdmission(parent=parent,template=start.template,recipe=recipe,records=records,configuration_hash='a'*64)
        signer=m.ExistingEd25519Signer(auth.binding(auth.key),'synthetic-attestor-key',installer.verifier,
            {'role':m.ROLE,'issuerRef':ctx['attestorRef'],'installationRef':ctx['installationRef'],'entityRef':ctx['entityRef']})
        boot=patch.object(m,'boot_id',return_value=snapshot['bootId']);boot.start();self.addCleanup(boot.stop)
        issuer=m.LeaseAttestationIssuer(installation=installer,provider=provider,signer=signer)
        return issuer,intent,auth,consumption,signed

    def test_current_signed_provider_and_consumption_issue_three_then_publish_existing_installer(self):
        owner,intent,auth,_,_=self.fixture()
        with patch.object(owner.signer,'sign',wraps=owner.signer.sign) as signing:
            owner.issue(intent);self.assertEqual(signing.call_count,3)
            self.assertEqual(owner.observe(intent)[0],'APPLIED');self.assertEqual(signing.call_count,3)
            owner.installation.apply(intent);self.assertEqual(owner.installation.observe(intent)[0],'APPLIED')
            self.assertEqual(signing.call_count,3)
            with self.assertRaises(FileExistsError):owner.issue(intent)
            self.assertEqual(signing.call_count,3)

    def test_provider_reader_alone_performs_no_signing_or_lifecycle(self):
        owner,intent,auth,_,_=self.fixture();snapshot=owner.installation.material['proposal']['nativeObservation']
        proof=owner.provider.current(snapshot);self.assertFalse(proof['providerReadinessProven'])
        self.assertEqual(proof['signaturesIssued'],0);self.assertEqual(list(owner.root.iterdir()),[])

    def test_consumption_starting_or_other_generation_or_evidence_cannot_authorize_signing(self):
        for change in ('state','generation','evidenceHash'):
            owner,intent,auth,row,_=self.fixture()
            if change=='state':row['state']='STARTING'
            elif change=='generation':row['generation']['startTicks']+=1
            else:row['evidenceHash']='f'*64
            auth.write(Path(owner.provider.scope['records']['consumption']),m.encoded(row))
            with patch.object(owner.signer,'sign',side_effect=AssertionError('NO_KEY_ACCESS')):
                with self.assertRaises((ValueError,RuntimeError)):owner.issue(intent)
            self.assertFalse((owner.root/'claim.json').exists())

    def test_missing_provider_rootfs_signature_and_expired_protocol_block_before_claim(self):
        for change in ('signature','expired'):
            owner,intent,auth,_,_=self.fixture()
            if change=='signature':
                raw=Path(owner.provider.scope['records']['acceptanceMandate']).read_bytes()
                (auth.signatures/(hashlib.sha256(raw).hexdigest()+'.'+m.ROLE+'.json')).unlink()
            else:auth.now+=86
            with self.assertRaises((ValueError,RuntimeError,FileNotFoundError)):owner.issue(intent)
            self.assertFalse((owner.root/'claim.json').exists())

    def test_signed_rootfs_mismatch_is_rejected_even_with_valid_role(self):
        owner,intent,auth,_,sign=self.fixture();file=Path(owner.provider.scope['records']['acceptanceMandate'])
        value=m.decode(file.read_bytes());value['rootfsSeal']['sha256']='f'*64;auth.write(file,sign(value,m.ROLE))
        with self.assertRaisesRegex(ValueError,'ROOTFS_AND_GENERATION'):owner.issue(intent)

    def test_legacy_attestation_without_authenticated_creation_frame_is_rejected(self):
        owner,intent,auth,_,sign=self.fixture();file=Path(owner.provider.scope['records']['attestation'])
        value=m.decode(file.read_bytes());value['schema']='ouf.semantic-created-candidate-attestation.v1'
        acceptance=value['creationAcceptance'];acceptance['schema']='ouf.semantic-container-creation-acceptance.v1'
        acceptance.pop('artifactHash');acceptance.pop('creationFrameHash');auth.write(file,sign(value,m.ROLE))
        approval_file=Path(owner.provider.scope['records']['approval']);approval=m.decode(approval_file.read_bytes())
        approval['creationAcceptanceHash']=m.digest(acceptance);auth.write(approval_file,sign(approval,'FINAL_DEPLOYMENT_APPROVAL'))
        with self.assertRaisesRegex(ValueError,'AUTHENTICATED_CREATION_FRAME'):owner.issue(intent)

    def test_lost_signer_result_never_resigns_and_retains_dispatch(self):
        owner,intent,auth,_,_=self.fixture();original=owner.signer.sign;count=[]
        def lose(raw):count.append(1);original(raw);raise TimeoutError('SYNTHETIC_LOST_SIGNING_RESULT')
        with patch.object(owner.signer,'sign',side_effect=lose),self.assertRaises(TimeoutError):owner.issue(intent)
        self.assertEqual(owner.observe(intent)[0],'UNKNOWN')
        with self.assertRaises(FileExistsError):owner.issue(intent)
        self.assertEqual(len(count),1);self.assertTrue((owner.root/'seal-dispatch.json').exists())

    def test_partial_second_signature_is_preserved_without_automatic_completion(self):
        owner,intent,auth,_,_=self.fixture();original=owner.signer.sign;count=[]
        def fail(raw):
            count.append(1)
            if len(count)==2:raise OSError('SYNTHETIC_SIGNER_FAILURE')
            return original(raw)
        with patch.object(owner.signer,'sign',side_effect=fail),self.assertRaises(OSError):owner.issue(intent)
        self.assertEqual(owner.observe(intent)[0],'UNKNOWN')
        self.assertTrue((owner.root/'seal-owned.json').exists());self.assertFalse((owner.root/'generation-owned.json').exists())
        with self.assertRaises(FileExistsError):owner.issue(intent)

    def test_lost_completion_reply_is_read_only_reconciled(self):
        owner,intent,auth,_,_=self.fixture();original=m.new_file
        def lose(fd,name,raw,mode=0o600):
            if name=='complete.json':raise TimeoutError('SYNTHETIC_LOST_COMMIT_REPLY')
            return original(fd,name,raw,mode)
        with patch.object(m,'new_file',side_effect=lose),self.assertRaises(TimeoutError):owner.issue(intent)
        with (patch.object(m,'new_file',side_effect=AssertionError('NO_RECONCILIATION_WRITES')),
             patch.object(owner.signer,'sign',side_effect=AssertionError('NO_RESIGNING'))):
            self.assertEqual(owner.observe(intent)[0],'APPLIED')

    def test_native_generation_and_registry_admission_each_block_before_key_access(self):
        for change in ('probe','registry'):
            owner,intent,auth,_,_=self.fixture()
            selected=patch.object(m.NativeLeaseGenerationProbe,'__call__',side_effect=ValueError('NATIVE_DRIFT')) if change=='probe' else \
                patch.object(owner.start.node_owner,'verify_retained',side_effect=ValueError('REGISTRY_ADMISSION_REVOKED'))
            with selected,patch.object(owner.signer,'sign',side_effect=AssertionError('NO_KEY_ACCESS')):
                with self.assertRaises(ValueError):owner.issue(intent)
            self.assertFalse((owner.root/'claim.json').exists())

    def test_parent_revoked_after_signing_blocks_signature_publication(self):
        owner,intent,auth,_,_=self.fixture();original=owner.signer.sign
        def revoke(raw):
            result=original(raw)
            (auth.signatures/(owner.start.parent.sha+'.FINAL_DEPLOYMENT_APPROVAL.json')).unlink()
            return result
        with patch.object(owner.signer,'sign',side_effect=revoke),self.assertRaises(FileNotFoundError):owner.issue(intent)
        self.assertTrue((owner.root/'seal-dispatch.json').exists());self.assertFalse((owner.root/'seal-owned.json').exists())

    def test_wrong_key_or_scope_cannot_use_parent_approval(self):
        owner,intent,auth,_,_=self.fixture();owner.signer.key_ref='other-key'
        with self.assertRaisesRegex(ValueError,'ISSUER_KEY_CONTEXT'):owner.issue(intent)
        self.assertFalse((owner.root/'claim.json').exists())

    def test_concurrency_is_fenced_by_existing_logical_lock(self):
        owner,intent,auth,_,_=self.fixture();c=owner.installation.material['proposal']['configuration']
        with m.existing_kernel_lock(c['commonInvocationLock'],c['commonLockIdentity']):
            with self.assertRaises(BlockingIOError):owner.issue(intent)
        self.assertFalse((owner.root/'claim.json').exists())

    def test_replaced_signature_with_equal_bytes_is_not_adopted(self):
        owner,intent,auth,_,_=self.fixture();owner.issue(intent)
        name=auth.signatures/(m.digest(owner.installation.material['seal'])+'.'+m.ROLE+'.json')
        replacement=auth.signatures/'replacement.json';auth.write(replacement,name.read_bytes());replacement.replace(name)
        with self.assertRaisesRegex(ValueError,'SIGNATURE_INODE_DRIFT'):owner.observe(intent)

    def test_changed_issuance_directory_custody_blocks_before_key_access(self):
        owner,intent,auth,_,_=self.fixture();owner.root.chmod(0o755)
        with patch.object(owner.signer,'sign',side_effect=AssertionError('NO_KEY_ACCESS')):
            with self.assertRaisesRegex(ValueError,'DIRECTORY_CUSTODY'):owner.issue(intent)


if __name__=='__main__':unittest.main()
