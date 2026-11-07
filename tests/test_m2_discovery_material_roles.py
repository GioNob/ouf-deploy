"""Regression for heterogeneous producer labels; identity and fencing stay exact."""
import copy
import json
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import test_m2_discovery_material_preparation as base_fixture
from tools.m2_discovery_installation_profile import material_preparation as retained
from tools.m2_discovery_installation_profile import material_role_preparation as m


def alias(role):return 'retained::'+role


class MaterialRoles(unittest.TestCase):
    def fixture(self):
        root,k,peers,calls,secret,key,ca=base_fixture.MaterialPreparation.fixture(self)
        cohort=json.loads((k['cohort_root']/'inputs.json').read_bytes())
        cohort['observations']={alias(r):v for r,v in cohort['observations'].items()}
        cohort['processPins']={alias(r):v for r,v in cohort['processPins'].items()}
        k['cohort_hash']=m.digest(cohort)
        (k['cohort_root']/'inputs.json').write_bytes(m.encoded(cohort))
        inputs=json.loads((k['input_root']/'inputs.json').read_bytes())
        inputs.update(sourceBinding={'root':str(k['cohort_root']),'inputsHash':k['cohort_hash'],
            'resultHash':m.COHORT_RESULT_HASH},engineBinding=cohort['engineBinding'],rootProcessPins=cohort['rootProcessPins'])
        k['input_hash']=m.digest(inputs);(k['input_root']/'inputs.json').write_bytes(m.encoded(inputs))
        path=k['candidate_root']/'material-candidates.private.json';candidates=json.loads(path.read_bytes())
        candidates['installationInputsHash']=k['input_hash'];path.write_bytes(m.encoded(candidates));k['candidate_hash']=m.digest(candidates)
        failed=retained.Preparation(root/'failed-consumed-predecessor')
        with self.assertRaisesRegex(m.Stop,'INSTALLATION_ROLES_OUTSIDE_REVIEWED_COHORT'):
            retained.prepare(failed,**k)
        self.assertEqual(failed.counts['metadataReads'],3);self.assertEqual(failed.counts['engineGets'],0)
        self.assertEqual(failed.counts['privateCopiesPrepared'],0)
        result={'schema':'ouf.m2-discovery-material-preparation-result.v1','status':'STOP_RECONCILE',
            'reasonCode':'INSTALLATION_ROLES_OUTSIDE_REVIEWED_COHORT','complete':False,'scope':str(failed.scope),
            'scopeConsumed':True,'counts':dict(failed.counts),'automaticReplayAllowed':False,'budgetReset':False,
            'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'applicationE2EProven':False,'releaseAcceptance':False}
        failed.put('result.json',result)
        k.update(predecessor_root=failed.scope,predecessor_hash=m.digest(result))
        return root,k,peers,calls,secret,key,ca

    def objects(self,k):
        return (json.loads((k['input_root']/'inputs.json').read_bytes()),
            json.loads((k['cohort_root']/'inputs.json').read_bytes()),
            json.loads((k['candidate_root']/'material-candidates.private.json').read_bytes()))

    def test_exact_previous_failure_and_corrected_full_pass_keep_every_source_unchanged(self):
        root,k,peers,calls,secret,key,ca=self.fixture();inputs,cohort,candidates=self.objects(k)
        self.assertFalse(set(inputs['observations'])&set(cohort['observations']))
        expected={r:alias(r) for r in m.ROLES}
        before={p:p.read_bytes() for p in root.rglob('*') if p.is_file()}
        c=m.Preparation(root/'corrective-successor');out=m.prepare(c,**k)
        self.assertEqual(out['counts']['metadataReads'],4);self.assertEqual(out['counts']['engineGets'],27)
        self.assertEqual(out['counts']['privateCopiesPrepared'],2);self.assertEqual(out['counts']['preparedCopyReads'],3)
        self.assertEqual(out['installationRoleMapHash'],m.digest(expected))
        private=json.loads((c.scope/'prepared-inputs.private.json').read_bytes())
        self.assertEqual(private['installationRoleMap'],expected)
        self.assertEqual(private['selectedInstallationObservations']['apisix']['Id'],peers['apisix']['Id'])
        self.assertEqual(set(private['currentObservations']),set(cohort['observations']))
        self.assertEqual(private['failedPredecessor']['sha256'],k['predecessor_hash'])
        for p,raw in before.items():self.assertEqual(p.read_bytes(),raw)
        self.assertNotIn(secret.decode(),json.dumps(out));self.assertNotIn(key.decode(),json.dumps(out))
        self.assertFalse(out['runtimeAuthorityIssued']);self.assertFalse(out['applicationE2EProven'])
        with self.assertRaisesRegex(m.Stop,'CONSUMED_NO_REPLAY'):m.Preparation(k['predecessor_root'])
        with self.assertRaisesRegex(m.Stop,'CONSUMED_NO_REPLAY'):m.Preparation(c.scope)

    def test_binding_is_by_unique_id_not_matching_friendly_label(self):
        root,k,*_=self.fixture();inputs,cohort,candidates=self.objects(k)
        original=copy.deepcopy((inputs,cohort,candidates))
        mapping=m.bind_installation_roles(inputs,cohort,candidates,k['cohort_root'],k['cohort_hash'])
        self.assertEqual(mapping,{r:alias(r) for r in m.ROLES})
        self.assertEqual(original,(inputs,cohort,candidates))
        # A misleading friendly name belongs to a different exact peer. It must
        # not be selected instead of the configured APISIX container ID.
        other=alias('peer-0');cohort['observations']['apisix']=cohort['observations'].pop(other)
        cohort['processPins']['apisix']=cohort['processPins'].pop(other)
        h=m.digest(cohort);inputs['sourceBinding']['inputsHash']=h
        self.assertEqual(m.bind_installation_roles(inputs,cohort,candidates,k['cohort_root'],h)['apisix'],alias('apisix'))

    def test_missing_duplicate_selected_and_duplicate_cohort_ids_are_denied(self):
        for case in ('missing','duplicate-selected','duplicate-cohort'):
            root,k,*_=self.fixture();inputs,cohort,candidates=self.objects(k)
            if case=='missing':inputs['observations']['apisix']['Id']='f'*64
            if case=='duplicate-selected':inputs['observations']['apisix']=copy.deepcopy(inputs['observations']['mcp'])
            if case=='duplicate-cohort':cohort['observations'][alias('peer-0')]['Id']=cohort['observations'][alias('mcp')]['Id']
            h=m.digest(cohort);inputs['sourceBinding']['inputsHash']=h
            with self.subTest(case=case),self.assertRaises(m.Stop):
                m.bind_installation_roles(inputs,cohort,candidates,k['cohort_root'],h)

    def test_same_id_with_image_config_mount_network_or_pin_drift_is_denied(self):
        for case in ('image','config','mount','network','pin'):
            root,k,*_=self.fixture();inputs,cohort,candidates=self.objects(k);row=cohort['observations'][alias('apisix')]
            if case=='image':row['Image']='sha256:'+'e'*64
            if case=='config':row['Config']['Env'].append('CHANGED=1')
            if case=='mount':row['Mounts'].append({'Destination':'/unreviewed'})
            if case=='network':row['NetworkSettings']['Changed']=True
            if case=='pin':cohort['processPins'][alias('apisix')]['startTicks']+=1
            h=m.digest(cohort);inputs['sourceBinding']['inputsHash']=h
            with self.subTest(case=case),self.assertRaisesRegex(m.Stop,'GENERATION_DISAGREE'):
                m.bind_installation_roles(inputs,cohort,candidates,k['cohort_root'],h)

    def test_unrelated_provenance_engine_or_root_process_chain_is_denied(self):
        for case in ('source','engine','root'):
            root,k,*_=self.fixture();inputs,cohort,candidates=self.objects(k)
            if case=='source':inputs['sourceBinding']['inputsHash']='e'*64
            if case=='engine':inputs['engineBinding']['peerCredentials'][0]+=1
            if case=='root':inputs['rootProcessPins']['pid1']['startTicks']+=1
            with self.subTest(case=case),self.assertRaisesRegex(m.Stop,'PROVENANCE_CHAIN'):
                m.bind_installation_roles(inputs,cohort,candidates,k['cohort_root'],k['cohort_hash'])

    def test_changed_or_effectful_failed_predecessor_never_reaches_engine_or_material(self):
        for case in ('hash','effect','reason','scope'):
            root,k,*_=self.fixture();p=k['predecessor_root']/'result.json';v=json.loads(p.read_bytes())
            if case=='hash':k['predecessor_hash']='e'*64
            if case=='effect':v['counts']['privateCopiesPrepared']=1
            if case=='reason':v['reasonCode']='OTHER_FAILURE'
            if case=='scope':v['scope']='/unrelated'
            if case!='hash':p.write_bytes(m.encoded(v));k['predecessor_hash']=m.digest(v)
            c=m.Preparation(root/'corrective-successor')
            with self.subTest(case=case),self.assertRaises(m.Stop):m.prepare(c,**k)
            self.assertEqual(c.counts['engineGets'],0);self.assertEqual(c.counts['credentialFileReads'],0)
            self.assertEqual(c.counts['privateCopiesPrepared'],0)

    def test_nonselected_current_peer_drift_still_blocks_before_secret_reads(self):
        root,k,peers,*_=self.fixture();peers['peer-8']['HostConfig']['changed']=True
        c=m.Preparation(root/'corrective-successor')
        with self.assertRaisesRegex(m.Stop,'CURRENT_FULL_PREPARATION_COHORT_CHANGED'):m.prepare(c,**k)
        self.assertEqual(c.counts['credentialFileReads'],0);self.assertEqual(c.counts['privateCopiesPrepared'],0)

if __name__=='__main__':unittest.main()
