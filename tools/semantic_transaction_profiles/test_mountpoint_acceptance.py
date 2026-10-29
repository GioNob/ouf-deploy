"""Exact empty-placeholder scope and unchanged runtime verification contracts."""
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

import prepare_mountpoint_acceptance as proposal
sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'semantic_target_review'))
from test_audited_provider_recovery import build,package_inputs
sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'semantic_frame_compiler'))
from prepare_provider_v2_frame_policies import compile_role,BASELINE_HASHES


def directory(path):return {'path':path,'kind':'directory','uid':0,'gid':0,'mode':0o755,'links':2,'xattrs':{}}
def file(path):return {'path':path,'kind':'file','uid':0,'gid':0,'mode':0o644,'links':1,'size':0,'sha256':proposal.sha(b''),'xattrs':{}}


class MountpointAcceptanceTest(unittest.TestCase):
    def compiled_role_oci(self,role):
        path=Path(__file__).resolve().parent.parent/'semantic_frame_compiler'/('containerd-overlayfs-'+role+'.json')
        raw=path.read_bytes();self.assertEqual(proposal.sha(raw),BASELINE_HASHES[role])
        baseline=json.loads(raw);launch=copy.deepcopy(baseline['launch'])
        source=launch['sources'][0];launch['sources']=[];launch['manifest']['mounts']=[]
        for index,target in enumerate(proposal.BIND_FILES[role]):
            mount={'source':'/ci-only/input-'+str(index),'target':'/'+target,'readOnly':True}
            launch['sources'].append({**source,**mount});launch['manifest']['mounts'].append(mount)
        before=copy.deepcopy((baseline,launch))
        policy=compile_role(role,baseline,launch,{'serverVersion':'29.8.1','storageDriver':'overlayfs',
            'cgroupDriver':'systemd','dataRoot':'/var/lib/docker'})['policy']
        self.assertEqual((baseline,launch),before)
        return policy['expectedOci']

    def fixture(self,role):
        left={p:directory(p) for p in ('','run','usr','usr/local','usr/local/apisix','usr/local/apisix/conf')}
        left['program']=file('program');left['program'].update(size=4,sha256=proposal.sha(b'GOOD'))
        oci={'mounts':[{'destination':'/'+p,'type':'bind','options':['rbind','ro']} for p in proposal.BIND_FILES[role]]}
        expanded,paths=proposal.expanded_image(proposal.image_entries(left,True),oci,proposal.BIND_FILES[role])
        right=copy.deepcopy(expanded)
        for item in right.values():
            if item['kind']=='directory':item['links']=2
        value={'expectedOfflineEntries':left,'currentEntries':right,'summary':{}}
        return value,oci

    def test_only_exact_empty_bind_files_and_one_parent_are_admitted_to_the_proposal(self):
        for role in ('adapter','southbound'):
            value,oci=self.fixture(role);before=copy.deepcopy(value)
            with patch.dict(proposal.OFFLINE_SEALS,{role:proposal.seal_entries(value['expectedOfflineEntries'])['sha256']}),\
                 patch.dict(proposal.PROPOSED_SEALS,{role:proposal.seal_entries(value['currentEntries'])}),\
                 patch.dict(proposal.IMAGE_SEALS,{role:proposal.image_digest(proposal.image_entries(value['expectedOfflineEntries'],True))}):
                result=proposal.validate_comparison(role,value,oci)
            self.assertEqual(value,before)
            self.assertEqual(len(result['addedEntries']),6 if role=='adapter' else 3)
            self.assertFalse(result['acceptanceGranted']);self.assertFalse(result['startAuthorized'])

    def test_fixed_engine_compiler_rro_output_reaches_complete_rootfs_review_without_rewriting_oci(self):
        for role in ('adapter','southbound'):
            value,_=self.fixture(role);oci=self.compiled_role_oci(role);before=copy.deepcopy((value,oci))
            declared=[m for m in oci['mounts'] if m['destination'].lstrip('/') in proposal.BIND_FILES[role]]
            self.assertEqual(len(declared),len(proposal.BIND_FILES[role]))
            self.assertTrue(all(m['options']==['rbind','rro','rprivate'] for m in declared))
            # This is precisely the old predicate that denied the frozen Engine
            # output. CI input hashes below grant no target authority.
            self.assertTrue(all('ro' not in m['options'] for m in declared))
            with patch.dict(proposal.OFFLINE_SEALS,{role:proposal.seal_entries(value['expectedOfflineEntries'])['sha256']}),\
                 patch.dict(proposal.PROPOSED_SEALS,{role:proposal.seal_entries(value['currentEntries'])}),\
                 patch.dict(proposal.IMAGE_SEALS,{role:proposal.image_digest(proposal.image_entries(value['expectedOfflineEntries'],True))}):
                result=proposal.validate_comparison(role,value,oci)
            self.assertEqual((value,oci),before)
            self.assertEqual(len(result['addedEntries']),6 if role=='adapter' else 3)
            self.assertFalse(result['startAuthorized']);self.assertFalse(result['acceptanceGranted'])

    def test_compiled_rro_writable_conflicts_and_missing_binds_are_denied_with_safe_differences(self):
        value,_=self.fixture('adapter');oci=self.compiled_role_oci('adapter')
        path=proposal.BIND_FILES['adapter'][0]
        for edit,expected_field in [('rw','noWritableOption'),('rrw','noWritableOption'),
                ('neither','readOnlyOption'),('missing','declaredMount'),('type','bindType')]:
            altered=copy.deepcopy(oci);mount=next(m for m in altered['mounts'] if m['destination']=='/'+path)
            mount['source']='/PRIVATE_SOURCE_MUST_NOT_APPEAR'
            if edit in ('rw','rrw'):mount['options'].extend([edit,'PRIVATE_OPTION_MUST_NOT_APPEAR'])
            elif edit=='neither':mount['options']=['rbind','rprivate']
            elif edit=='missing':altered['mounts'].remove(mount)
            else:mount['type']='tmpfs'
            with self.assertRaisesRegex(ValueError,'EXACT_READ_ONLY_BIND') as caught:
                proposal.expanded_image(proposal.image_entries(value['expectedOfflineEntries'],True),altered,proposal.BIND_FILES['adapter'])
            self.assertIn(expected_field,caught.exception.diagnosis['differentFields'])
            self.assertNotIn('PRIVATE_',json.dumps(caught.exception.diagnosis))

    def test_changed_content_permissions_links_xattrs_and_extra_entries_are_never_accepted(self):
        base,oci=self.fixture('adapter');path=proposal.BIND_FILES['adapter'][0]
        changes=[('program','sha256',proposal.sha(b'EVIL')),(path,'size',1),(path,'uid',10006),
                 (path,'mode',0o600),(path,'links',2),(path,'xattrs',{'user.test':'01'})]
        for name,field,value in changes:
            altered=copy.deepcopy(base);altered['currentEntries'][name][field]=value
            # Even a substituted proposed digest cannot conceal semantic drift.
            with patch.dict(proposal.OFFLINE_SEALS,{'adapter':proposal.seal_entries(base['expectedOfflineEntries'])['sha256']}),\
                 patch.dict(proposal.PROPOSED_SEALS,{'adapter':proposal.seal_entries(altered['currentEntries'])}),\
                 patch.dict(proposal.IMAGE_SEALS,{'adapter':proposal.image_digest(proposal.image_entries(base['expectedOfflineEntries'],True))}):
                with self.assertRaisesRegex(ValueError,'UNREVIEWED_ROOTFS'):
                    proposal.validate_comparison('adapter',altered,oci)
        for key,value in [('type','tmpfs'),('options',['rbind','rw']),('destination','/foreign')]:
            altered=copy.deepcopy(oci);altered['mounts'][0][key]=value
            with self.assertRaisesRegex(ValueError,'EXACT_READ_ONLY_BIND'):
                proposal.expanded_image(proposal.image_entries(base['expectedOfflineEntries'],True),altered,proposal.BIND_FILES['adapter'])

    def test_v1_reconstruction_uses_depth_first_order_after_json_key_sorting(self):
        records={'':directory(''),'a':directory('a'),'a/z':file('a/z'),'a-file':file('a-file')}
        h=__import__('hashlib').sha256(b'OUF-ROOTFS-SEAL\0V1\0')
        for path in ('','a','a/z','a-file'):
            raw=proposal.encoded(records[path]);h.update(len(raw).to_bytes(4,'big'));h.update(raw)
        restored=json.loads(proposal.encoded(records))
        self.assertEqual(proposal.seal_entries(restored)['sha256'],h.hexdigest())

    def test_built_package_changes_only_two_seal_literals_and_entry_bindings(self):
        old=build(*package_inputs());original=copy.deepcopy(old)
        files={k:v for k,v in old['files'].items() if k not in ('intake-source-closure.json','provider_transaction_intake.py')}
        new=proposal.build_package(old['files']['intake-source-closure.json'],files,old['files']['provider_transaction_intake.py'])
        self.assertEqual(old,original)
        changed={k for k in old['files'] if old['files'][k]!=new['files'][k]}
        self.assertEqual(changed,{'utility/authenticate_provider_transaction.py','intake-source-closure.json','provider_transaction_intake.py'})
        self.assertEqual(new['sourceClosureHash'],old['sourceClosureHash'])
        self.assertEqual(new['changedRuntimeFiles'],[])
        text=new['files']['utility/authenticate_provider_transaction.py']
        for role in proposal.PROPOSED_SEALS:
            self.assertIn(repr(proposal.PROPOSED_SEALS[role]).encode(),text)
            self.assertNotIn(repr(proposal.OLD_SEALS[role]).encode(),text)
        self.assertFalse(new['acceptanceGranted'])
        tampered=dict(files);tampered['frame-observer.py']+=b'\n'
        with self.assertRaisesRegex(ValueError,'SOURCE_BYTES_DRIFT'):
            proposal.build_package(old['files']['intake-source-closure.json'],tampered,old['files']['provider_transaction_intake.py'])


if __name__=='__main__':unittest.main()
