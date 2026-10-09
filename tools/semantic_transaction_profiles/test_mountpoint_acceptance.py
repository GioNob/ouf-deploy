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


def directory(path):return {'path':path,'kind':'directory','uid':0,'gid':0,'mode':0o755,'links':2,'xattrs':{}}
def file(path):return {'path':path,'kind':'file','uid':0,'gid':0,'mode':0o644,'links':1,'size':0,'sha256':proposal.sha(b''),'xattrs':{}}


class MountpointAcceptanceTest(unittest.TestCase):
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
