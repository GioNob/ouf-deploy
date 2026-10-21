"""Actual local owner/receipt/signatures/TLS; simulated IAM-admin/systemctl only.

The existing composed owner fixture supplies real admitted token custody. No VPS
effects and no predicted inode stand in for the completed output receipt.
"""
import copy,json,os,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
TOKEN=ROOT if (ROOT/'tools/semantic_policy_token_owner/owner_installation.py').exists() else ROOT.parent/'token-owner-installer-work'
sys.path[:0]=[str(ROOT),str(TOKEN),str(TOKEN/'tests'),str(ROOT/'tests'),
    str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_database_cutover'),
    str(ROOT/'tools/semantic_frame_compiler'),str(TOKEN/'tools/semantic_policy_token_owner'),
    str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
import test_policy_token_owner_installation as fixture
from file_only_node_owner import FileOnlyNodeOwner
from transition_journal import digest

class DeferredOutput(unittest.TestCase):
    def fixture(self):
        f=fixture.OwnerInstallationTest();f.setUp();self.addCleanup(f.doCleanups)
        installation=f.installation;installation.install()
        node=FileOnlyNodeOwner.__new__(FileOnlyNodeOwner)
        node.authority=installation.action.authority;node.raw=installation.action.raw
        node.token_owner=installation.observer
        b=installation.observer.binding
        node.recipe={'renewableToken':{'source':b.output_directory,'target':'/run/ouf/policy','fileName':b.output_member,
            'gid':b.output_gid,'directoryCustodyScopeHash':digest(installation.output.scope),
            'ownerBindingHash':b.digest(),'maxBytes':8192,'minimumRemainingSeconds':30}}
        return f,installation,node

    def test_completed_same_action_output_materializes_real_identity_without_replay(self):
        f,installation,node=self.fixture();proposal=copy.deepcopy(node.recipe)
        calls=(f.grants(),len(f.f.commands),len(f.f.calls))
        expected=node.token_binding();info=Path(expected['source']).stat()
        self.assertEqual((expected['directoryDevice'],expected['directoryInode']),(info.st_dev,info.st_ino))
        self.assertNotIn('directoryCustodyScopeHash',expected);self.assertEqual(node.recipe,proposal)
        self.assertEqual(node.token_binding(),expected)
        self.assertEqual((f.grants(),len(f.f.commands),len(f.f.calls)),calls)

    def test_foreign_scope_replaced_inode_missing_receipt_and_revoked_authority_deny(self):
        for case in ('scope','inode','receipt','revoked'):
            with self.subTest(case=case):
                f,installation,node=self.fixture();before=f.grants()
                if case=='scope':node.recipe['renewableToken']['directoryCustodyScopeHash']='0'*64
                if case=='inode':
                    output=Path(installation.output.path);output.rename(str(output)+'.retained')
                    output.mkdir(mode=0o750);os.chown(output,0,10001)
                if case=='receipt':(f.f.root/installation.output.name).unlink()
                if case=='revoked':
                    f.f.f.approval['state']='REVOKED';f.f.f.write(f.f.f.mandate,fixture.fixture.binding.encoded(f.f.f.approval))
                with self.assertRaises(Exception):node.token_binding()
                self.assertEqual(f.grants(),before)

if __name__=='__main__':unittest.main()
