"""Disposable proposal recovery contract; no HTTP, credentials or live operations."""
import copy,importlib.util,unittest
from pathlib import Path
path=Path(__file__).resolve().parents[1]/'scripts/prepare-chatbot-role-review-recovery-20261015.py'
spec=importlib.util.spec_from_file_location('role_recovery',path)
recovery=importlib.util.module_from_spec(spec);spec.loader.exec_module(recovery)

class Transport:
    def __init__(self,plan):
        self.plan=plan;self.calls=[];self.current_roles=copy.deepcopy(plan['baseline']['roles'])
        self.old_state='EXPIRED';self.policy=copy.deepcopy(plan['candidatePolicy'])
    def roles(self):self.calls.append(('read-roles',));return self.current_roles
    def active(self):return {'policy':self.policy}
    def tool(self,name,args,key):
        self.calls.append((name,copy.deepcopy(args),key))
        if name=='authorization.proposal.read':return {'proposalId':recovery.EXPIRED_ID,'state':self.old_state,'finalPolicyRef':None}
        if name!='authorization.permissions.propose':raise AssertionError('UNEXPECTED_TOOL')
        return {'proposalId':'new-owner-proposal','state':'PENDING','approvalPath':'https://owner/path','expiresAt':'fixed-expiry'}

class Recovery(unittest.TestCase):
    def setUp(self):
        self.plan={'baseline':{'roles':{'roles':['unchanged']},'active':{'policy':{}}},
            'targetRoles':{'roles':['unchanged','reviewed']},
            'candidatePolicy':{'bundleId':'b','version':3,'capabilities':['a','reviewed'],'grants':['existing']},
            'addedDescriptors':['reviewed']}
        self.plan['roleProposal']={'operation':'REPLACE_ROLES','reason':'same reviewed reason','roleCatalogue':copy.deepcopy(self.plan['targetRoles'])}
        self.transport=Transport(self.plan);self.guards=[]
    def run_recovery(self):return recovery.propose_once(self.transport,self.plan,lambda:self.guards.append(True))
    def assert_no_write(self):self.assertFalse(any(c[0]=='authorization.permissions.propose' for c in self.transport.calls))
    def test_exact_payload_only_one_draft_and_guard(self):
        original=copy.deepcopy(self.plan);result=self.run_recovery();self.assertEqual(result['state'],'PENDING')
        writes=[c for c in self.transport.calls if c[0]=='authorization.permissions.propose']
        self.assertEqual(writes,[(writes[0][0],self.plan['roleProposal'],recovery.KEY)])
        self.assertEqual(self.plan,original);self.assertEqual(len(self.guards),2)
    def test_pending_old_proposal_blocks(self):
        self.transport.old_state='PENDING'
        with self.assertRaises(RuntimeError):self.run_recovery()
        self.assert_no_write()
    def test_rejected_old_proposal_blocks(self):
        self.transport.old_state='REJECTED'
        with self.assertRaises(RuntimeError):self.run_recovery()
        self.assert_no_write()
    def test_published_old_proposal_blocks(self):
        self.transport.old_state='PUBLISHED'
        with self.assertRaises(RuntimeError):self.run_recovery()
        self.assert_no_write()
    def test_unrelated_role_change_blocks(self):
        self.transport.current_roles={'roles':['unrelated']}
        with self.assertRaises(RuntimeError):self.run_recovery()
        self.assert_no_write()
    def test_active_policy_drift_blocks(self):
        self.transport.policy['version']=99
        with self.assertRaises(RuntimeError):self.run_recovery()
        self.assert_no_write()
    def test_already_target_no_new_draft(self):
        self.transport.current_roles=copy.deepcopy(self.plan['targetRoles'])
        self.assertEqual(self.run_recovery()['state'],'TARGET_ALREADY_PUBLISHED_NO_PROPOSAL_CREATED');self.assert_no_write()
    def test_repeat_uses_same_owner_dedup_key_and_fixed_draft(self):
        self.assertEqual(self.run_recovery(),self.run_recovery())
        self.assertEqual([c[2] for c in self.transport.calls if c[0]=='authorization.permissions.propose'],[recovery.KEY,recovery.KEY])

if __name__=='__main__':unittest.main()
