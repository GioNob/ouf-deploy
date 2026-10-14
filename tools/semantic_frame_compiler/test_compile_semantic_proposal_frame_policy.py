import copy
import unittest
from test_compile_six_mount_frame_policy import SixCompiler
from compile_six_mount_frame_policy import compile_policy as six_compile
from compile_semantic_proposal_frame_policy import compile_policy,compilation_receipt,Denied

class ProposalCompiler(unittest.TestCase):
    def setUp(self):
        f=SixCompiler();f.setUp()
        self.template,self.launch,self.context,self.tree,self.token=f.template,f.launch,f.context,f.tree,f.token
        self.key={'source':'/approved/distinct-receipt-key','target':'/run/proposal-owner.key','readOnly':True,
            'uid':0,'gid':10001,'mode':0o440,'maxBytes':65,'sha256':'c'*64,'metadataHash':'d'*64}
        self.launch['sources'].append({k:v for k,v in self.key.items()if k!='metadataHash'})
        self.launch['manifest']['mounts'].insert(4,{k:self.key[k]for k in ('source','target','readOnly')})
        self.template['expectedOci']['mounts'].append({'type':'bind','source':self.key['source'],
            'destination':self.key['target'],'options':['rbind','rprivate','ro']})
    def compile(self):
        return compile_policy(self.template,self.launch,self.context,configtree=self.tree,
            renewable_token=self.token,delegation_key_metadata_hash='b'*64,proposal_receipt_key=self.key)
    def test_seven_independent_mounts_preserve_original_key_and_grant_nothing(self):
        original=copy.deepcopy((self.template,self.launch,self.context,self.key))
        policy=self.compile()
        self.assertEqual(len(policy['sources']),5);self.assertEqual(len(policy['manifest']['mounts']),7)
        self.assertEqual(policy['sources'][3]['target'],policy['delegationKeyTarget'])
        self.assertEqual(policy['delegationKeyMetadataHash'],'b'*64)
        self.assertEqual(policy['proposalReceiptKey']['metadataHash'],'d'*64)
        self.assertEqual(original,(self.template,self.launch,self.context,self.key))
        receipt=compilation_receipt(self.template,self.launch,self.context,policy)
        self.assertFalse(receipt['observedOciUsed']);self.assertFalse(receipt['acceptanceGranted'])
    def test_original_six_mount_compiler_does_not_accept_extra_input(self):
        with self.assertRaises(Denied):
            six_compile(self.template,self.launch,self.context,configtree=self.tree,
                renewable_token=self.token,delegation_key_metadata_hash='b'*64)
    def test_receipt_key_custody_and_independent_hashes_are_required(self):
        for name,value in [('uid',10001),('gid',0),('mode',0o400),('mode',0o444),('readOnly',False),
                           ('metadataHash',''),('maxBytes',257)]:
            before=self.key[name];self.key[name]=value
            with self.subTest(name=name,value=value),self.assertRaises(Denied):self.compile()
            self.key[name]=before
    def test_rw_shared_shadowed_and_duplicate_input_are_denied(self):
        mount=self.template['expectedOci']['mounts'][-1];original=copy.deepcopy(mount)
        for options in (['rbind','rw'],['rbind','ro','rshared']):
            mount['options']=options
            with self.assertRaises(Denied):self.compile()
        mount.clear();mount.update(original)
        self.key['target']=self.token['target']+'/key'
        with self.assertRaises(Denied):self.compile()
    def test_key_cannot_be_placed_in_singleton_or_renewable_directory(self):
        for directory in (self.tree,self.token):
            self.key['source']=directory['source']+'/key'
            self.launch['sources'][4]['source']=self.key['source']
            self.launch['manifest']['mounts'][4]['source']=self.key['source']
            self.template['expectedOci']['mounts'][-1]['source']=self.key['source']
            with self.assertRaisesRegex(Denied,'CANNOT_ENTER'):self.compile()
    def test_observed_compiled_oci_cannot_be_reused_as_template(self):
        policy=self.compile();self.template['expectedOci']=policy['expectedOci']
        with self.assertRaises(Denied):self.compile()

if __name__=='__main__':unittest.main()
