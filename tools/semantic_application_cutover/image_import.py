"""One-use image import reconciliation; not a target entrypoint/authority.

The caller authenticates source/archive/current execution authority and command
custody at checkpoints. Hashes alone confer none. The owner supplies a new sealed
Journal bound to this context. Never use or initialize R12's journal here.
"""
import copy
from contextlib import contextmanager
from image_custody import digest,loaded,require,runtime_image_id

def intent(audit):
    return {'imageId':runtime_image_id(audit),**{k:audit[k] for k in ('sourceCommit','archiveSha256')}}

class Import:
    def __init__(self,journal,context_hash):
        self.journal,self.context,self.active=journal,context_hash,False
    @staticmethod
    def initial(audit,authority_hash):
        require(type(authority_hash) is str and len(authority_hash)==64
                and all(c in '0123456789abcdef' for c in authority_hash),'IMPORT_AUTHORITY_BINDING_REQUIRED')
        target=intent(audit)
        return {'schema':'ouf.image-import-journal.v1','contextHash':digest({'intent':target,'authorityHash':authority_hash}),
                'intent':target,'authorityHash':authority_hash,'version':0,'state':'READY',
                'automaticReplayAllowed':False,'effectAttemptCount':0,'imageCustodyProven':False}
    def read(self,audit):
        row=self.journal.read()
        require(row.get('schema')=='ouf.image-import-journal.v1' and row.get('contextHash')==self.context
                and digest({'intent':row['intent'],'authorityHash':row['authorityHash']})==self.context
                and row['intent']==intent(audit),'IMPORT_CONTEXT_OR_INTENT_DRIFT')
        require(row['automaticReplayAllowed'] is False and type(row['version']) is int and row['version']>=0
                and row['state'] in ('READY','IN_FLIGHT','VERIFIED') and type(row['effectAttemptCount']) is int
                and row['effectAttemptCount'] in (0,1) and type(row['imageCustodyProven']) is bool,'IMPORT_STATE_INVALID')
        require((row['state']=='VERIFIED')==row['imageCustodyProven']
                and (row['state']!='IN_FLIGHT' or row['effectAttemptCount']==1)
                and (row['state']!='READY' or row['effectAttemptCount']==0),'IMPORT_HISTORY_INVALID')
        require((row['state'],row['effectAttemptCount'],row['version']) in
                {('READY',0,0),('IN_FLIGHT',1,1),('VERIFIED',0,1),('VERIFIED',1,2)},'IMPORT_VERSION_HISTORY_DRIFT')
        if row['state']=='VERIFIED':
            proof=row.get('nativeEvidenceHash')
            require(type(proof) is str and len(proof)==64 and all(c in '0123456789abcdef' for c in proof),'IMPORT_NATIVE_EVIDENCE_REQUIRED')
        return row
    @contextmanager
    def invocation(self):
        require(not self.active,'IMPORT_NESTED_INVOCATION_DENIED')
        with self.journal.invocation():
            self.active=True
            try:yield self
            finally:self.active=False
    def checkpoint(self,row,callback,phase):
        require(self.active,'IMPORT_EXCLUSIVE_INVOCATION_REQUIRED')
        # Callback must perform REAL authentication/native freshness externally.
        require(callback(phase)==row['authorityHash'],'IMPORT_AUTHENTICATION_RECEIPT_DRIFT')
    def verify(self,audit,row,inspect,checkpoint):
        self.checkpoint(row,checkpoint,'BEFORE_IMAGE_CUSTODY_RECONCILIATION')
        actual=inspect(runtime_image_id(audit))
        require(actual is not None,'IMPORT_ABSENCE_DOES_NOT_PROVE_NO_EFFECT')
        proof=loaded(audit,actual)
        require(inspect(runtime_image_id(audit))==actual,'IMAGE_CHANGED_DURING_RECONCILIATION')
        self.checkpoint(row,checkpoint,'AFTER_IMAGE_CUSTODY_RECONCILIATION')
        following=copy.deepcopy(row);following.update(version=row['version']+1,state='VERIFIED',imageCustodyProven=True,nativeEvidenceHash=digest(proof))
        self.journal.compare_and_save(row,following)
        return proof
    def import_once(self,audit,load,inspect,checkpoint):
        row=self.read(audit)
        require(row['state']=='READY','IMPORT_RECONCILIATION_REQUIRED_NO_REPLAY')
        self.checkpoint(row,checkpoint,'BEFORE_IMAGE_IMPORT_CLAIM')
        if inspect(runtime_image_id(audit)) is not None:return self.verify(audit,row,inspect,checkpoint)
        following=copy.deepcopy(row);following.update(version=row['version']+1,state='IN_FLIGHT',effectAttemptCount=1)
        self.journal.compare_and_save(row,following)
        self.checkpoint(following,checkpoint,'BEFORE_IMAGE_IMPORT_EFFECT')
        # Exceptions/crashes keep IN_FLIGHT durable. Never automatically retry.
        load()
        return self.verify(audit,following,inspect,checkpoint)
    def reconcile(self,audit,inspect,checkpoint):
        row=self.read(audit)
        require(row['state']=='IN_FLIGHT','EXACT_IN_FLIGHT_IMAGE_IMPORT_REQUIRED')
        return self.verify(audit,row,inspect,checkpoint)
