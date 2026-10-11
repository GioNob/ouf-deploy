"""Stopped creation effect for Executor-owned intent journaling.

Do not call Engine.create_once here: that primitive owns its own intent. This
adapter uses the same bounded Engine and native matching, while Executor owns
claim/authentication/checkpoints. No target authority, start, pause or removal.
"""
import json,re
from engine_creation import CreationDenied,digest

def require(ok,reason):
 if not ok:raise CreationDenied(reason)

class CreationAdapter:
 def __init__(self,engine,transition,request):
  self.engine,self.transition=engine,transition
  self.request=json.loads(json.dumps(request,allow_nan=False));self.request_hash=digest(self.request)
 def exact(self,intent):
  require(digest(intent)==self.request_hash and self.transition.read()['creationRequestHash']==self.request_hash,'EXACT_EXECUTOR_CREATION_INTENT_REQUIRED')
 def apply(self,intent):
  self.exact(intent)
  require(self.engine.inspect(self.transition) is None,'EXISTING_CONTAINER_REQUIRES_NATIVE_RECONCILIATION')
  status,result=self.engine.request('POST','/v1.44/containers/create?name='+self.engine.name(self.transition),self.request)
  require(status==201 and type(result) is dict and type(result.get('Id')) is str and re.fullmatch('[0-9a-f]{64}',result['Id']) is not None,'CREATION_OUTCOME_REQUIRES_RECONCILIATION')
 def observe(self,intent):
  self.exact(intent);actual=self.engine.inspect(self.transition)
  if actual is None:return 'UNKNOWN',{'nativeNameAbsent':True,'absenceDoesNotProveNoEffect':True}
  actual=self.engine.matching_created(self.transition,self.request,actual)
  following=self.engine.inspect(self.transition)
  require(following==actual,'CREATION_CHANGED_DURING_EXECUTOR_RECONCILIATION')
  return 'APPLIED',actual
