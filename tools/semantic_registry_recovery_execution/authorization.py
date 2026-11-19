"""Existing dual-role current CutoverAuthority scope; no issuer or approval UI."""
import copy,json
from .core import require,digest,validate_plan,hashed

def cutover_type():
    from cutover_authority import CutoverAuthority
    return CutoverAuthority

def scope(plan):
    validate_plan(plan);intent=plan['stages'][0]['intent']
    return {'schema':'ouf.semantic-registry-fresh-generation-recovery-scope.v1',
        'planHash':digest(plan),'logicalOperationRef':plan['logicalOperationRef'],
        'registryId':intent['registryId'],'proposalHash':intent['proposalHash'],
        'historicalChainHash':intent['historicalChainHash'],
        'predecessorIncidentRef':plan['retainedPredecessorIncidentRef'],
        'maximumRuntimeSeconds':900,'maximumObservationAttempts':128,
        'maximumDockerEffectAttempts':4,'maximumAttestationAttempts':1,
        'oldClaimsRemainConsumed':True,'sameFreshGenerationRequired':True,
        'providerRecoveryAllowed':False,'gatewayWritesAllowed':False,'databaseMigrationAllowed':False,
        'automaticAuthenticationAllowed':False,'sourceActivationAllowed':False,
        'automaticReplayAllowed':False,'budgetReset':False}

class AuthorityScope:
    def __init__(self,authority,raw,plan,request):
        require(type(authority) is cutover_type() and type(raw) is bytes,'EXISTING_TYPED_CUTOVER_AUTHORITY_REQUIRED')
        self.authority,self.raw=authority,bytes(raw);self.hash=__import__('hashlib').sha256(raw).hexdigest()
        self.expected=scope(plan);self.plan_hash=digest(plan)
        require(authority.expected['creationRequestHash']==digest(request), 'CURRENT_AUTHORITY_MUST_BIND_RETAINED_CREATION_REQUEST')
        self.guard()
    def guard(self,row=None):
        require(__import__('hashlib').sha256(self.raw).hexdigest()==self.hash
                and self.authority(self.raw) is True,'CURRENT_DUAL_ROLE_HUMAN_RECOVERY_AUTHORITY_REQUIRED')
        parsed=json.loads(self.raw)
        require(parsed.get('semanticRegistryRecovery')==self.expected,'EXACT_SIGNED_REGISTRY_RECOVERY_SCOPE_REQUIRED')
        if row is not None:
            if row.get('schema')=='ouf.semantic-registry-recovery-journal.v2':
                from .resumption import KEY
                require(parsed.get(KEY)==row.get('resumption',{}).get('scope'), 'EXACT_SIGNED_SUCCESSOR_EPOCH_REQUIRED')
            else:
                require('semanticRegistryCheckpointResumption' not in parsed,
                        'SUCCESSOR_AUTHORITY_CANNOT_DISPATCH_OLD_EPOCH')
            require(row['planHash']==self.plan_hash and row['authorityHash']==self.hash
                    and parsed['issuedAt']<=row['createdUnix']<row['expiresUnix']<=parsed['expiresAt']
                    and row['predecessorIncidentRef']==self.expected['predecessorIncidentRef'],
                    'CURRENT_JOURNAL_WITHIN_EXACT_SIGNED_AUTHORITY_REQUIRED')

