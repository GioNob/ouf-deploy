"""Explicit finite discovery installation authority with reviewed normal use.

Authentication only: no signature issuance, child mandate publication, runtime
admission, process start or journal initialization. A parent review covers each
separate component; the legacy thirteen-phase child authority stays unchanged.
"""
import copy,hashlib,time
from pathlib import Path
from .custody_capture import decode,digest,encoded,require
from tools.semantic_provider_deployment_authentication import DetachedAuthenticator,private_bytes,policy
from tools.semantic_provider_deployment_protocol import identity

COMPONENTS={'registryCutover','providerInstallation','registryGatePeerWindow',
    'operationalLeaseInstallation','cohortInstallation','capabilityPublication'}
EXPECTED={'reviewHash','sourceClosureHash','installationInputsHash','desiredProfileHash','predecessorHistoryHash'}
SEMANTICS={'finiteApprovalAuthorizesInstallationOnly':True,'reviewedNormalOperationAfterInstallation':True,
    'currentNativeAdmissionRequiredForEveryGeneration':True,'runtimeSigningKeyAccessAllowed':False,
    'automaticBudgetResetAllowed':False,'historicalAuthorityReuseAllowed':False,
    'sourceActivationAuthorized':False,'releaseAcceptanceGranted':False}
DECISION='APPROVE_EXACT_DISCOVERY_INSTALLATION_AND_REVIEWED_NORMAL_OPERATION'


def hashed(value):return type(value) is str and len(value)==64 and set(value)<=set('0123456789abcdef')


def review_scope(review):
    require(type(review) is dict and set(review)=={'schema','sourceClosureHash','installationInputsHash',
        'desiredProfileHash','predecessorHistoryHash','components','operationalSemantics','runtimeAuthorityIssued',
        'targetApplyAuthorized','releaseAcceptance'}
        and review['schema']=='ouf.discovery-parent-installation-review.v1'
        and all(hashed(review[k]) for k in EXPECTED-{'reviewHash'})
        and type(review['components']) is dict and set(review['components'])==COMPONENTS
        and all(type(v) is dict and bool(v) for v in review['components'].values())
        and review['operationalSemantics']==SEMANTICS
        and all(review[k] is False for k in ('runtimeAuthorityIssued','targetApplyAuthorized','releaseAcceptance'))
        and len(encoded(review))<=131072,'EXACT_DISCOVERY_PARENT_INSTALLATION_REVIEW_REQUIRED')
    return {'schema':'ouf.discovery-parent-installation-scope.v1','reviewHash':digest(review),
        **{k:review[k] for k in EXPECTED-{'reviewHash'}},
        'componentScopeHashes':{k:digest(v) for k,v in review['components'].items()},
        'operationalSemantics':copy.deepcopy(SEMANTICS)}


class DiscoveryParentAuthority:
    def __init__(self,verifier,human_binding,explicitly_approved_hash,context,review,authority_raw,clock=time.time):
        require(type(verifier) is DetachedAuthenticator and type(human_binding) is dict
            and set(human_binding)=={'path','sha256'} and hashed(explicitly_approved_hash)
            and human_binding['sha256']==explicitly_approved_hash,
            'ACTUAL_DISCOVERY_PARENT_VERIFIER_AND_EXPLICIT_HUMAN_BINDING_REQUIRED')
        require(type(context) is dict and set(context)=={'installationRef','entityRef','intentIssuerRef',
            'approvalIssuerRef','attestorRef'} and all(identity(v) for v in context.values())
            and type(authority_raw) is bytes and 0<len(authority_raw)<=131072,
            'EXACT_DISCOVERY_PARENT_CONTEXT_AND_AUTHORITY_REQUIRED')
        self.verifier,self.binding,self.approved,self.context=verifier,copy.deepcopy(human_binding),explicitly_approved_hash,copy.deepcopy(context)
        self.review,self.scope=copy.deepcopy(review),review_scope(review)
        self.raw,self.sha,self.clock=bytes(authority_raw),hashlib.sha256(authority_raw).hexdigest(),clock

    def decision(self):
        require(review_scope(self.review)==self.scope and hashlib.sha256(self.raw).hexdigest()==self.sha,
            'DISCOVERY_PARENT_REVIEW_OR_AUTHORITY_CHANGED')
        raw=private_bytes(Path(self.binding['path']),131072)
        require(hashlib.sha256(raw).hexdigest()==self.approved,'DISCOVERY_PARENT_HUMAN_DECISION_CHANGED')
        human=decode(raw);authority=decode(self.raw);now=self.clock()
        require(type(human) is dict and set(human)=={'schema','decision','state','approvalRef','scope',
            'authorityHash','issuedAt','expiresAt'}
            and human['schema']=='ouf.discovery-parent-human-decision.v1'
            and human['decision']==DECISION and human['state']=='ACTIVE'
            and identity(human['approvalRef'])
            and human['scope']==self.scope and human['authorityHash']==self.sha
            and type(human['issuedAt']) is int and type(human['expiresAt']) is int
            and 0<human['expiresAt']-human['issuedAt']<=3600
            and human['issuedAt']<=now<human['expiresAt'],
            'CURRENT_EXPLICIT_DISCOVERY_INSTALLATION_AND_NORMAL_USE_DECISION_REQUIRED')
        require(type(authority) is dict and set(authority)=={'schema','scope','issuedAt','expiresAt',
            'installationRef','entityRef','automaticReplayAllowed','budgetReset','releaseAcceptance'}
            and authority['schema']=='ouf.discovery-parent-execution-authority.v1'
            and authority['scope']==self.scope
            and authority['installationRef']==self.context['installationRef']
            and authority['entityRef']==self.context['entityRef']
            and all(authority[k] is False for k in ('automaticReplayAllowed','budgetReset','releaseAcceptance'))
            and type(authority['issuedAt']) is int and type(authority['expiresAt']) is int
            and human['issuedAt']<=authority['issuedAt']<=now<authority['expiresAt']<=human['expiresAt'],
            'EXACT_FINITE_DISCOVERY_PARENT_EXECUTION_AUTHORITY_REQUIRED')
        configured=policy(self.verifier.read_policy(),self.context['installationRef'],self.context['entityRef'],now)
        for role,key in (('DEPLOYMENT_INTENT','intentIssuerRef'),('FINAL_DEPLOYMENT_APPROVAL','approvalIssuerRef'),
                         ('CREATION_ATTESTATION','attestorRef')):
            selected=[k for k in configured['keys'] if k['issuerRef']==self.context[key] and role in k['roles']
                and k['state']=='ACTIVE' and k['notBefore']<=now<k['expiresAt']]
            require(len(selected)==1 and authority['expiresAt']<=selected[0]['expiresAt'],
                'DISCOVERY_PARENT_WINDOW_EXCEEDS_CURRENT_ROLE_MANDATE')
        return raw

    def guard(self,component,expected_scope):
        require(component in COMPONENTS and self.review['components'][component]==expected_scope
            and digest(expected_scope)==self.scope['componentScopeHashes'][component],
            'EXACT_SEPARATE_DISCOVERY_PARENT_COMPONENT_REQUIRED')
        started=self.clock();before=self.decision()
        for role,key in (('DEPLOYMENT_INTENT','intentIssuerRef'),('FINAL_DEPLOYMENT_APPROVAL','approvalIssuerRef')):
            require(self.verifier(self.raw,role,self.context[key],self.context['installationRef'],self.context['entityRef']) is True,
                'CURRENT_DUAL_ROLE_DISCOVERY_PARENT_SIGNATURE_REQUIRED')
        require(self.decision()==before and self.clock()>=started,'DISCOVERY_PARENT_DECISION_CHANGED_DURING_VERIFICATION')
        return True

    def registry_child(self,child,raw):
        from cutover_authority import CutoverAuthority
        require(type(child) is CutoverAuthority and child.execution_profile is None and child.verifier is self.verifier
            and child.context==self.context,'ACTUAL_SEPARATE_THIRTEEN_PHASE_DISCOVERY_CHILD_REQUIRED')
        expected={'schema':'ouf.discovery-registry-child-scope.v1','authorityHash':hashlib.sha256(raw).hexdigest(),
            'humanManifestHash':child.approved,**child.expected}
        self.guard('registryCutover',expected)
        require(child.expected['sourceClosureHash']==self.scope['sourceClosureHash']
            and child.expected['predecessorHistoryHash']==self.scope['predecessorHistoryHash'],
            'DISCOVERY_CHILD_SOURCE_OR_HISTORY_DRIFT')
        value=decode(raw);parent=decode(self.raw)
        from transition_journal import PHASES
        require(value.get('schema')=='ouf.semantic-cutover-execution-authority.v1'
            and value.get('newDistinctLeaseWorkerRequired') is True
            and set(value.get('phaseIntentHashes',{}))==set(PHASES)
            and all(value.get(k) is False for k in ('automaticReplayAllowed','databaseRestoreAuthorized','r12ReplayAuthorized'))
            and parent['issuedAt']<=value['issuedAt']<value['expiresAt']<=parent['expiresAt'],
            'FULL_DISCOVERY_CHILD_WITHIN_PARENT_WINDOW_REQUIRED')
        require(child(raw) is True,'CURRENT_DISCOVERY_CHILD_HUMAN_AND_ROLE_AUTHORITY_REQUIRED')
        self.guard('registryCutover',expected)
        return True
