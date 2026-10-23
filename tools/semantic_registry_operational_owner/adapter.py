"""Actual existing-IAM transport and atomic publisher; no credential provisioning."""
import copy
import hashlib
import ssl
from pathlib import Path
from .core import require, NotSubmitted, number
from .guard import InstalledGuard, protected_file
from .store import Store
from tools.semantic_policy_token_owner.producer import Binding, CredentialFile, HttpsGrant, AtomicTokenFile, token_response
from tools.semantic_policy_token_owner.iam_admission import IamProfile, PinnedIamOpener, OnlineIamAdmission
from tools.semantic_lease_recovery.bounded_recovery import Temporary


class ExpiryAdmission(OnlineIamAdmission):
    """Retain only exp after the unchanged online validator accepts the response."""
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs);self.response_expiry=None;self.verified_expiry=None

    def request(self,url,deadline,data=None):
        value=super().request(url,deadline,data)
        if url==self.profile.introspection_endpoint:
            self.response_expiry=value.get('exp') if type(value) is dict else None
        return value

    def admit(self,token,valid_until_monotonic,deadline):
        self.response_expiry=self.verified_expiry=None
        result=super().admit(token,valid_until_monotonic,deadline)
        require(result is True and type(self.response_expiry) is int,'AUTHENTICATED_TOKEN_EXPIRY_REQUIRED')
        self.verified_expiry=self.response_expiry
        return result


class NativeAdapter:
    def __init__(self,guard,store,clock):
        require(type(guard) is InstalledGuard and type(store) is Store,'ACTUAL_INSTALLED_GUARD_AND_LEDGER_REQUIRED')
        self.owner,self.store,self.clock=guard,store,clock
        inputs=guard.configuration['ownerInputs']
        self.binding=Binding(**inputs['binding']);p=copy.deepcopy(inputs['iamProfile'])
        for name in ('required_scopes','allowed_scopes','peer_addresses'):p[name]=tuple(p[name])
        self.profile=IamProfile(**p);self.profile.match(self.binding)
        self.credential=CredentialFile(Path(inputs['credentialPath']))
        self.pair_clock=lambda:self.clock()[1:]
        ca=guard.configuration['tlsCa']
        require(type(ca) is dict and set(ca)=={'path','sha256'},'EXACT_OPERATIONAL_PUBLIC_CA_BINDING_REQUIRED')
        ca_raw=protected_file(ca['path'],4194304,expected=ca['sha256'],modes=(0o400,0o440,0o444,0o600,0o640,0o644))
        context=ssl.create_default_context(cadata=ca_raw.decode('ascii'))
        self.transport=PinnedIamOpener(self.profile,self.pair_clock,context=context)
        require(self.transport.trust_digest()==inputs['tlsTrustHash'],'EXISTING_IAM_CA_TRUST_CHANGED')
        self.grant_transport=HttpsGrant(self.pair_clock,opener=self.transport)
        self.admission=ExpiryAdmission(self.profile,self.credential,self.transport,self.pair_clock)
        self.writer=AtomicTokenFile(self.binding);self.pending=None

    def guard(self):
        self.owner.guard();self.store.assert_invocation()
        require(self.transport.trust_digest()==self.owner.configuration['ownerInputs']['tlsTrustHash'],
                'OPERATIONAL_IAM_TRUST_CHANGED')
        self.writer.check_custody()

    def grant_and_admit(self,deadline):
        self.guard();self.pending=None
        try:self.admission.prepare(deadline)
        except Temporary as error:
            # Discovery is a GET. No grant transport has been called.
            raise NotSubmitted() from error
        secret=self.credential.read();self.guard()
        _,wall,mono=self.clock()
        try:response=self.grant_transport.request(self.binding,secret,deadline)
        except Temporary as error:
            if error.no_effect is True:raise NotSubmitted() from error
            raise
        token,seconds=token_response(response,self.binding)
        self.admission.admit(token,mono+seconds,deadline)
        expiry=min(wall+seconds,self.admission.verified_expiry)
        self.guard()
        require(number(expiry),'VERIFIED_OPERATIONAL_TOKEN_WINDOW_REQUIRED')
        self.pending={'hash':hashlib.sha256(token.encode()).hexdigest(),'expiresWall':expiry,
                      'expiresMono':mono+seconds,'deadline':deadline,'startedWall':wall,'startedMono':mono}
        return token,expiry

    def publish(self,token,attempt_id,token_hash):
        self.guard();value=self.pending;self.pending=None
        require(type(value) is dict and value['hash']==token_hash==hashlib.sha256(token.encode()).hexdigest()
                and type(attempt_id) is str and len(attempt_id)==64,'ONE_ADMITTED_PUBLICATION_ONLY')
        def before_replace():
            self.guard();_,wall,mono=self.clock()
            require(value['startedWall']<=wall and value['startedMono']<=mono<value['deadline']
                    and min(value['expiresWall']-wall,value['expiresMono']-mono)>=self.binding.minimum_remaining,
                    'CURRENT_TOKEN_PUBLICATION_WINDOW_REQUIRED')
        before_replace();self.writer.publish(token,before_replace)

    def verify_publication(self,token_hash):
        self.guard()
        path=Path(self.binding.output_directory)/self.binding.output_member
        protected_file(path,16384,expected=token_hash,modes=(0o440,))

    def readmit_existing(self,token_hash):
        self.guard();row=self.store.read();_,wall,mono=self.clock()
        require(row['tokenHash']==token_hash and row['tokenExpiresWall']>wall,'EXACT_CURRENT_PUBLICATION_FOR_READMISSION_REQUIRED')
        raw=protected_file(Path(self.binding.output_directory)/self.binding.output_member,16384,expected=token_hash,modes=(0o440,))
        token=raw.decode('ascii');deadline=mono+self.owner.configuration['policy']['attempt_timeout_seconds']
        self.admission.prepare(deadline)
        self.admission.admit(token,mono+row['tokenExpiresWall']-wall,deadline)
        self.verify_publication(token_hash)
        return min(self.admission.verified_expiry,row['tokenExpiresWall'])
