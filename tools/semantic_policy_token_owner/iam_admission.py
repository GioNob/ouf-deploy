"""Existing-IAM online token admission and actual peer-bound HTTPS.

No new issuer, JWT decoder, grant authority, default endpoint or permissive
admission. Installation supplies an independently authenticated profile. Secret
material never enters a URL, log, receipt or persisted admission projection.
"""
from dataclasses import dataclass
import http.client
import hashlib
import io
import ipaddress
import json
import math
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from tools.semantic_policy_token_owner.producer import Binding,CredentialFile,check
from tools.semantic_lease_recovery.bounded_recovery import Permanent,Temporary,fingerprint

def unique(pairs):
    out={}
    for key,value in pairs:
        check(key not in out);out[key]=value
    return out

@dataclass(frozen=True)
class IamProfile:
    issuer: str
    token_endpoint: str
    introspection_endpoint: str
    client_id: str
    subject_id: str
    tenant_id: str
    audience: str
    required_scopes: tuple
    allowed_scopes: tuple
    peer_addresses: tuple
    minimum_remaining: int = 90
    maximum_token_seconds: int = 3600

    def __post_init__(self):
        issuer=urllib.parse.urlsplit(self.issuer)
        check(issuer.scheme=='https' and issuer.hostname and not issuer.username and not issuer.password
              and not issuer.query and not issuer.fragment and issuer.path.startswith('/')
              and self.issuer==self.issuer.rstrip('/') and not any(c.isspace() for c in self.issuer))
        # Current OUF uses Keycloak. These must also match its authenticated discovery.
        check(self.token_endpoint==self.issuer+'/protocol/openid-connect/token'
              and self.introspection_endpoint==self.token_endpoint+'/introspect')
        for v in (self.client_id,self.subject_id,self.tenant_id,self.audience):
            check(type(v) is str and 0<len(v)<=256 and not any(c.isspace() or ord(c)<32 for c in v))
        for scopes in (self.required_scopes,self.allowed_scopes):
            check(type(scopes) is tuple and 1<=len(scopes)<=32 and len(set(scopes))==len(scopes)
                  and all(type(s) is str and 0<len(s)<=128 and not any(c.isspace() for c in s) for s in scopes))
        check(set(self.required_scopes)<=set(self.allowed_scopes)
              and 'authorization.bundle.read' in self.required_scopes)
        check(type(self.peer_addresses) is tuple and 1<=len(self.peer_addresses)<=8
              and len(set(self.peer_addresses))==len(self.peer_addresses))
        for address in self.peer_addresses:
            check(type(address) is str and str(ipaddress.ip_address(address))==address)
        check(type(self.minimum_remaining) is int and type(self.maximum_token_seconds) is int
              and 1<=self.minimum_remaining<=self.maximum_token_seconds<=86400)
        _=issuer.port # Reject malformed ports before opening any connection.

    def digest(self):return fingerprint(self.__dict__)
    def match(self,binding):
        check(type(binding) is Binding and binding.endpoint==self.token_endpoint
              and binding.client_id==self.client_id
              and set(binding.scope.split())==set(self.required_scopes)
              and binding.minimum_remaining==self.minimum_remaining
              and binding.maximum_token_seconds==self.maximum_token_seconds)

class _Deadline:
    def __init__(self,clock,timeout):
        check(type(timeout) in (int,float) and math.isfinite(timeout) and 0<timeout<=10)
        self.clock=clock;self.last=clock()[1];self.end=self.last+timeout
    def remaining(self):
        now=self.clock()[1]
        check(type(now) in (int,float) and math.isfinite(now) and now>=self.last)
        self.last=now
        if now>=self.end:raise Temporary('DEPENDENCY_TIMEOUT',no_effect=True)
        return self.end-now

class _Raw(io.RawIOBase):
    def __init__(self,sock,deadline):
        super().__init__();self.sock,self.deadline=sock,deadline
        # HTTPConnection closes its socket as soon as a non-persistent
        # response's headers arrive. Keep the socket's native file reference
        # until the response body is consumed, like SSLSocket.makefile does.
        self.stream=sock.makefile('rb',buffering=0)
    def readable(self):return True
    def readinto(self,buffer):
        self.sock.settimeout(self.deadline.remaining())
        return self.stream.readinto(buffer)
    def close(self):
        if not self.closed:
            try:self.stream.close()
            finally:super().close()

class _Socket:
    def __init__(self,sock,deadline):self.sock,self.deadline=sock,deadline
    def sendall(self,data):
        self.sock.settimeout(self.deadline.remaining());return self.sock.sendall(data)
    def makefile(self,mode):
        check(mode=='rb');return io.BufferedReader(_Raw(self.sock,self.deadline))
    def close(self):self.sock.close()

class _Connection(http.client.HTTPConnection):
    def __init__(self,host,port,address,context,deadline):
        super().__init__(host,port=port,timeout=deadline.remaining())
        self.address,self.context,self.deadline=address,context,deadline
    def connect(self):
        raw=socket.create_connection((self.address,self.port),timeout=self.deadline.remaining())
        try:
            raw.settimeout(self.deadline.remaining())
            secured=self.context.wrap_socket(raw,server_hostname=self.host)
            check(str(ipaddress.ip_address(secured.getpeername()[0]))==self.address)
            self.sock=_Socket(secured,self.deadline)
        except Exception:raw.close();raise

class _Response:
    def __init__(self,connection,response,deadline,mutating):
        self.connection,self.response,self.deadline,self.mutating=connection,response,deadline,mutating
        self.status=response.status;self.total=0
    def __enter__(self):return self
    def __exit__(self,*_):self.close()
    def close(self):
        try:self.response.close()
        finally:self.connection.close()
    def read(self,count):
        try:
            self.deadline.remaining();raw=self.response.read(min(count,65537-self.total))
            self.deadline.remaining();self.total+=len(raw)
            if self.total>65536:raise Permanent('INTEGRITY_UNPROVEN')
            return raw
        except (socket.timeout,TimeoutError):raise Temporary('DEPENDENCY_TIMEOUT',no_effect=not self.mutating) from None
        except Temporary as e:raise Temporary(e.code,retry_after=e.retry_after,no_effect=not self.mutating) from None

class PinnedIamOpener:
    """One configured IP per connection; no DNS re-resolution, proxies or redirects.

    All permitted IPs are independent installation policy, not discovered from a
    token response. TLS hostname/CA verification applies on the actual socket.
    A whole-request deadline bounds header and body trickle, not just each read.
    """
    def __init__(self,profile,clock=lambda:(time.time(),time.monotonic()),context=None):
        check(type(profile) is IamProfile)
        self.profile,self.clock=profile,clock;self.context=context or ssl.create_default_context()
        check(self.context.check_hostname and self.context.verify_mode==ssl.CERT_REQUIRED)
    def trust_digest(self):
        check(self.context.check_hostname and self.context.verify_mode==ssl.CERT_REQUIRED)
        return fingerprint(sorted(hashlib.sha256(raw).hexdigest() for raw in self.context.get_ca_certs(binary_form=True)))
    def open(self,request,timeout):
        self.trust_digest()
        p=self.profile;url=request.full_url;method=request.get_method()
        discovery=p.issuer+'/.well-known/openid-configuration'
        check((url==discovery and method=='GET' and request.data is None)
              or (url in (p.token_endpoint,p.introspection_endpoint) and method=='POST'))
        mutating=url==p.token_endpoint;parts=urllib.parse.urlsplit(url);deadline=_Deadline(self.clock,timeout)
        # Do not try another peer after failure: the durable owner owns any retry.
        connection=_Connection(parts.hostname,parts.port or 443,p.peer_addresses[0],self.context,deadline)
        submitted=False;response=None
        def close_failed_response():
            try:
                if response is not None:response.close()
            finally:connection.close()
        try:
            connection.connect();deadline.remaining();submitted=True
            headers={'Host':parts.netloc,'Accept':'application/json','Connection':'close'}
            if method=='POST':headers['Content-Type']='application/x-www-form-urlencoded'
            connection.request(method,parts.path,body=request.data,headers=headers)
            response=connection.getresponse();deadline.remaining()
            if response.status in (400,401,403):raise Permanent('PERMANENT_FAILURE')
            if response.status in (301,302,303,307,308):raise Permanent('CONFIGURATION_DRIFT')
            if response.status!=200:
                if response.status in (429,502,503,504):
                    delay=response.getheader('Retry-After','0')
                    if not delay.isdigit():raise Permanent('INTEGRITY_UNPROVEN')
                    raise Temporary('RATE_LIMITED' if response.status==429 else 'SERVICE_UNAVAILABLE',retry_after=int(delay),no_effect=not mutating)
                raise Permanent('PERMANENT_FAILURE')
            content=response.getheader('Content-Type','').split(';',1)[0].strip().lower()
            check(content=='application/json')
            return _Response(connection,response,deadline,mutating)
        except ssl.SSLError:
            close_failed_response();raise Permanent('INTEGRITY_UNPROVEN') from None
        except Temporary as e:
            close_failed_response();raise Temporary(e.code,retry_after=e.retry_after,no_effect=not mutating or not submitted) from None
        except Permanent:close_failed_response();raise
        except (socket.timeout,TimeoutError,ConnectionError,OSError,http.client.HTTPException):
            close_failed_response();raise Temporary('DEPENDENCY_TIMEOUT',no_effect=not mutating or not submitted) from None
        except Exception:
            close_failed_response();raise Permanent('INTEGRITY_UNPROVEN') from None

class OnlineIamAdmission:
    """Read-only authenticated discovery/introspection at the EXISTING issuer.

    The issuer determines token validity/signature/revocation. Local comparisons
    restrict the admitted client, subject, tenant, SERVICE actor, audience and
    scopes to the independently approved OUF binding. No JWT claims are decoded
    locally and no response/credential is logged or persisted here.
    """
    def __init__(self,profile,credential,transport,clock=lambda:(time.time(),time.monotonic())):
        check(type(profile) is IamProfile and type(credential) is CredentialFile
              and type(transport) is PinnedIamOpener and transport.profile==profile)
        self.profile,self.credential,self.transport,self.clock=profile,credential,transport,clock
    def request(self,url,deadline,data=None):
        now=self.clock()[1];timeout=min(10,deadline-now)
        if timeout<=0:raise Temporary('DEPENDENCY_TIMEOUT',no_effect=True)
        request=urllib.request.Request(url,data=None if data is None else urllib.parse.urlencode(data).encode('ascii'),method='GET' if data is None else 'POST')
        with self.transport.open(request,timeout) as response:
            raw=response.read(65537)
        try:return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in ()).throw(ValueError()))
        except Exception:raise Permanent('INTEGRITY_UNPROVEN') from None
    def prepare(self,deadline):
        p=self.profile;metadata=self.request(p.issuer+'/.well-known/openid-configuration',deadline)
        check(type(metadata) is dict and metadata.get('issuer')==p.issuer
              and metadata.get('token_endpoint')==p.token_endpoint
              and metadata.get('introspection_endpoint')==p.introspection_endpoint)
        return True
    def admit(self,token,valid_until_monotonic,deadline):
        p=self.profile;before_wall,before_mono=self.clock()
        check(type(token) is str and 0<len(token)<=16384 and not any(c.isspace() for c in token)
              and type(valid_until_monotonic) in (int,float) and math.isfinite(valid_until_monotonic))
        value=self.request(p.introspection_endpoint,deadline,{'token':token,'token_type_hint':'access_token','client_id':p.client_id,'client_secret':self.credential.read()})
        if type(value) is dict and value.get('active') is False:raise Permanent('AUTHORITY_REVOKED')
        check(type(value) is dict and value.get('active') is True and value.get('iss')==p.issuer
              and value.get('client_id')==p.client_id and value.get('sub')==p.subject_id
              and value.get('tenant_id')==p.tenant_id and value.get('ouf_actor_type')=='SERVICE'
              and type(value.get('scope')) is str and type(value.get('exp')) is int
              and type(value.get('iat')) is int and 0<=value['iat']<value['exp'])
        audiences=value.get('aud');audiences=[audiences] if type(audiences) is str else audiences
        check(type(audiences) is list and audiences and all(type(a) is str for a in audiences)
              and p.audience in audiences)
        scopes=set(value['scope'].split());check(set(p.required_scopes)<=scopes<=set(p.allowed_scopes))
        wall,mono=self.clock();check(before_wall<=wall and before_mono<=mono<deadline and value['iat']<=before_wall)
        remaining=min(value['exp']-wall,valid_until_monotonic-mono)
        if remaining<p.minimum_remaining:raise Permanent('AUTHORITY_EXPIRED')
        check(value['exp']-before_wall<=p.maximum_token_seconds)
        return True
