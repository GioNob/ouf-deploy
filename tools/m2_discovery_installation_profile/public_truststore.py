"""Certificate-only Java PKCS12 bytes from an exact explicit CA set.

No file/network/process/key generation. The caller must authenticate the IAM
fingerprints and provider-file binding independently. The public password/MAC
is format integrity, never deployment or certificate approval authority.
Format: RFC7292 password integrity (SHA256) and OpenJDK trustedKeyUsage.
"""
import hashlib
import hmac
import math
import re
import ssl
from .audit import require

PASSWORD='changeit'
ITERATIONS=100000
MAX_STORE=1048576
PEM=re.compile(rb'-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+?-----END CERTIFICATE-----')


def _der(tag,value):
    n=len(value)
    length=bytes([n]) if n<128 else bytes([0x80+(n.bit_length()+7)//8])+n.to_bytes((n.bit_length()+7)//8,'big')
    return bytes([tag])+length+value


def _seq(*values):return _der(0x30,b''.join(values))
def _octet(value):return _der(4,value)
def _integer(value):
    raw=value.to_bytes(max(1,(value.bit_length()+7)//8),'big')
    return _der(2,(b'\0' if raw[0]&0x80 else b'')+raw)


def _oid(text):
    arcs=list(map(int,text.split('.')));body=bytearray()
    for value in [40*arcs[0]+arcs[1],*arcs[2:]]:
        encoded=[value&127];value>>=7
        while value:encoded.insert(0,128|(value&127));value>>=7
        body.extend(encoded)
    return _der(6,bytes(body))


def _data(value):return _seq(_oid('1.2.840.113549.1.7.1'),_der(0xa0,_octet(value)))


def _mac_key(salt):
    # RFC7292 Appendix B. Only one SHA256 output block (32 bytes) is needed
    # for the SHA256 MAC, so no subsequent-block I adjustment is performed.
    def repeat(value):return (value*((64+len(value)-1)//len(value)))[:64]
    password=PASSWORD.encode('utf-16-be')+b'\0\0'
    block=hashlib.sha256(b'\x03'*64+repeat(salt)+repeat(password)).digest()
    for _ in range(ITERATIONS-1):block=hashlib.sha256(block).digest()
    return block


def _pkcs12(certificates):
    bags=[]
    for certificate in certificates:
        name='ca-'+hashlib.sha256(certificate).hexdigest()
        friendly=_seq(_oid('1.2.840.113549.1.9.20'),_der(0x31,_der(0x1e,name.encode('utf-16-be'))))
        trusted=_seq(_oid('2.16.840.1.113894.746875.1.1'),_der(0x31,_oid('2.5.29.37.0')))
        certbag=_seq(_oid('1.2.840.113549.1.9.22.1'),_der(0xa0,_octet(certificate)))
        bags.append(_seq(_oid('1.2.840.113549.1.12.10.1.3'),_der(0xa0,certbag),
                         _der(0x31,b''.join(sorted([friendly,trusted])))))
    authenticated=_seq(_data(_seq(*bags)))
    # All inputs and the format password are public. A deterministic salt makes
    # the derived public artifact reproducible; it protects no secret password.
    salt=hashlib.sha256(b'OUF_PUBLIC_CA_PKCS12_V1\0'+authenticated).digest()[:20]
    mac=hmac.new(_mac_key(salt),authenticated,hashlib.sha256).digest()
    digest_info=_seq(_seq(_oid('2.16.840.1.101.3.4.2.1'),_der(5,b'')),_octet(mac))
    return _seq(_integer(3),_data(authenticated),_seq(digest_info,_octet(salt),_integer(ITERATIONS)))


def _ca_certificates(pem):
    require(type(pem) is bytes and 0<len(pem)<=4194304,'BOUNDED_PUBLIC_CA_BUNDLE_REQUIRED')
    values=[];position=0
    for match in PEM.finditer(pem):
        require(not pem[position:match.start()].strip(),'PUBLIC_CERTIFICATES_WITHOUT_OTHER_MATERIAL_REQUIRED')
        certificate=ssl.PEM_cert_to_DER_cert(match.group().decode('ascii'))
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        require(context.get_ca_certs()==[],'EMPTY_EXPLICIT_CA_CONTEXT_REQUIRED')
        context.load_verify_locations(cadata=match.group().decode('ascii'))
        require(context.get_ca_certs(binary_form=True)==[certificate], 'EXPLICIT_CA_CERTIFICATE_REQUIRED')
        values.append((certificate,context.get_ca_certs()[0]));position=match.end()
    require(not pem[position:].strip() and 1<=len(values)<=1024
            and len({v[0] for v in values})==len(values),'EXACT_UNIQUE_PUBLIC_CA_CERTIFICATES_REQUIRED')
    return values


def build(iam_pem,expected_iam_fingerprints,provider_pem,expected_provider_file_hash,now):
    require(type(now) in (int,float) and math.isfinite(now) and now>0,'FINITE_TRUST_PREPARATION_TIME_REQUIRED')
    require(type(expected_iam_fingerprints) is list and 1<=len(expected_iam_fingerprints)<=1024
            and all(type(v) is str and re.fullmatch('[0-9a-f]{64}',v) for v in expected_iam_fingerprints)
            and expected_iam_fingerprints==sorted(set(expected_iam_fingerprints)),
            'EXACT_EXPLICIT_IAM_CA_FINGERPRINT_SET_REQUIRED')
    require(type(expected_provider_file_hash) is str and re.fullmatch('[0-9a-f]{64}',expected_provider_file_hash)
            and type(provider_pem) is bytes and hashlib.sha256(provider_pem).hexdigest()==expected_provider_file_hash,
            'EXACT_BOUND_PROVIDER_PUBLIC_CA_FILE_REQUIRED')
    iam=_ca_certificates(iam_pem);provider=_ca_certificates(provider_pem)
    actual=sorted(hashlib.sha256(v[0]).hexdigest() for v in iam)
    require(actual==expected_iam_fingerprints,'IAM_CA_SET_MUST_MATCH_WITHOUT_AMBIENT_EXTRAS')
    require(len(provider)==1 and ssl.cert_time_to_seconds(provider[0][1]['notBefore'])<=now
            <ssl.cert_time_to_seconds(provider[0][1]['notAfter']),'CURRENT_SINGLE_PROVIDER_CA_REQUIRED')
    # Preserve the entire approved IAM CA set. Endpoint chain/expiry admission
    # remains with the current IAM owner; do not silently prune/change its roots.
    certificates=sorted({v[0] for v in iam+provider},key=lambda v:hashlib.sha256(v).hexdigest())
    raw=_pkcs12(certificates);require(len(raw)<=MAX_STORE,'BOUNDED_PUBLIC_JAVA_TRUSTSTORE_REQUIRED')
    return raw,{'schema':'ouf.discovery-public-java-truststore-proposal.v1',
        'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'certificateCount':len(certificates),
        'iamCaFingerprints':actual,'providerCaFingerprint':hashlib.sha256(provider[0][0]).hexdigest(),
        'allCaFingerprints':[hashlib.sha256(v).hexdigest() for v in certificates],
        'providerCaTimeCheckedAt':now,'privateKeyCount':0,'ambientCaRootsAdded':False,
        'approvedIamCaSetPreserved':True,'inputsAuthenticatedHere':False,
        'iamTlsAdmissionProven':False,'providerTlsAdmissionProven':False,
        'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'releaseAcceptance':False}
