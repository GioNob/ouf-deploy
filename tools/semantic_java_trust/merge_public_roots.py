"""Merge a public provider CA with the candidate's own public Java roots."""
import hashlib,os,re,ssl,subprocess
from pathlib import Path
def sha(raw):return hashlib.sha256(raw).hexdigest()
def require(v,why):
    if not v:raise ValueError(why)
def certificates(raw):
    require(len(raw)<=2097152 and b'PRIVATE KEY' not in raw,'PUBLIC_CERTIFICATES_ONLY_REQUIRED')
    blocks=re.findall(b'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',raw,re.S)
    require(0<len(blocks)<=1024,'BOUNDED_PUBLIC_CERTIFICATES_REQUIRED')
    return {sha(ssl.PEM_cert_to_DER_cert(b.decode('ascii'))) for b in blocks}
def run(keytool,args):
    p=subprocess.run([str(keytool),'-J-Duser.language=en','-J-Duser.country=US',*args],capture_output=True,timeout=30)
    require(p.returncode==0 and len(p.stdout)<=2097152 and len(p.stderr)<=131072,'NATIVE_KEYTOOL_PUBLIC_STORE_UNPROVEN');return p.stdout+p.stderr
def public_store(keytool,path):
    raw=run(keytool,['-list','-rfc','-keystore',str(path),'-storepass','changeit'])
    require(b'PrivateKeyEntry' not in raw and b'SecretKeyEntry' not in raw and b'trustedCertEntry' in raw,'PUBLIC_TRUSTED_CERT_ENTRIES_ONLY_REQUIRED')
    return certificates(raw)
def merge(keytool,baseline,ca,destination):
    keytool,baseline,ca,destination=map(Path,(keytool,baseline,ca,destination))
    require(not os.path.lexists(destination),'TRUSTSTORE_OUTPUT_EXISTS_RECONCILE')
    before=public_store(keytool,baseline);added=certificates(ca.read_bytes());require(len(added)==1 and before.isdisjoint(added),'ONE_DISTINCT_PROVIDER_CA_REQUIRED')
    baseline_hash=sha(baseline.read_bytes());ca_hash=sha(ca.read_bytes())
    run(keytool,['-importkeystore','-noprompt','-srckeystore',str(baseline),'-srcstorepass','changeit','-destkeystore',str(destination),'-deststoretype','PKCS12','-deststorepass','changeit'])
    run(keytool,['-importcert','-noprompt','-alias','ouf-discovery-provider-root','-file',str(ca),'-keystore',str(destination),'-storetype','PKCS12','-storepass','changeit'])
    after=public_store(keytool,destination)
    require(after==before|added and sha(baseline.read_bytes())==baseline_hash and sha(ca.read_bytes())==ca_hash,'JAVA_PUBLIC_ROOT_PRESERVATION_UNPROVEN')
    require(destination.stat().st_size<=2097152,'BOUNDED_JAVA_STORE_REQUIRED');destination.chmod(0o600)
    with destination.open('rb') as stream:os.fsync(stream.fileno())
    return {'baselineCertificateCount':len(before),'mergedCertificateCount':len(after),'baselineHash':baseline_hash,'providerCaHash':ca_hash,'truststoreHash':sha(destination.read_bytes()),'publicRootsPreserved':True,'containsPrivateKeys':False,'storeType':'PKCS12','mounted':False}
