"""Read-only comparison of existing public trust bytes with the new candidate baseline."""
import hashlib,json,os,re,stat,sys
from pathlib import Path
INPUTS=Path("/etc/ouf/deploy-snapshots/semantic-discovery-runtime-inputs-682nr5ky")
TRUST=Path("/etc/ouf/deploy-snapshots/semantic-discovery-java-trust-4pgerb71")
MANIFEST="732a633e46cb06bb720352aa6a90946281ba6489e94aa35dc04820eae56b4a70"
BASELINE="98d34a90fca2688ef5674862d2a484e09e5ca25d2f07c5d654aa28f1581f3419"
CA="b1bda8d7dffb8d074e9eabeae7faa7d44bb7fe27375dae78859fcce1697d087b"
STORE="dcfb221cf3382ab02b752bce3274f64a63c0d822227a5359d1329dee38008079"
IMAGE="sha256:e826bd9769a72e930e356f72c1c244007f9a34d065db94ca8113b064d10d8b85"
SOURCE="622614b0040cf11be2f6c7e3568733a488ca4ca8"
def require(ok,reason):
    if not ok:raise ValueError(reason)
def qualify(receipt,baseline,ca,store):
    require(baseline==BASELINE and ca==CA and store==STORE,"NEW_CANDIDATE_PUBLIC_TRUST_BYTE_BINDING_REQUIRED")
    require(receipt.get("schema")=="ouf.discovery.java-trust-preparation.v1" and receipt.get("status")=="CANDIDATE_PUBLIC_JAVA_TRUST_PREPARED_NOT_MOUNTED","EXACT_RETAINED_PUBLIC_TRUST_RECEIPT_REQUIRED")
    expected={"runtimeInputManifestHash":MANIFEST,"baselineHash":BASELINE,"providerCaHash":CA,
        "truststoreHash":STORE,"baselineCertificateCount":118,"mergedCertificateCount":119,
        "publicRootsPreserved":True,"containsPrivateKeys":False,"storeType":"PKCS12","mounted":False,
        "applicationCutoverAuthorized":False,"semanticUid":10001}
    require(all(type(receipt.get(k)) is type(v) and receipt.get(k)==v for k,v in expected.items()),"RETAINED_PUBLIC_TRUST_SCOPE_OR_CONTENT_DRIFT")
    return {"candidateImageId":IMAGE,"candidateSourceCommit":SOURCE,"baselineHash":baseline,
       "providerCaHash":ca,"truststoreHash":store,"baselineCertificateCount":118,"mergedCertificateCount":119,
       "publicRootsPreservationProof":"EXACT_BYTES_OF_PREVIOUSLY_VERIFIED_PUBLIC_ONLY_STORE",
       "priorInstallationAuthorityReused":False,"truststoreRegenerated":False,"storeType":"PKCS12"}
def directory(path):
    st=path.lstat()
    require(stat.S_ISDIR(st.st_mode) and st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o700,"ROOT_PRIVATE_DIRECTORY_METADATA_REQUIRED")
def file_bytes(path,owner,mode,expected=None):
    st=path.lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and st.st_uid==owner and stat.S_IMODE(st.st_mode)==mode and 0<st.st_size<=2097152,"EXACT_PUBLIC_TRUST_FILE_METADATA_REQUIRED")
    same=lambda x:(x.st_dev,x.st_ino,x.st_size,x.st_mtime_ns,x.st_ctime_ns,x.st_uid,x.st_mode)
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW),"rb") as f:
        require(same(os.fstat(f.fileno()))==same(st),"PUBLIC_TRUST_OPEN_CHANGED")
        raw=f.read(2097153)
        require(same(os.fstat(f.fileno()))==same(st)==same(path.lstat()),"PUBLIC_TRUST_FILE_CHANGED")
    require(len(raw)<=2097152 and (expected is None or hashlib.sha256(raw).hexdigest()==expected),"EXACT_PUBLIC_TRUST_FILE_BYTES_REQUIRED")
    return raw
def main():
    base={"schema":"ouf.file-loop.candidate-trust-byte-comparison.v1","applyAuthorized":False,
      "mountsInstalled":False,"existingConfigurationWrites":0,"imageImports":0,"containerLifecycleOperations":0,
      "privateKeyFilesOpened":0,"credentialFilesOpened":0,"deploymentSignaturesIssued":0,
      "commonLockAcquired":False,"dnsQueries":0,"providerCalls":0,"r9Touched":False,"privateValuesPrinted":False,
      "newDecisionIssued":False,"readOnlyRetrySafe":True,"notReleaseAcceptance":True}
    try:
        require(os.geteuid()==0 and sys.flags.isolated and sys.dont_write_bytecode,"ISOLATED_ROOT_READ_REQUIRED")
        directory(INPUTS);directory(TRUST)
        manifest=file_bytes(INPUTS/"private-input-manifest.json",0,0o600,MANIFEST)
        before=file_bytes(TRUST/"receipt.json",0,0o600)
        receipt=json.loads(before)
        baseline=file_bytes(TRUST/"candidate-cacerts",0,0o600,BASELINE)
        ca=file_bytes(INPUTS/"provider-public-ca.crt",0,0o600,CA)
        copied_ca=file_bytes(TRUST/"provider-public-ca.crt",0,0o600,CA)
        store=file_bytes(TRUST/"java-truststore.p12",10001,0o400,STORE)
        result=qualify(receipt,hashlib.sha256(baseline).hexdigest(),hashlib.sha256(ca).hexdigest(),hashlib.sha256(store).hexdigest())
        require(copied_ca==ca,"PUBLIC_CA_COPY_CHANGED")
        for path,owner,mode,original in ((INPUTS/"private-input-manifest.json",0,0o600,manifest),(TRUST/"receipt.json",0,0o600,before),(TRUST/"candidate-cacerts",0,0o600,baseline),(INPUTS/"provider-public-ca.crt",0,0o600,ca),(TRUST/"provider-public-ca.crt",0,0o600,copied_ca),(TRUST/"java-truststore.p12",10001,0o400,store)):
            require(file_bytes(path,owner,mode)==original,"PUBLIC_TRUST_INPUT_CHANGED_DURING_READ")
        output={**base,**result,"status":"EXISTING_PUBLIC_TRUST_BYTES_MATCH_NEW_CANDIDATE_BASELINE",
           "snapshotFilesRead":6,"readConsistencyMode":"STABLE_REREADS_NOT_TRANSITION_AUTHORITY"}
        code=0
    except Exception as error:
        reason=str(error);output={**base,"status":"PUBLIC_TRUST_COMPARISON_BLOCKED","errorType":type(error).__name__,
            "reason":reason if re.fullmatch("[A-Z][A-Z0-9_]{0,120}",reason) else "PUBLIC_TRUST_COMPARISON_UNPROVEN"};code=1
    print("OUF_CANDIDATE_TRUST_BYTE_COMPARISON="+json.dumps(output,sort_keys=True));return code
if __name__=="__main__":raise SystemExit(main())
