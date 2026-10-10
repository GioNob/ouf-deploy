"""Verify publisher signatures against existing local ZIPs; never imports or applies."""
import hashlib,json,os,re,stat,subprocess,sys
from pathlib import Path
STAGE=Path("/home/oufadmin/ouf-file-loop-offline-stage.LMawhAuO")
PUBLISHER_SHA="cc39a2d9a20a3edeacb1594d34e0a1780e897113"
ROOTS_SHA="1cb25d6ad95e58d0405d01ea4a245ca85704ad11"
COSIGN_SHA="4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71"
SPECS={
 "semantic":("a0c30bbb7d44d3e6405bae28ad80b6c5dcfc28ed2f078d387cf4e26d179e28c3","622614b0040cf11be2f6c7e3568733a488ca4ca8","sha256:e826bd9769a72e930e356f72c1c244007f9a34d065db94ca8113b064d10d8b85",10),
 "ingestion":("29a981ddfaed56265ed1061bdf9a59088e87cd0cac46d5844a7fe9255a7d9c32","8b908554314617298242eb2ae8312f734f55e817","sha256:98af9d774e446ce621128a52bfa1f9faaa096052cdc185f17dc81f1ea76e9a05",14),
 "udp":("36de53a045bbe94c3cdda80cf6599adfd014c595da1720c817f2aeb586ef14cd","bc336208ce41876f2854c3a4d8623fb6698bdcdd","sha256:7a97979286113c4e3ef6bae87e1bf2d54d2f7195d447ce43b9329f3b90899d28",34)}
def require(ok,reason):
    if not ok:raise ValueError(reason)
def digest(path):
    st=path.lstat();require(stat.S_ISREG(st.st_mode) and st.st_nlink==1,"REGULAR_UNLINKED_SIGNATURE_SUBJECT_REQUIRED")
    same=lambda x:(x.st_dev,x.st_ino,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW),"rb") as src:
        require(same(os.fstat(src.fileno()))==same(st),"SUBJECT_OPEN_CHANGED")
        value=hashlib.file_digest(src,"sha256").hexdigest()
        require(same(os.fstat(src.fileno()))==same(st)==same(path.lstat()),"SUBJECT_CHANGED_DURING_HASH")
    return value
def metadata(path):
    require(path.lstat().st_size<=4194304,"BOUNDED_PUBLISHER_METADATA_REQUIRED")
    return json.loads(path.read_bytes())
def verify(binary,subject,bundle,workflow,sha,branch):
    before=digest(subject)
    identity="https://github.com/GioNob/ouf-deploy/.github/workflows/"+workflow+"@refs/heads/"+branch
    p=subprocess.run([str(binary),"verify-blob",str(subject),"--bundle",str(bundle),
       "--certificate-identity",identity,"--certificate-oidc-issuer","https://token.actions.githubusercontent.com",
       "--certificate-github-workflow-repository","GioNob/ouf-deploy","--certificate-github-workflow-sha",sha],
       capture_output=True,timeout=180)
    require(p.returncode==0,"TARGET_PUBLISHER_SIGNATURE_VERIFICATION_FAILED")
    require(digest(subject)==before,"SUBJECT_CHANGED_AFTER_SIGNATURE")
def main():
    base={"schema":"ouf.file-loop.target-publisher-byte-verification.v1","imageImports":0,
       "containerLifecycleOperations":0,"applicationConfigurationWrites":0,"deploymentSignaturesIssued":0,
       "installationAuthorityAccepted":False,"applicationCutoverAuthorized":False,
       "privateKeysRead":0,"r9Touched":False,"notReleaseAcceptance":True}
    try:
        require(len(sys.argv)==2,"EXACT_PUBLISHER_CAPSULE_ARGUMENT_REQUIRED")
        root=Path(sys.argv[1]).resolve();binary=root/"cosign-linux-amd64"
        require(digest(binary)==COSIGN_SHA,"PINNED_COSIGN_BINARY_REQUIRED")
        rows=[]
        for module,(expected,source,image,count) in SPECS.items():
            archive=STAGE/(module+".zip");proof=root/module
            require(digest(archive)==expected,"ORIGINAL_STAGED_ZIP_CHANGED")
            verify(binary,archive,proof/(module+".zip.sigstore.json"),"file-loop-package-provenance.yml",PUBLISHER_SHA,"codex/file-loop-package-provenance-20261010")
            verify(binary,proof/"continuity.json",proof/"continuity.json.sigstore.json","file-loop-package-provenance.yml",PUBLISHER_SHA,"codex/file-loop-package-provenance-20261010")
            row=metadata(proof/"continuity.json")
            require(row.get("originalZipSha256")==expected and row.get("sourceCommit")==source and row.get("imageId")==image and row.get("migrationCount")==count,"EXACT_SIGNED_PACKAGE_CONTEXT_REQUIRED")
            require(all(row.get(k) is True for k in ("originalZipBytesVerified","allMemberChecksumsVerified","packagedSqlBytesVerified","fixtureIdentityExcluded","runtimeSdkPackaged")),"SIGNED_PACKAGE_CLOSURE_UNPROVEN")
            require(row.get("targetApplyAuthorized") is False and row.get("imageRebuilt") is False,"RETAINED_PACKAGE_NO_APPLY_SCOPE_REQUIRED")
            rows.append({"module":module,"sourceCommit":source,"imageId":image,"migrationCount":count,"originalZipSha256":expected,"publisherCryptoVerified":True})
        roots=root/"public-roots"
        for name in ("candidate-cacerts","public-roots.json"):
            verify(binary,roots/name,roots/(name+".sigstore.json"),"file-loop-candidate-public-roots.yml",ROOTS_SHA,"codex/file-loop-candidate-public-roots-20261010")
        info=metadata(roots/"public-roots.json")
        require(info.get("imageId")==SPECS["semantic"][2] and info.get("sourceCommit")==SPECS["semantic"][1] and info.get("originalZipSha256")==SPECS["semantic"][0],"EXACT_NEW_CANDIDATE_ROOT_CONTEXT_REQUIRED")
        require(digest(roots/"candidate-cacerts")==info.get("publicStoreHash")=="98d34a90fca2688ef5674862d2a484e09e5ca25d2f07c5d654aa28f1581f3419","NEW_CANDIDATE_PUBLIC_ROOT_BYTES_MISMATCH")
        result={**base,"status":"PUBLISHER_CRYPTO_AND_NEW_PUBLIC_ROOT_BYTES_VERIFIED_NOT_APPLY_READY",
             "capsuleDirectory":str(root),"packages":rows,"publicRootStoreHash":info["publicStoreHash"],
             "publicRootBytesMatchHistoricalBaseline":True,"publicRootsMergedOrMounted":False}
        code=0
    except Exception as error:
        reason=str(error);result={**base,"status":"TARGET_PUBLISHER_VERIFICATION_BLOCKED","errorType":type(error).__name__,
             "reason":reason if re.fullmatch("[A-Z][A-Z0-9_]{0,120}",reason) else "TARGET_CRYPTO_UNPROVEN"};code=1
    print("OUF_FILE_LOOP_TARGET_PUBLISHER_VERIFICATION="+json.dumps(result,sort_keys=True));return code
if __name__=="__main__":raise SystemExit(main())
