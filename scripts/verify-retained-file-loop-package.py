#!/usr/bin/env python3
"""Validate retained package byte continuity; no build or host-apply claims."""
import argparse,hashlib,json,pathlib,re,stat,zipfile
SPECS={
"semantic":{"artifactId":11676412613,"zipSha256":"a0c30bbb7d44d3e6405bae28ad80b6c5dcfc28ed2f078d387cf4e26d179e28c3","source":"622614b0040cf11be2f6c7e3568733a488ca4ca8","image":"sha256:e826bd9769a72e930e356f72c1c244007f9a34d065db94ca8113b064d10d8b85"},
"ingestion":{"artifactId":11676720102,"zipSha256":"29a981ddfaed56265ed1061bdf9a59088e87cd0cac46d5844a7fe9255a7d9c32","source":"8b908554314617298242eb2ae8312f734f55e817","image":"sha256:98af9d774e446ce621128a52bfa1f9faaa096052cdc185f17dc81f1ea76e9a05"},
"udp":{"artifactId":11676625220,"zipSha256":"36de53a045bbe94c3cdda80cf6599adfd014c595da1720c817f2aeb586ef14cd","source":"bc336208ce41876f2854c3a4d8623fb6698bdcdd","image":"sha256:7a97979286113c4e3ef6bae87e1bf2d54d2f7195d447ce43b9329f3b90899d28"}}
def require(ok,why):
    if not ok:raise ValueError(why)
def digest(stream):return hashlib.file_digest(stream,"sha256").hexdigest()
def verify(path,module):
    spec=SPECS[module]
    with path.open("rb") as raw:require(digest(raw)==spec["zipSha256"],"ORIGINAL_PRODUCER_ZIP_BYTES_REQUIRED")
    with zipfile.ZipFile(path) as z:
        names=z.namelist()
        require(len(names)==len(set(names)) and len(names)<=256,"BOUNDED_UNIQUE_ARCHIVE_MEMBERS_REQUIRED")
        for item in z.infolist():
            p=pathlib.PurePosixPath(item.filename)
            require(not p.is_absolute() and ".." not in p.parts and not stat.S_ISLNK(item.external_attr>>16),"SAFE_PACKAGE_PATH_REQUIRED")
        candidates=[n for n in names if n.endswith("package-record.json")]
        require(len(candidates)==1,"EXACT_PACKAGE_RECORD_REQUIRED")
        prefix=candidates[0][:-len("package-record.json")]
        def metadata(name):
            info=z.getinfo(prefix+name)
            require(info.file_size<=4*1024*1024,"BOUNDED_PACKAGE_METADATA_REQUIRED")
            return z.read(info)
        record=json.loads(metadata("package-record.json"))
        require(record["module"]==module and record["sourceCommit"]==spec["source"] and record["imageId"]==spec["image"],"EXACT_RETAINED_SOURCE_IMAGE_REQUIRED")
        require(record["signatureIssued"] is False and record["targetApplyAuthorized"] is False and record["vpsOperations"]==0,"ORIGINAL_UNSIGNED_NO_APPLY_RECORD_REQUIRED")
        hashes={}
        for row in metadata("SHA256SUMS").decode().splitlines():
            match=re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_.-]+)",row)
            require(match is not None,"EXACT_CHECKSUM_ROW_REQUIRED")
            expected,name=match.groups()
            require(name not in hashes,"DUPLICATE_CHECKSUM_ROW_DENIED")
            with z.open(prefix+name) as stream:require(digest(stream)==expected,"PACKAGE_MEMBER_BYTES_CHANGED")
            hashes[name]=expected
        required={"Dockerfile.resolved","application.jar","image.docker.tar","package-record.json","source-inventory.json","source.tar","trivy-image.json"}
        require(required<=hashes.keys(),"RETAINED_PACKAGE_CLOSURE_REQUIRED")
        members={n[len(prefix):] for n in names if n.startswith(prefix) and not n.endswith("/")}
        require(members==set(hashes)|{"SHA256SUMS"},"UNHASHED_PACKAGE_MEMBER_DENIED")
        scan=json.loads(metadata("trivy-image.json"))
        require(scan.get("Metadata",{}).get("ImageID")==spec["image"],"EXACT_SCAN_IMAGE_REQUIRED")
        require(not [v for r in scan.get("Results",[]) for v in r.get("Vulnerabilities",[]) if v.get("Severity") in {"HIGH","CRITICAL","UNKNOWN"}],"RETAINED_IMAGE_SCAN_GATE_BLOCKED")
        if module=="ingestion":
            require("native-probe.txt" in hashes and "RUNTIME_IMAGE_SQLITE_AND_XLSX=PASS" in metadata("native-probe.txt").decode(),"EXACT_NATIVE_IMAGE_PROBE_REQUIRED")
        return {"schema":"ouf.retained-package-provenance-verification.v1","module":module,
          "originalProducerRun":38069730894,"originalProducerCommit":"1ae013c11c9cd47b8619df72e3e843da2b41f8d6",
          "originalArtifactId":spec["artifactId"],"originalZipSha256":spec["zipSha256"],
          "sourceCommit":spec["source"],"imageId":spec["image"],"memberSha256":hashes,
          "originalZipBytesVerified":True,"allMemberChecksumsVerified":True,
          "purpose":"PUBLISHER_BYTE_PROVENANCE_NOT_NEW_IMAGE_BUILD_OR_INSTALLATION_AUTHORITY",
          "imageRebuilt":False,"targetApplyAuthorized":False,"notReleaseAcceptance":True}
def main():
    p=argparse.ArgumentParser();p.add_argument("--module",required=True,choices=SPECS);p.add_argument("--zip",required=True);p.add_argument("--output",required=True)
    a=p.parse_args();r=verify(pathlib.Path(a.zip),a.module)
    pathlib.Path(a.output).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n")
    print("OUF_RETAINED_PACKAGE_BYTES=PASS "+a.module)
if __name__=="__main__":main()
