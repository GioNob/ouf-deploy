#!/usr/bin/env python3
"""Hosted-only retained-byte verification and fresh scan projection; no deployment."""
import hashlib, importlib.util, json, pathlib, shutil, subprocess, sys, zipfile
def module(name, path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
retained=module("retained","scripts/verify-retained-file-loop-package.py")
publisher=module("publisher","tools/file_loop_package/verify_target_publisher.py")
role=sys.argv[2]
spec=retained.SPECS[role]
root=pathlib.Path("fresh-evidence");root.mkdir(exist_ok=True)
if sys.argv[1]=="verify":
    result=retained.verify(pathlib.Path("candidate.zip"),role)
    with zipfile.ZipFile("publisher.zip") as z:
        allowed={"continuity.json","continuity.json.sigstore.json",role+".zip.sigstore.json"}
        for name in allowed:
            matches=[i for i in z.infolist() if pathlib.PurePosixPath(i.filename).name==name]
            retained.require(len(matches)==1 and 0<matches[0].file_size<=4194304,"BOUNDED_UNIQUE_PUBLISHER_PROOF_REQUIRED")
            (root/name).write_bytes(z.read(matches[0]))
    binary=pathlib.Path(shutil.which("cosign"))
    for subject,bundle in [(pathlib.Path("candidate.zip"),root/(role+".zip.sigstore.json")),(root/"continuity.json",root/"continuity.json.sigstore.json")]:
        publisher.verify(binary,subject,bundle,"file-loop-package-provenance.yml",publisher.PUBLISHER_SHA,"codex/file-loop-package-provenance-20261010")
    retained.require(json.loads((root/"continuity.json").read_bytes())==result,"SIGNED_CONTINUITY_AND_FRESH_BYTES_MUST_MATCH")
    with zipfile.ZipFile("candidate.zip") as z:
        members=[i for i in z.infolist() if pathlib.PurePosixPath(i.filename).name=="image.docker.tar"]
        retained.require(len(members)==1 and 0<members[0].file_size<=2147483648,"ONE_BOUNDED_IMAGE_ARCHIVE_REQUIRED")
        with z.open(members[0]) as src,open("image.docker.tar","xb") as dst:
            shutil.copyfileobj(src,dst,1048576)
    result.update({"publisherCryptoFreshlyVerified":True,"verificationOnly":True})
    (root/"verified-bytes.json").write_text(json.dumps(result,indent=2)+"\n")
    print("OUF_FRESH_RETAINED_PUBLISHER_CRYPTO=PASS "+role)
elif sys.argv[1]=="scan":
    scan=json.loads((root/"trivy.json").read_bytes())
    retained.require(scan.get("Metadata",{}).get("ImageID")==spec["image"],"FRESH_SCAN_EXACT_IMAGE_REQUIRED")
    results=scan.get("Results")
    retained.require(isinstance(results,list) and bool(results),"NONEMPTY_SCANNER_COVERAGE_REQUIRED")
    counts={s:0 for s in ("CRITICAL","HIGH","MEDIUM","LOW","UNKNOWN")}
    for item in results:
        for v in item.get("Vulnerabilities",[]):
            severity=v.get("Severity","UNKNOWN");counts[severity if severity in counts else "UNKNOWN"]+=1
    passed=not any(counts[s] for s in ("CRITICAL","HIGH","UNKNOWN"))
    result={"schema":"ouf.fresh-retained-package-security.v1","module":role,"imageId":spec["image"],"zipSha256":spec["zipSha256"],"severityCounts":counts,"freshScannerCoverage":[{"type":x.get("Type"),"class":x.get("Class")} for x in results],"thresholdMet":passed,"unfixedIncluded":True,"scanSha256":hashlib.sha256((root/"trivy.json").read_bytes()).hexdigest(),"targetActions":0,"targetApplyAuthorized":False,"notReleaseAcceptance":True}
    (root/"security.json").write_text(json.dumps(result,indent=2)+"\n")
    print("OUF_FRESH_PACKAGE_SECURITY="+json.dumps(result,sort_keys=True))
    retained.require(passed,"CURRENT_RETAINED_PACKAGE_SECURITY_BLOCKED")
else:raise ValueError("UNKNOWN_PHASE")
