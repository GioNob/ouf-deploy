#!/usr/bin/env python3
"""Stage exact signed discovery candidates on the target; no image import or container changes."""
import ast, datetime, gzip, hashlib, json, os, subprocess, sys, tarfile, tempfile
from pathlib import Path
os.umask(0o077)
GH=Path("/home/oufadmin/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh")
SPECS={
 "semantic":{"repo":"GioNob/ouf-semantic-registry","run":37995955667,"producer":"47d70fac4d69f23a24c552cd5cac4ebaf797c529","ref":"refs/heads/codex/discovery-java-runtime-security-20261009","source":"403531a9df1cbc877078f8126fd1fc4ff18acea9","image":"sha256:b1a7956a673f88b5ee65d174c2eda7b9e448153e101348c06fdd53c0640e700b","user":"10001:10001"},
 "mcp":{"repo":"GioNob/ouf-mcp-server","run":37995954188,"producer":"db45385648c7956e045d2d8f0b3f8e3f24270dac","ref":"refs/heads/codex/discovery-go-security-20261009","source":"3ba1d4abcf62af1572997a217a333fa8d231c29f","image":"sha256:33eb5195d926bbc15397a82ccd2b1a6c0ae0461f3ff86dd1bb7bbcc7fbc8e7c7","user":"10005:10005"}}
def run(args):
    p=subprocess.run(args,capture_output=True,timeout=300)
    if p.returncode: raise RuntimeError("GH_COMMAND_FAILED")
    return p.stdout
def sha(path):
    h=hashlib.sha256()
    with path.open("rb") as f:
        while b:=f.read(1048576):h.update(b)
    return h.hexdigest()
report={"schema":"ouf.discovery.signed-target-stage.v1","imageImportPerformed":False,"containerLifecycleOperations":0,"targetConfigurationWrites":0,"releaseApplied":False,"acceptanceGranted":False,"publisherTrustAccepted":False,"secretValuesPrinted":False,"roles":[]}
try:
    if not GH.is_file():raise RuntimeError("EXISTING_GH_BINARY_UNAVAILABLE")
    sys.path.insert(0,str(Path("verification-source").resolve()))
    from tools import verify_semantic_image_archive as archive
    node=next(n for n in ast.parse(Path("scripts/scan-discovery-candidate.py").read_text()).body if isinstance(n,ast.FunctionDef) and n.name=="verify_general_image")
    scope=dict(archive=archive,gzip=gzip,hashlib=hashlib,tarfile=tarfile)
    exec(compile(ast.Module(body=[node],type_ignores=[]),"archive-verifier","exec"),scope)
    if datetime.datetime.now(datetime.timezone.utc)>=datetime.datetime(2026,10,11,6,32,32,tzinfo=datetime.timezone.utc):raise RuntimeError("FRESH_DATABASE_WINDOW_EXPIRED")
    root=Path(tempfile.mkdtemp(prefix="ouf-discovery-remediation-stage-",dir=Path.home()))
    report["stageDirectory"]=str(root)
    for role,spec in SPECS.items():
        folder=root/role
        folder.mkdir(mode=0o700)
        run([str(GH),"run","download",str(spec["run"]),"--repo",spec["repo"],"--name","signed-"+role+"-discovery-candidate-"+str(spec["run"]),"--dir",str(folder)])
        files=(role+".image.tar.gz","inventory.json",role+".syft.json",role+".grype.json","build-image.json")
        for name in files:
            file=folder/name
            if not file.is_file() or file.is_symlink():raise RuntimeError("SIGNED_SUBJECT_MISSING")
            verified=run([str(GH),"attestation","verify",str(file),"--repo",spec["repo"],"--signer-workflow",spec["repo"]+"/.github/workflows/signed-discovery-candidate.yml","--source-digest",spec["producer"],"--source-ref",spec["ref"],"--deny-self-hosted-runners","--bundle",str(folder/"provenance.json"),"--format","json"])
            (folder/(name+".target-verification.json")).write_bytes(verified)
        inv=json.loads((folder/"inventory.json").read_bytes())
        image=json.loads((folder/"build-image.json").read_bytes())[0]
        if inv["sourceCommit"]!=spec["source"] or inv["imageId"]!=spec["image"] or image["Id"]!=spec["image"] or image["Config"]["User"]!=spec["user"]:raise RuntimeError("SIGNED_SOURCE_OR_IMAGE_BINDING_MISMATCH")
        if not inv["archiveByteVerified"] or not inv["thresholdMet"] or any(inv["severityCounts"][k] for k in ("Critical","High","Unknown")):raise RuntimeError("SIGNED_SCAN_THRESHOLD_BLOCKED")
        scan=json.loads((folder/(role+".grype.json")).read_bytes())
        counts={k:0 for k in ("Critical","High","Medium","Low","Negligible","Unknown")}
        for match in scan["matches"]:counts[match["vulnerability"]["severity"]]+=1
        if counts!=inv["severityCounts"] or scan.get("alertsByPackage") or scan.get("ignoredMatches"):raise RuntimeError("SIGNED_SCAN_REPORT_DRIFT")
        outer=folder/(role+".image.tar")
        size=0
        with gzip.open(folder/(role+".image.tar.gz"),"rb") as f,outer.open("xb") as out:
            while b:=f.read(1048576):
                size+=len(b)
                if size>4294967296:raise RuntimeError("IMAGE_ARCHIVE_UNBOUNDED")
                out.write(b)
        binding=scope["verify_general_image"](outer,spec["image"])
        outer.unlink()
        sbom=json.loads((folder/(role+".syft.json")).read_bytes())
        if sbom["source"]["metadata"]["imageID"]!="sha256:"+binding["configByteSha256"]:raise RuntimeError("SIGNED_SBOM_IMAGE_BINDING_MISMATCH")
        report["roles"].append({"role":role,"producerRun":spec["run"],"producerCommit":spec["producer"],"sourceCommit":spec["source"],"imageId":spec["image"],"archiveSha256":sha(folder/(role+".image.tar.gz")),"targetCryptoVerified":True,"targetArchiveBytesVerified":True,"severityCounts":counts})
    report["status"]="STAGED_CRYPTO_AND_BYTES_VERIFIED"
except (OSError,RuntimeError,ValueError,KeyError,subprocess.TimeoutExpired,AssertionError,tarfile.TarError) as exc:
    report["status"]="BLOCKED"
    report["reason"]=str(exc) if isinstance(exc,RuntimeError) else type(exc).__name__
if "stageDirectory" in report:
    (Path(report["stageDirectory"])/"stage-report.json").write_text(json.dumps(report,indent=2)+"\n")
print("OUF_DISCOVERY_SIGNED_TARGET_STAGE="+json.dumps(report,sort_keys=True))
if report["status"]=="BLOCKED":raise SystemExit(1)
