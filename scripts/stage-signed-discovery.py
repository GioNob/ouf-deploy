#!/usr/bin/env python3
"""Stage exact signed discovery candidates on the target; no image import or container changes."""
import ast, gzip, hashlib, json, os, subprocess, sys, tarfile, tempfile
from pathlib import Path
os.umask(0o077)
GH=Path("/home/oufadmin/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh")
SPECS={
 "semantic":{"repo":"GioNob/ouf-semantic-registry","run":37665730385,"producer":"91381f96be0a3fbd75dcdc44c22aeb90c9f12b8a","ref":"refs/heads/codex/semantic-discovery-oss-runtime","source":"67cb426995d7b0723e34bfe54e52ea89ae02b81d","image":"sha256:e9730d879f171530d56843670d7d5139dd7ef2f4ee59c812a1361224392a73b3","user":"10001:10001"},
 "mcp":{"repo":"GioNob/ouf-mcp-server","run":37665728762,"producer":"32bc369b0ab98629db82620c4ae14525ae412650","ref":"refs/heads/codex/semantic-discovery-mcp-tools","source":"3d51524eeddb539d6f78961447e64d9d640141c4","image":"sha256:a0bfc5a3c4eb8710d64b7621224a373d3cfe6db03bc79fc6adbf071c3a220e47","user":"10005:10005"}}
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
    root=Path(tempfile.mkdtemp(prefix="ouf-discovery-signed-stage-",dir=Path.home()))
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
        if counts!=inv["severityCounts"] or scan.get("alertsByPackage"):raise RuntimeError("SIGNED_SCAN_REPORT_DRIFT")
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
