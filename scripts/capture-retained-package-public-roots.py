#!/usr/bin/env python3
"""Capture fresh candidate public-root bytes from a retained image; no import/merge."""
import argparse,hashlib,importlib.util,json,os,pathlib,shutil,tempfile,zipfile
def main():
    p=argparse.ArgumentParser();p.add_argument("--zip",required=True);p.add_argument("--continuity",required=True);p.add_argument("--output",required=True)
    a=p.parse_args();os.umask(0o077)
    evidence=json.loads(pathlib.Path(a.continuity).read_text())
    if evidence.get("module")!="semantic" or evidence.get("originalZipSha256")!="a0c30bbb7d44d3e6405bae28ad80b6c5dcfc28ed2f078d387cf4e26d179e28c3" or evidence.get("imageId")!="sha256:e826bd9769a72e930e356f72c1c244007f9a34d065db94ca8113b064d10d8b85":
        raise ValueError("EXACT_RETAINED_SEMANTIC_PACKAGE_REQUIRED")
    with pathlib.Path(a.zip).open("rb") as f:
        if hashlib.file_digest(f,"sha256").hexdigest()!=evidence["originalZipSha256"]:raise ValueError("EXACT_ORIGINAL_ZIP_BYTES_REQUIRED")
    source=pathlib.Path(__file__).resolve().parents[1]/"tools/file_loop_package/candidate_public_roots.py"
    spec=importlib.util.spec_from_file_location("candidate_public_roots",source);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    output=pathlib.Path(a.output);output.mkdir(mode=0o700,parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory() as temp,zipfile.ZipFile(a.zip) as archive:
        paths=[n for n in archive.namelist() if n.endswith("/image.docker.tar") or n=="image.docker.tar"]
        if len(paths)!=1:raise ValueError("EXACT_SINGLE_IMAGE_ARCHIVE_REQUIRED")
        image=pathlib.Path(temp)/"image.docker.tar"
        with archive.open(paths[0]) as src,image.open("xb") as dest:shutil.copyfileobj(src,dest)
        raw,receipt=module.roots(image,evidence["memberSha256"]["image.docker.tar"],evidence["imageId"])
    (output/"candidate-cacerts").write_bytes(raw)
    receipt.update(schema="ouf.file-loop.candidate-public-root-capture.v1",status="CANDIDATE_PUBLIC_ROOT_BYTES_CAPTURED_NOT_MERGED",
        sourceCommit=evidence["sourceCommit"],originalProducerRun=evidence["originalProducerRun"],
        originalZipSha256=evidence["originalZipSha256"],imageArchiveSha256=evidence["memberSha256"]["image.docker.tar"],
        truststoreTypeAndEntriesVerified=False,trustMerged=False,mounted=False,
        previousCandidateTrustReused=False,imageImports=0,containerLifecycleOperations=0,
        applicationCutoverAuthorized=False,privateKeyFilesOpened=0,installationAuthorityAccepted=False,notReleaseAcceptance=True)
    (output/"public-roots.json").write_text(json.dumps(receipt,indent=2,sort_keys=True)+chr(10))
    print("OUF_CANDIDATE_PUBLIC_ROOT_CAPTURE="+json.dumps(receipt,sort_keys=True))
if __name__=="__main__":main()
