"""Hosted original publisher/archive/layer/native Engine proof; never target apply."""
import hashlib,importlib.util,json,os,pathlib,shutil,subprocess,tempfile,zipfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
custody=module("image_custody","tools/semantic_application_cutover/image_custody.py")
verify=module("package_bytes","scripts/verify-durable-v11-package.py")
spec=verify.SPECS["semantic"]
def command(args,timeout=120):
    p=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
    if p.returncode or len(p.stdout)>2097152:raise ValueError("HOSTED_CUSTODY_NATIVE_OPERATION_BLOCKED")
    return p.stdout
with tempfile.TemporaryDirectory() as folder:
    root=pathlib.Path(folder);root.chmod(0o700)
    verified=verify.verify(ROOT/"semantic.zip","semantic")
    with zipfile.ZipFile(ROOT/"semantic.zip") as z:
        for name in ("image.docker.tar","source.tar","source-inventory.json","application.jar","package-record.json","migration-continuity.json","trivy-image.json","Dockerfile.resolved","provenance.json"):
            rows=[i for i in z.infolist() if pathlib.PurePosixPath(i.filename).name==name]
            assert len(rows)==1
            with z.open(rows[0]) as src,(root/name).open("xb") as dst:shutil.copyfileobj(src,dst,1048576)
    for name in ("image.docker.tar","source.tar","source-inventory.json","application.jar","package-record.json","migration-continuity.json","trivy-image.json","Dockerfile.resolved"):
        command(["gh","attestation","verify",str(root/name),"--repo","GioNob/ouf-semantic-registry",
          "--signer-workflow","GioNob/ouf-semantic-registry/.github/workflows/discovery-durable-candidate.yml",
          "--source-digest","3ec99277b8383e496913b9fd3bb05c877825abf5",
          "--source-ref","refs/heads/codex/discovery-durable-resilience-20261011",
          "--deny-self-hosted-runners","--bundle",str(root/"provenance.json"),"--format","json"])
    expected=verified["memberSha256"]["image.docker.tar"]
    with (root/"image.docker.tar").open("rb") as stream:audit=custody.archive(stream,expected,spec["image"],spec["source"])
    # Exactly one fixture import after original-byte/signature/layer checks.
    # No running container, database, provider or target operation.
    command(["docker","image","load","--input",str(root/"image.docker.tar")])
    native=json.loads(command(["docker","image","inspect",spec["image"]]))[0]
    receipt=custody.loaded(audit,native)
    receipt.update(status="ORIGINAL_SIGNED_V11_ARCHIVE_LAYERS_AND_HOSTED_ENGINE_MATCH",
       originalZipSha256=spec["zipSha256"],signedSubjectsVerified=8,
       hostedImageImports=1,targetImageImports=0,targetEffects=False,
       archiveLayersActuallyHashed=True,engineActuallyInspected=True,
       rootfsLayerCount=len(audit["layers"]),repositoryTagCount=len(audit["repositoryTags"]),
       sourcePublisherCommit="3ec99277b8383e496913b9fd3bb05c877825abf5",notReleaseAcceptance=True)
    (ROOT/"durable-v11-image-custody-receipt.json").write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n")
    print("OUF_DURABLE_V11_IMAGE_CUSTODY="+json.dumps(receipt,sort_keys=True))
