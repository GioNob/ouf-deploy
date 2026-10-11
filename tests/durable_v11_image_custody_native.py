"""Hosted original publisher/archive/layer/native Engine proof; never target apply."""
import hashlib,importlib.util,json,os,pathlib,shutil,stat,subprocess,sys,tempfile,zipfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
custody=module("image_custody","tools/semantic_application_cutover/image_custody.py")
verify=module("package_bytes","scripts/verify-durable-v11-package.py")
spec=verify.SPECS["semantic"]
sys.path.insert(0,str(ROOT/"tools/semantic_application_cutover"))
from image_import import Import
journal_module=module("image_import_journal","tools/semantic_lease_recovery/recovery_journal.py")
engine_module=module("image_import_engine","tools/semantic_application_cutover/engine_creation.py")
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
    socket=pathlib.Path("/var/run/docker.sock");s=socket.stat()
    engine=engine_module.Engine(str(socket),(s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode)))
    def inspect(image):
        status,value=engine.request("GET","/v1.44/images/"+image+"/json")
        assert status in (200,404)
        return value if status==200 else None
    assert inspect(spec["image"]) is None
    directory=root/"journal";directory.mkdir(mode=0o700)
    journal=journal_module.Journal(directory)
    fixture_authority=custody.digest({"fixtureOnly":True,"source":spec["source"],"originalSubjectsVerified":8})
    initial=Import.initial(audit,fixture_authority);journal.initialize(initial)
    session=Import(journal,initial["contextHash"])
    def checkpoint(phase):return fixture_authority
    pid=os.fork()
    if pid==0:
        with session.invocation():
            def load_then_crash():
                command(["docker","image","load","--input",str(root/"image.docker.tar")])
                os._exit(71)
            session.import_once(audit,load_then_crash,inspect,checkpoint)
        os._exit(72)
    _,status=os.waitpid(pid,0);assert os.waitstatus_to_exitcode(status)==71
    assert journal.read()["state"]=="IN_FLIGHT"
    restarted=Import(journal_module.Journal(directory),initial["contextHash"])
    with restarted.invocation():receipt=restarted.reconcile(audit,inspect,checkpoint)
    assert journal.read()["state"]=="VERIFIED" and journal.read()["effectAttemptCount"]==1
    receipt.update(actualProcessDeathAfterImport=True,durableJournalReopened=True,
                   importEffectAttemptCount=1,reconciliationWithoutSecondImport=True,
                   runtimeAuthorityFixtureOnly=True)
    receipt.update(status="ORIGINAL_SIGNED_V11_ARCHIVE_LAYERS_AND_HOSTED_ENGINE_MATCH",
       originalZipSha256=spec["zipSha256"],signedSubjectsVerified=8,
       hostedImageImports=1,targetImageImports=0,targetEffects=False,
       archiveLayersActuallyHashed=True,engineActuallyInspected=True,
       rootfsLayerCount=len(audit["layers"]),repositoryTagCount=len(audit["repositoryTags"]),
       sourcePublisherCommit="3ec99277b8383e496913b9fd3bb05c877825abf5",notReleaseAcceptance=True)
    (ROOT/"durable-v11-image-custody-receipt.json").write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n")
    print("OUF_DURABLE_V11_IMAGE_CUSTODY="+json.dumps(receipt,sort_keys=True))
