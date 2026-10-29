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
import image_manifest_identity
import rebase_native_manifest
import transition_journal
import test_semantic_creation_plan as creation_fixture
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
    original_audit=audit
    output=tempfile.TemporaryFile()
    with (root/"image.docker.tar").open("rb") as source:
        envelope=custody.tagless_archive(source,output,original_audit)
        audit=custody.archive(output,envelope["derivedArchiveSha256"],spec["image"],spec["source"])
    expected_descriptor=image_manifest_identity.descriptor(output,audit)
    print('OUF_V11_AUTHENTICATED_MANIFEST='+json.dumps(expected_descriptor,sort_keys=True),flush=True)
    assert expected_descriptor=={'mediaType':'application/vnd.docker.distribution.manifest.v2+json',
        'digest':'sha256:bd48ab35db0441b1f4f48422e7190adaff176a61cddde5f981d93e496ad4b24a','size':1845}
    assert audit["repositoryTags"]==[] and audit["layers"]==original_audit["layers"]
    # Exactly one fixture import after original-byte/signature/layer checks.
    # No running container, database, provider or target operation.
    socket=pathlib.Path(os.environ.get("OUF_CUSTODY_SOCKET","/var/run/docker.sock"));s=socket.stat()
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
                output.seek(0)
                with tempfile.TemporaryDirectory(dir=directory,prefix='empty-docker-cli-') as empty:
                    p=subprocess.run(['docker','--config',empty,'image','load'],stdin=output,
                      stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120,
                      env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','DOCKER_HOST':'unix://'+str(socket)})
                    assert p.returncode==0 and len(p.stdout)<=2097152
                    print('OUF_HOSTED_EXACT_STDIN_LOAD='+json.dumps({'exit':p.returncode,'stdoutHash':hashlib.sha256(p.stdout).hexdigest(),
                        'expectedImageInOutput':spec['image'].encode() in p.stdout,'fdOffsetAfterLoad':os.lseek(output.fileno(),0,os.SEEK_CUR)}),flush=True)
                os._exit(71)
            session.import_once(audit,load_then_crash,inspect,checkpoint)
        os._exit(72)
    _,status=os.waitpid(pid,0);assert os.waitstatus_to_exitcode(status)==71
    assert journal.read()["state"]=="IN_FLIGHT"
    restarted=Import(journal_module.Journal(directory),initial["contextHash"])
    with restarted.invocation():
        if os.environ.get('OUF_CUSTODY_MANIFEST_STORE')=='true':
            def inspect_manifest(image):
                status,value=engine.request('GET','/v1.48/images/'+image+'/json?manifests=true')
                assert status in (200,404)
                return value if status==200 else None
            receipt=image_manifest_identity.reconcile_existing(restarted,audit,expected_descriptor,inspect_manifest,checkpoint)
        else:receipt=restarted.reconcile(audit,inspect,checkpoint)
    assert os.environ.get('OUF_CUSTODY_MANIFEST_STORE')=='true'
    actual=inspect_manifest(expected_descriptor['digest'])
    fresh_proof=rebase_native_manifest.native_proof(actual)
    assert fresh_proof==receipt
    original_plan,fixture_host=creation_fixture.CreationPlan().fixture()
    original_plan['candidateImageId']=spec['image']
    original_plan['qualifiedPackageBinding']={'sourceCommit':spec['source'],'zipSha256':spec['zipSha256'],'imageId':spec['image']}
    original_request=creation_fixture.m.compile_creation(original_plan,creation_fixture.m.digest(original_plan),fixture_host)[0]
    native_plan,native_request=rebase_native_manifest.rebase(original_plan,original_request,journal.read(),fresh_proof,
        initial['contextHash'],rebase_native_manifest.digest(original_plan),rebase_native_manifest.digest(original_request))
    assert creation_fixture.m.compile_creation(native_plan,rebase_native_manifest.digest(native_plan),fixture_host)[0]==native_request
    assert {k:v for k,v in native_request.items() if k!='Image'}=={k:v for k,v in original_request.items() if k!='Image'}
    assert native_request['Image']==expected_descriptor['digest']
    # New integration boundary: create the ORIGINAL signed image by its native
    # manifest ID, die after the effect, reopen and reconcile without create.
    # The image's JVM is never started. Prior phase receipts are fixture-only.
    creation_request={'Image':expected_descriptor['digest'],'User':'10001:10001',
        'HostConfig':{'NetworkMode':'none','ReadonlyRootfs':True,'CapDrop':['ALL'],
            'SecurityOpt':['no-new-privileges'],'RestartPolicy':{'Name':'no','MaximumRetryCount':0},
            'Memory':2147483648,'MemorySwap':2147483648,'NanoCpus':2000000000,'PidsLimit':512}}
    creation_dir=root/'creation-journal';creation_dir.mkdir(mode=0o700)
    creation_journal=journal_module.Journal(creation_dir)
    initial_creation=transition_journal.Transition.initial(fixture_authority,engine_module.digest(creation_request),'c'*64,'d'*64)
    creation_journal.initialize(initial_creation)
    transition=transition_journal.Transition(creation_journal,initial_creation['contextHash'])
    with transition.invocation():
        for phase in transition_journal.PHASES[:4]:
            row=transition.begin(phase,fixture_authority,fixture_authority,transition.read()['version'])
            transition.reconcile(phase,fixture_authority,'APPLIED',engine_module.digest({'syntheticFixturePhase':phase}),row['version'])
    try:
        pid=os.fork()
        if pid==0:
            try:
                with transition.invocation():
                    engine.create_once(transition,creation_request,fixture_authority,lambda phase:None)
                    os._exit(71)
            except Exception as error:
                print('OUF_NATIVE_V11_CREATION_DENIED='+json.dumps({'errorType':type(error).__name__,
                    'reason':str(error) if str(error).isupper() else 'NATIVE_CREATION_UNPROVEN'}),flush=True)
                os._exit(72)
        _,status=os.waitpid(pid,0)
        observed=engine.inspect(transition)
        print('OUF_NATIVE_V11_CREATED_IDENTITY='+json.dumps({'requestImageId':creation_request['Image'],
            'observedImageId':observed.get('Image') if observed else None,'childExit':os.waitstatus_to_exitcode(status)}),flush=True)
        assert os.waitstatus_to_exitcode(status)==71
        assert creation_journal.read()['state']=='IN_FLIGHT'
        reopened=transition_journal.Transition(journal_module.Journal(creation_dir),initial_creation['contextHash'])
        with reopened.invocation():
            # A new authority hash cannot replay a consumed creation.
            try:reopened.begin('CREATE_REPLACEMENT',engine_module.digest(creation_request),'e'*64,reopened.read()['version'])
            except ValueError:pass
            else:raise AssertionError('NATIVE_MANIFEST_CREATION_REPLAY_ALLOWED')
            reconciled=engine.reconcile(reopened,creation_request,lambda phase:None)
        assert reconciled['nextPhase']==5 and reconciled['state']=='READY'
        assert engine.inspect(reopened)['Id']==observed['Id']
        assert not observed['State']['Running'] and observed['State']['Pid']==0
        receipt.update(actualOriginalImageContainerCreatedByManifest=True,
            actualProcessDeathAfterContainerCreation=True,creationJournalReopened=True,
            exactStoppedCreationReconciledWithoutDuplicate=True,originalSignedJvmNeverStarted=True,
            precedingCutoverPhasesSyntheticFixtureOnly=True,targetTransitionAuthorityIssued=False)
    finally:
        observed=engine.inspect(transition)
        if observed is not None:engine.request('DELETE','/v1.44/containers/'+observed['Id'])
    receipt.update(nativePlanCompiledUsingActualEngineProof=True,onlyCreationImageIdentityChanged=True,
                   privateRootPlanIsFixture=True,targetPrivatePlanPrepared=False)
    from native_v11_cutover_executor import qualify
    qualify(engine,journal_module,root,expected_descriptor['digest'],receipt)
    assert journal.read()["state"]=="VERIFIED" and journal.read()["effectAttemptCount"]==1
    receipt.update(originalArchiveSha256=expected,derivedArchiveSha256=envelope["derivedArchiveSha256"],
                   imageRebuilt=False,newSignatureIssued=False,actualProcessDeathAfterImport=True,durableJournalReopened=True,
                   importEffectAttemptCount=1,reconciliationWithoutSecondImport=True,
                   runtimeAuthorityFixtureOnly=True,actualContainerdStore=os.environ.get('OUF_CUSTODY_MANIFEST_STORE')=='true')
    receipt.update(status="ORIGINAL_SIGNED_V11_LAYERS_TAGLESS_ENVELOPE_AND_HOSTED_ENGINE_MATCH",
       originalZipSha256=spec["zipSha256"],signedSubjectsVerified=8,
       hostedImageImports=1,targetImageImports=0,targetEffects=False,
       archiveLayersActuallyHashed=True,engineActuallyInspected=True,
       rootfsLayerCount=len(audit["layers"]),repositoryTagCount=len(audit["repositoryTags"]),
       sourcePublisherCommit="3ec99277b8383e496913b9fd3bb05c877825abf5",notReleaseAcceptance=True)
    (ROOT/"native-v11-plan-qualification-receipt.json").write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n")
    print("OUF_NATIVE_V11_PLAN_QUALIFICATION="+json.dumps(receipt,sort_keys=True))
