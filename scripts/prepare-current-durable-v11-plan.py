"""Prepare a new source-bound private V11 declaration and creation plan only.

Reuses current R12 sealed native readers. No import, DB, lifecycle, lease,
firewall, signature, transition claim or budget renewal/reset is performed.
"""
import hashlib,json,os,re,sys,tempfile,types
from pathlib import Path
SOURCE_HASHES={
 "reader":"4d4da44d8ef27f77e00982d978ad8400eb7a0b79997bd468535fc49654b2ac3f",
 "planner":"38bb934fedfcdd38d11fc29ff4d60e75170854686273b7592edcae92fa0d1d28",
 "prepare":"693ec0196a60d3a9f6adee96571947306df4a0cffb449905c3dcf8c09a34da1b",
 "custody":"cb9ff64684243d563da79d327eb7d7e325dbea6a3922c91a0b7791a3ceec9baf",
 "creation":"e018567bbd67504ec00d5cbd830c65adbb2670dd7a627b63b9ae20ffa420d665",
 "package":"c147db8ce3a9a4facf8c4e7aa1f2e4cb292445f23c8e77e97e820014ee82feb0",
 "rebind":"7959736a932211e18215a39a11204435b1b10f512e1420f9a445d936339ffdef",
}
PACKAGE=Path("/home/oufadmin/ouf-durable-v11-stage.drTnFl4m/semantic.zip")

def require(ok, reason):
    if not ok:raise ValueError(reason)

def modules(sources):
    require(type(sources) is dict and set(sources)==set(SOURCE_HASHES),"EXACT_V11_PLAN_SOURCE_CLOSURE_REQUIRED")
    for name,expected in SOURCE_HASHES.items():
        raw=sources[name]
        require(type(raw) is bytes and len(raw)<=131072 and hashlib.sha256(raw).hexdigest()==expected,
                "V11_PLAN_SOURCE_HASH_MISMATCH")
    loaded={}
    for name in ("reader","package","rebind"):
        m=types.ModuleType("sealed_v11_"+name)
        exec(compile(sources[name],"sealed-v11-"+name,"exec"),m.__dict__)
        loaded[name]=m
    planner,prepare,custody,creation=loaded["reader"].modules({k:sources[k] for k in ("planner","prepare","custody","creation")})
    loaded.update(planner=planner,prepare=prepare,custody=custody,creation=creation)
    return loaded

def main():
    os.umask(0o077)
    report={"schema":"ouf.durable-v11-current-private-plan.v1","containerLifecycleOperations":0,"imageImports":0,
            "databaseQueries":0,"databaseWrites":0,"firewallWrites":0,"commonLockAcquired":False,
            "providerCalls":0,"dnsQueries":0,"signaturesIssued":0,"newClaimCreated":False,"budgetReset":False,
            "r12Touched":False,"privateValuesPrinted":False,"productionApplyReady":False,
            "newCandidateImageCustodyProven":False,"newTransportClosureProven":False,"notReleaseAcceptance":True,
            "protectedFileWrites":0}
    phase="VERIFY_COMPLETE_SEALED_SOURCE_CLOSURE"
    try:
        require(os.geteuid()==0 and sys.flags.isolated and sys.dont_write_bytecode and len(sys.argv)==1,
                "ISOLATED_ROOT_V11_PLAN_ENTRY_REQUIRED")
        m=modules(globals().get("__v11_plan_sources__"))
        reader,planner,prepare,custody,creation,package,rebind=(m[k] for k in ("reader","planner","prepare","custody","creation","package","rebind"))
        phase="CURRENT_R12_AND_INPUT_READ"
        before=reader.observe(planner,prepare,custody,creation)
        raw=custody.file_bytes(planner.DECLARATION,0,{0o600},expected=planner.DECLARATION_HASH)
        declaration=json.loads(raw)
        phase="VERIFY_EXACT_ORIGINAL_ZIP_AND_IMAGE_CONFIG"
        # This sealed historical metadata reader supports explicit ZIP/image
        # inputs. Its SOURCE label binding is set only to the sealed new source.
        package.SOURCE=rebind.SOURCE
        config=package.package_config(PACKAGE,expected_zip=rebind.ZIP_HASH,expected_image=rebind.IMAGE)
        proposed=rebind.rebind(declaration,planner.DECLARATION_HASH,config)
        require(creation.digest(proposed)==rebind.digest(proposed),"CANONICAL_DECLARATION_HASH_CONTRACT_DRIFT")
        phase="COMPILE_CURRENT_PRIVATE_V11_CREATION_REQUEST"
        native_raw=custody.file_bytes(prepare.R10/"reader.py",0,{0o600},expected=prepare.PROGRAMS["reader.py"])
        native=types.ModuleType("sealed_v11_native_reader")
        native.__file__=str(prepare.R10/"reader.py")
        exec(compile(native_raw,"sealed-v11-native-reader","exec"),native.__dict__)
        human=native.parse(native.private(native.CONTEXT/"human-approval-binding.json"))
        cfg=native.parse(native.private(native.CONTEXT/"execution-configuration.json",human["configurationHash"]))
        args=["inspect","--type","container",native.SEMANTIC_ID]
        current=native.parse(prepare.native(native,cfg["commandBindings"]["docker"],args,True))[0]
        require(creation.digest(prepare.frame(current))==before["currentSemanticFrameHash"],"CURRENT_V11_PLAN_FRAME_DRIFT")
        planner.verify_secret_custody(custody,declaration,current)
        new_hash=creation.digest(proposed)
        request,public=creation.compile_creation(proposed,new_hash,planner.current_host(creation,current))
        phase="FINAL_STABLE_RECHECK"
        after=reader.observe(planner,prepare,custody,creation)
        require(all(after[k]==before[k] for k in ("workerGenerationHash","authorizationHash","currentSemanticFrameHash","declarationHash"))
                and after["refreshCount"]>=before["refreshCount"],"CURRENT_GENERATION_CHANGED_DURING_V11_PLAN")
        require(custody.file_bytes(planner.DECLARATION,0,{0o600},expected=planner.DECLARATION_HASH)==raw,
                "PREDECESSOR_DECLARATION_CHANGED_DURING_V11_PLAN")
        require(package.package_config(PACKAGE,expected_zip=rebind.ZIP_HASH,expected_image=rebind.IMAGE)==config,
                "V11_PACKAGE_CHANGED_DURING_PLAN")
        final=native.parse(prepare.native(native,cfg["commandBindings"]["docker"],args,True))[0]
        require(creation.digest(prepare.frame(final))==after["currentSemanticFrameHash"],"FINAL_V11_PLAN_FRAME_DRIFT")
        planner.verify_secret_custody(custody,declaration,final)
        require(creation.compile_creation(proposed,new_hash,planner.current_host(creation,final))[0]==request,
                "FINAL_V11_CREATION_INTENT_DRIFT")
        phase="NEW_PRIVATE_DRAFT_PUBLICATION_NO_APPLY"
        directory=Path(tempfile.mkdtemp(prefix="semantic-durable-v11-plan-",dir=prepare.BASE));directory.chmod(0o700)
        # These are new private review artifacts only. Existing snapshots/inputs
        # are untouched; no executable authorization is manufactured.
        for name,value in (("private-runtime-declaration.json",proposed),("creation-request.private.json",request),
                           ("observation.private.json",{"custodyBefore":before,"custodyAfter":after})):
            custody.create(directory/name,creation.encoded(value));report["protectedFileWrites"]+=1
        report.update(status="CURRENT_V11_DECLARATION_AND_PLAN_PREPARED_NOT_APPLY_READY",
                      evidenceDirectory=str(directory),privateDeclarationHash=new_hash,
                      creationRequestHash=creation.digest(request),creationPlanHash=creation.digest(public),
                      sourceCommit=rebind.SOURCE,candidateImageId=rebind.IMAGE,zipSha256=rebind.ZIP_HASH,
                      predecessorDeclarationHash=planner.DECLARATION_HASH,existingInputFilesReverified=4,
                      workerPid=after["workerPid"],refreshCount=after["refreshCount"],flows=after["flows"],
                      executionDefaultsPreserved=True,retainedHostAndInputsPreserved=True,
                      completeRealizedOciProven=False,applicationCutoverAuthorized=False,
                      privateSnapshotPublicationIsAtomic=False)
        # Increment before serializing so receipt and stdout counts agree.
        report["protectedFileWrites"]+=1
        custody.create(directory/"receipt.json",creation.encoded(report))
        code=0
    except Exception as error:
        reason=str(error)
        report.update(status="CURRENT_V11_PLAN_BLOCKED",phase=phase,
                      reason=reason if re.fullmatch("[A-Z][A-Z0-9_]{0,120}",reason) else "CURRENT_V11_PLAN_UNPROVEN")
        code=1
    print("OUF_CURRENT_V11_PLAN="+json.dumps(report,sort_keys=True))
    return code

if __name__=="__main__":raise SystemExit(main())
