"""CI gate over the exact retained artifact ZIPs; synthetic captured input only."""
import copy,importlib.util,json,os,sys,tempfile
from pathlib import Path
source=Path(__file__).resolve().parents[1]/'scripts/stage-acquisition-read-packages-20261025.py'
spec=importlib.util.spec_from_file_location('qualified_stage',source);stage=importlib.util.module_from_spec(spec);spec.loader.exec_module(stage)
assert stage.CASE==json.loads((source.parents[1]/'releases/acquisition-read-package-case-20261025.json').read_text())
base=Path(tempfile.mkdtemp(prefix='actual-ci-artifacts-',dir=os.environ['OUF_CAPTURE_TEST_PARENT']));os.chmod(base,0o700)
case=copy.deepcopy(stage.CASE);inputs=base/'fixture-inputs.json'
inputs.write_bytes(stage.encode({'schema':'ouf.acquisition-read-current-private-inputs.v1','authenticationDeclarations':{'mcp':{'clientCredentialsDeclared':True}}}));os.chmod(inputs,0o400)
case.update(inputsPath=str(inputs),inputsHash=stage.sha(inputs.read_bytes()))
result=stage.stage(Path(sys.argv[1]),case,base/'scope')
assert result['complete']and not result['targetApplyAuthorized']and not result['currentRuntimeRevalidated']
assert result['imageImports']==result['engineGetAttempts']==result['oauthRequests']==result['sqlSessions']==0
assert set(result['artifacts'])=={'ingestion','udp','mcp','gateway'}
evidence={'schema':'ouf.acquisition-read-package-artifact-ci.v1','qualified':True,'exactProductionArtifactDescriptors':True,'syntheticCapturedInputs':True,'productionCaseHash':stage.sha(stage.encode(stage.CASE)),'artifactIds':{r:d['artifactId']for r,d in stage.CASE['artifacts'].items()},'targetEvidence':False,'runtimeAuthorityIssued':False,'releaseAcceptance':False,'rootProtectedStagingFunctionCompleted':True,'archiveImagesImported':False,'rootLauncherExecuted':False}
print(json.dumps(evidence,sort_keys=True))
