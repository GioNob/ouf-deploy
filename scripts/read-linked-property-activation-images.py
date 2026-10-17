#!/usr/bin/env python3
"""Installation-specific Docker metadata read on the existing VPS CI runner.

No exec into containers, application requests, SQL, OAuth, sudo or mutations.
Image selection is data in a versioned installation profile, never a product default.
"""
import hashlib,json,os,subprocess,sys
from pathlib import Path

def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()

def call(arguments):
    result=subprocess.run(['docker',*arguments],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,timeout=12,env={**os.environ,'DOCKER_API_VERSION':'1.44'})
    if result.returncode!=0:raise ValueError('RUNNER_DOCKER_METADATA_READ_UNAVAILABLE')
    if len(result.stdout)>2097152 or len(result.stderr)>65536:raise ValueError('METADATA_SIZE_BOUND_EXCEEDED')
    return result.stdout

def run(selection):
    rows=[]
    for module,expected in selection['expectedInstalledNativeImages'].items():
        ids=call(['ps','--no-trunc','--filter','ancestor='+expected,'--format','{{.ID}}']).decode().splitlines()
        if len(ids)!=1:raise ValueError('ONE_RUNNING_EXPECTED_APPLICATION_REQUIRED')
        before=json.loads(call(['inspect',ids[0]]))[0]
        if before['Image']!=expected or not before['State']['Running']:raise ValueError('APPLICATION_IMAGE_DRIFT')
        after=json.loads(call(['inspect',ids[0]]))[0]
        fields=['Id','Image','Config','HostConfig','Mounts','NetworkSettings']
        if any(before[k]!=after[k] for k in fields) or any(before['State'][k]!=after['State'][k] for k in ['Pid','StartedAt','Running']):
            raise ValueError('APPLICATION_CHANGED_DURING_READ')
        rows.append({'module':module,'containerId':before['Id'],'imageId':before['Image'],
            'configHash':hashlib.sha256(canonical(before['Config'])).hexdigest(),
            'running':True,'stableDuringRead':True})
    return rows

if __name__=='__main__':
    root=Path(__file__).resolve().parents[1]
    report={'schema':'ouf.linked-property-activation-image-read.v1','installationSpecific':True,
      'readOnly':True,'databaseCalls':0,'credentialFilesRead':0,'credentialValuesPrinted':False,
      'serviceMutations':0,'profilePublications':0,'oauthRequests':0,'jobsRetried':0,
      'completedTechnicalPhases':8,'functionalMilestonesProven':2}
    try:
        selection=json.loads(Path(sys.argv[1]).read_text())
        qualified=json.loads((root/'releases/linked-property-qualified-20261017.json').read_text())
        if 'sha256:'+selection['qualifiedZipSha256']!=qualified['package']['githubArtifactDigest']:
            raise ValueError('QUALIFIED_PACKAGE_BINDING_REQUIRED')
        report.update(complete=True,applications=run(selection),nativeProfilePublished=False,
          xsdCompatibleUpdateInstalled=False,scope='Installed pre-fix images only; no profile or scheduler read')
    except Exception as failure:
        report.update(complete=False,reason=str(failure) if type(failure) is ValueError else type(failure).__name__)
    print('OUF_LINKED_PROPERTY_ACTIVATION_IMAGE_READ='+json.dumps(report,sort_keys=True))
    sys.exit(0 if report['complete'] else 2)
