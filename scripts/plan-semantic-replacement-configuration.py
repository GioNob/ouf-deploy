#!/usr/bin/env python3
"""Freeze a private configuration delta; no image import, key read or lifecycle.
Not an OCI declaration, deployment command or application readiness proof.
"""
import copy, hashlib, json, os, re, subprocess, tempfile
from pathlib import Path

CID='7ae83be8c1fe9fe25774b7d748e35153652b29b2501886f89daeabb83bd1a147'
OLD_IMAGE='sha256:f6525f2512c72a600ebcbc7060d55355d86e0627487b655e7c5c6288a0be7fc6'
NEW_IMAGE='sha256:b1a7956a673f88b5ee65d174c2eda7b9e448153e101348c06fdd53c0640e700b'
SOURCE='403531a9df1cbc877078f8126fd1fc4ff18acea9'
STAGE=Path('/home/oufadmin/ouf-discovery-remediation-stage-6j7rh3xz/semantic')
CLI=None

def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(v):return hashlib.sha256(encoded(v)).hexdigest()
def require(v,reason):
    if not v:raise ValueError(reason)
def environment(entries):
    require(type(entries) is list and len(entries)<=256,'BOUNDED_ENVIRONMENT_REQUIRED')
    result={}
    for row in entries:
        require(type(row) is str and len(row)<=65536 and '=' in row,'EXACT_ENVIRONMENT_ENTRY_REQUIRED')
        key,value=row.split('=',1)
        require(re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,127}',key) and key not in result,'UNIQUE_ENVIRONMENT_KEYS_REQUIRED')
        result[key]=value
    return result

def configuration_delta(container,installed_image,candidate_image):
    require(container['Id']==CID and container['Image']==installed_image['Id']==OLD_IMAGE and candidate_image['Id']==NEW_IMAGE,'EXACT_IMAGE_AND_CONTAINER_REQUIRED')
    current,base,new=(environment(v['Config'].get('Env',[])) for v in (container,installed_image,candidate_image))
    overrides={k:v for k,v in current.items() if k not in base or base[k]!=v}
    # JAVA_VERSION labels the image build; it is not a supported application
    # setting. Keep the signed candidate's value, not old deployment metadata.
    legacy_runtime=sorted(set(overrides)&{'JAVA_VERSION'})
    for key in legacy_runtime:overrides.pop(key)
    inherited=sorted(k for k,v in current.items() if k in base and base[k]==v)
    removed=sorted(set(base)-set(current))
    unknown=sorted(k for k in overrides if not k.startswith(('OUF_','SPRING_','MANAGEMENT_')) and k not in ('PORT','JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS'))
    cfg=copy.deepcopy(candidate_image['Config'])
    merged={**new,**overrides};cfg['Env']=[k+'='+merged[k] for k in sorted(merged)]
    # Preserve explicit application argv only as a review item. The signed
    # candidate command remains selected; no unreviewed argv gets promoted.
    argv_overrides=[k for k in ('Entrypoint','Cmd','WorkingDir','User') if container['Config'].get(k)!=installed_image['Config'].get(k)]
    mounted=[m for m in container['Mounts'] if m['Destination'] in ('/run/ouf-semantic-auth','/run/secrets/semantic-read-owner.key')]
    require(len(mounted)==2 and all(m.get('RW') is False for m in mounted),'EXACT_RETAINED_READ_ONLY_AUTH_MOUNTS_REQUIRED')
    names=('OUF_SCHEMA_GOV_ENABLED','OUF_SCHEMA_GOV_GATEWAY_BASE_URL','OUF_SCHEMA_GOV_GATEWAY_AUTH_ENABLED','OUF_SCHEMA_GOV_TOKEN_ENDPOINT','OUF_SCHEMA_GOV_CLIENT_ID','OUF_SCHEMA_GOV_CLIENT_SECRET_FILE','OUF_SCHEMA_GOV_WORKLOAD_SCOPE','OUF_SEMANTIC_DISCOVERY_DELEGATION_KEY_FILE','OUF_SEMANTIC_DISCOVERY_DELEGATION_WORKLOAD')
    bindings={k:{'nonempty':bool(current.get(k))} for k in names}
    for k in ('OUF_SCHEMA_GOV_ENABLED','OUF_SCHEMA_GOV_GATEWAY_AUTH_ENABLED'):
        bindings[k]['enabledExplicitly']=current.get(k,'').lower()=='true'
    return {'candidateConfig':cfg,'retainedContainer':container,'installedImage':installed_image,'candidateImage':candidate_image,
        'public':{'containerId':CID,'installedImageId':OLD_IMAGE,'candidateImageId':NEW_IMAGE,
          'explicitEnvironmentOverrideNames':sorted(overrides),'inheritedImageEnvironmentNames':inherited,
          'ignoredLegacyRuntimeMetadataOverrideNames':legacy_runtime,
          'removedInstalledImageEnvironmentNames':removed,'unreviewedEnvironmentOverrideNames':unknown,'explicitCommandOrUserOverrideNames':argv_overrides,
          'runtimeDefaultsTakenFromSignedCandidate':True,'candidateConfigHash':digest(cfg),
          'candidateConfigUser':cfg.get('User'),'retainedAuthMounts':[{'destination':m['Destination'],'readOnly':True} for m in mounted],
          'otherMountDestinations':[m['Destination'] for m in container['Mounts'] if m not in mounted],
          'explicitProviderAndDiscoveryBindings':bindings,'providerAuthenticationReadinessProven':False,
          'discoveryReceiptKeyCustodyProven':False,'springImportedConfigurationNotInspected':True,
          'completeReplacementOciProven':False,'cutoverApplyReady':False}}

def call(args):
    require(CLI is not None,'EXPLICIT_EMPTY_DOCKER_CONFIGURATION_REQUIRED')
    p=subprocess.run(['/usr/bin/docker','--config',str(CLI),*args],capture_output=True,timeout=20,env={'PATH':'/usr/bin:/bin','DOCKER_HOST':'unix:///var/run/docker.sock'})
    require(p.returncode==0 and len(p.stdout)<=2000000,'BOUNDED_DOCKER_INSPECT_REQUIRED')
    return json.loads(p.stdout)
def stable(c):return {k:c[k] for k in ('Id','Image','Config','HostConfig','Mounts')}|{'networks':c['NetworkSettings']['Networks'],'generation':{k:c['State'][k] for k in ('Pid','StartedAt','Running')}}
def private_create(path,value):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,'wb') as stream:stream.write(encoded(value));stream.flush();os.fsync(stream.fileno())
    except Exception:
        raise

def main():
    global CLI
    os.umask(0o077)
    report={'schema':'ouf.discovery.semantic-replacement-configuration-read.v1','containerLifecycleOperations':0,'imageImports':0,'existingConfigurationWrites':0,'privateKeysRead':0,'privateValuesPrinted':False,'databaseWrites':0,'dnsQueries':0,'providerCalls':0,'signaturesIssued':0,'commonLockAcquired':False,'notReleaseAcceptance':True}
    try:
        root=Path(tempfile.mkdtemp(prefix='ouf-semantic-replacement-config-',dir=Path.home()));root.chmod(0o700)
        CLI=root/'empty-docker-cli';CLI.mkdir(mode=0o700)
        before=call(['inspect','--type','container',CID])[0]
        require(before['State']['Running'] is True and before['State']['Pid']==3789123,'RETAINED_PRIMARY_GENERATION_REQUIRED')
        old=call(['image','inspect',OLD_IMAGE])[0]
        raw=(STAGE/'build-image.json').read_bytes();require(len(raw)<=2000000,'CANDIDATE_IMAGE_METADATA_BOUNDED')
        candidate=json.loads(raw)[0]
        inventory=json.loads((STAGE/'inventory.json').read_bytes())
        require(inventory['sourceCommit']==SOURCE and inventory['imageId']==NEW_IMAGE and inventory['thresholdMet'] is True,'EXACT_STAGED_CANDIDATE_METADATA_REQUIRED')
        delta=configuration_delta(before,old,candidate)
        require(stable(before)==stable(call(['inspect','--type','container',CID])[0]),'PRIMARY_CHANGED_DURING_CONFIGURATION_READ')
        require((STAGE/'build-image.json').read_bytes()==raw,'SIGNED_METADATA_CHANGED_DURING_READ')
        private_create(root/'private-configuration-delta.json',delta)
        report.update(status='PRIVATE_CONFIGURATION_DELTA_CAPTURED_NOT_APPLY_READY',evidenceDirectory=str(root),**delta['public'],primaryGenerationUnchanged=True,candidateCryptoReverifiedInThisRead=False,privateEvidenceFilesCreated=2)
        private_create(root/'receipt.json',report)
    except Exception as error:
        reason=str(error);report.update(status='READ_BLOCKED',reason=reason if re.fullmatch('[A-Z][A-Z0-9_]{0,120}',reason) else 'CONFIGURATION_CUSTODY_UNPROVEN',errorType=type(error).__name__)
    print('OUF_SEMANTIC_REPLACEMENT_CONFIGURATION='+json.dumps(report,sort_keys=True))
    return 0 if report['status']=='PRIVATE_CONFIGURATION_DELTA_CAPTURED_NOT_APPLY_READY' else 1
if __name__=='__main__':raise SystemExit(main())
