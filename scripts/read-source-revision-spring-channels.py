#!/usr/bin/env python3
"""Installation-specific, bounded Docker metadata read; no value-bearing logs."""
import json,re,shlex,subprocess,sys
from pathlib import Path

RUNTIME_FORMAT='{"id":{{json .Id}},"image":{{json .Image}},"running":{{json .State.Running}},"pid":{{json .State.Pid}},"revision":{{json (index .Config.Labels "org.opencontainers.image.revision")}}}'
JVM=('JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','JAVA_OPTS','_JAVA_OPTIONS')

def jvm(value):
    if value=='':return 'EMPTY_JVM_NO_OPTIONS'
    if len(value)>4096:return 'UNCLASSIFIED'
    try:tokens=shlex.split(value,posix=True)
    except ValueError:return 'UNCLASSIFIED'
    memory=r'(?:-Xm[sx][1-9][0-9]*[kKmMgG]|-XX:(?:InitialRAMPercentage|MaxRAMPercentage|MinRAMPercentage)=(?:[0-9]+(?:\.[0-9]+)?))'
    if tokens and all(re.fullmatch(memory,t)for t in tokens):return 'MEMORY_ONLY_JVM'
    return 'UNCLASSIFIED'

def classify(key,value):
    if key in JVM:return jvm(value)
    if value=='':return 'EMPTY_SPRING_CHANNEL_REQUIRES_REVIEW'
    if key in ('SPRING_FLYWAY_ENABLED','SPRING_FLYWAY_BASELINE_ON_MIGRATE','SPRING_FLYWAY_VALIDATE_ON_MIGRATE'):
        return {'true':'EXPLICIT_TRUE','false':'EXPLICIT_FALSE'}.get(value,'UNCLASSIFIED')
    if key=='SPRING_JPA_HIBERNATE_DDL_AUTO':return {'validate':'VALIDATE_ONLY','none':'NO_DDL'}.get(value,'UNCLASSIFIED')
    if key=='SPRING_MAIN_BANNER_MODE'and value=='off':return 'BANNER_DISABLED'
    if key=='SPRING_SQL_INIT_MODE'and value=='never':return 'SQL_INIT_DISABLED'
    if key=='SPRING_CONFIG_ADDITIONAL_LOCATION':return 'RETAINED_LOCATION_REQUIRES_EXISTING_FILE_BINDING'
    return 'UNCLASSIFIED'

def channels(entries):
    assert type(entries)is list and len(entries)<=256
    result=[];seen=set()
    for entry in entries:
        assert type(entry)is str and '='in entry and len(entry)<=65536
        key,value=entry.split('=',1);assert key not in seen;seen.add(key)
        normalized=re.sub('[^a-z0-9]','',key.lower())
        if normalized.startswith(('spring','loader'))or key in JVM:
            assert re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,127}',key)
            result.append({'name':key,'classification':classify(key,value)})
    return sorted(result,key=lambda r:r['name'])

def inspect(reference,format):
    assert re.fullmatch('[0-9a-f]{64}',reference)
    reply=subprocess.run(['/usr/bin/docker','inspect','--type','container','--format',format,reference],
        stdin=subprocess.DEVNULL,capture_output=True,timeout=15,
        env={'PATH':'/usr/bin:/bin','LC_ALL':'C','DOCKER_HOST':'unix:///var/run/docker.sock','DOCKER_API_VERSION':'1.44'})
    assert reply.returncode==0 and 0<len(reply.stdout)<=131072
    return json.loads(reply.stdout)

def main(selection):
    assert selection['schema']=='ouf.source-revision-private-preparation-selection.v1'
    target=selection['currentApplications']['onboarding'];reference=target['containerId']
    before=inspect(reference,RUNTIME_FORMAT)
    assert before['id']==reference and before['image']==target['imageId']and before['revision']==target['sourceCommit']
    assert before['running']is True and type(before['pid'])is int and before['pid']>0
    selected=channels(inspect(reference,'{{json .Config.Env}}'))
    assert inspect(reference,RUNTIME_FORMAT)==before
    return {'schema':'ouf.source-revision-spring-channel-read.v1','installationSpecific':True,
        'complete':True,'completedTechnicalPhases':8,'functionalMilestonesProven':4,'generationMatches':True,
        'runtimeMutations':0,'runtimeAuthorityIssued':False,'profilePublications':0,'jobsRetried':0,
        'credentialFilesRead':0,'credentialValuesPrinted':False,'configurationValuesPrinted':False,
        'maximumEngineReads':3,'maximumSeconds':50,'automaticRetry':False,'channels':selected}

if __name__=='__main__':
    try:
        assert len(sys.argv)==2
        result=main(json.loads(Path(sys.argv[1]).read_bytes()))
    except Exception as error:
        result={'schema':'ouf.source-revision-spring-channel-read.v1','complete':False,
            'errorClass':type(error).__name__,'exceptionMessagePrinted':False,'runtimeMutations':0,
            'credentialValuesPrinted':False,'configurationValuesPrinted':False}
    print(json.dumps(result,sort_keys=True));sys.exit(0 if result['complete']else 1)
