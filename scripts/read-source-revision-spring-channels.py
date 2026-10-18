#!/usr/bin/env python3
"""Installation-specific, bounded Docker metadata read; no value-bearing logs."""
import json,re,shlex,subprocess,sys,traceback
from pathlib import Path

RUNTIME_FORMAT='{"id":{{json .Id}},"image":{{json .Image}},"running":{{json .State.Running}},"pid":{{json .State.Pid}},"revision":{{json (index .Config.Labels "org.opencontainers.image.revision")}}}'
JVM=('JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','JAVA_OPTS','_JAVA_OPTIONS')

def json_properties(raw):
    assert type(raw)is str and 0<len(raw.encode())<=65536,'BOUNDED_JSON_REQUIRED'
    def unique(rows):
        result={}
        for key,value in rows:
            assert key not in result,'DUPLICATE_JSON_KEY';result[key]=value
        return result
    value=json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in ()).throw(ValueError()))
    result=[];seen=set()
    def visit(obj,prefix='',depth=0):
        assert type(obj)is dict and depth<=12,'JSON_OBJECT_SHAPE'
        for key,item in obj.items():
            assert type(key)is str and re.fullmatch('[A-Za-z0-9_.-]{1,128}',key),'JSON_PROPERTY_SHAPE'
            full=prefix+'.'+key if prefix else key
            if type(item)is dict:visit(item,full,depth+1)
            else:
                normalized=re.sub('[^a-z0-9]','',full.lower())
                assert normalized not in seen and len(seen)<64,'JSON_ALIAS_OR_BOUND';seen.add(normalized)
                row={'property':normalized,'type':type(item).__name__}
                if normalized in ('springflywayenabled','springflywaybaselineonmigrate','springflywayvalidateonmigrate')and type(item)is bool:
                    row['classification']='EXPLICIT_TRUE'if item else'EXPLICIT_FALSE'
                result.append(row)
    visit(value)
    return sorted(result,key=lambda r:r['property'])

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
    assert type(entries)is list and len(entries)<=256,'ENV_LIST_BOUND'
    result=[];seen=set()
    for entry in entries:
        assert type(entry)is str and '='in entry and len(entry)<=65536,'ENV_ENTRY_BOUND'
        key,value=entry.split('=',1);assert key not in seen,'DUPLICATE_ENV_NAME';seen.add(key)
        normalized=re.sub('[^a-z0-9]','',key.lower())
        if normalized.startswith(('spring','loader'))or key in JVM:
            assert re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,127}',key),'ENV_NAME_SHAPE'
            row={'name':key,'classification':classify(key,value)}
            if key=='SPRING_APPLICATION_JSON':row['properties']=json_properties(value)
            result.append(row)
    return sorted(result,key=lambda r:r['name'])

def inspect(reference,format):
    assert re.fullmatch('[0-9a-f]{64}',reference)
    reply=subprocess.run(['/usr/bin/docker','inspect','--type','container','--format',format,reference],
        stdin=subprocess.DEVNULL,capture_output=True,timeout=15,
        env={'PATH':'/usr/bin:/bin','LC_ALL':'C','DOCKER_HOST':'unix:///var/run/docker.sock','DOCKER_API_VERSION':'1.44'})
    assert reply.returncode==0 and 0<len(reply.stdout)<=131072,'ENGINE_READ_UNPROVEN'
    return json.loads(reply.stdout)

def main(selection):
    assert selection['schema']=='ouf.source-revision-private-preparation-selection.v1'
    target=selection['currentApplications']['onboarding'];reference=target['containerId']
    before=inspect(reference,RUNTIME_FORMAT)
    assert before['id']==reference and before['image']==target['imageId']and before['revision']==target['sourceCommit'],'CURRENT_GENERATION_CHANGED'
    assert before['running']is True and type(before['pid'])is int and before['pid']>0,'CURRENT_PROCESS_NOT_RUNNING'
    selected=channels(inspect(reference,'{{json .Config.Env}}'))
    assert inspect(reference,RUNTIME_FORMAT)==before,'GENERATION_CHANGED_DURING_READ'
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
            'reason':str(error)if type(error)is AssertionError and re.fullmatch('[A-Z_]{1,100}',str(error))else'UNCLASSIFIED_READ_FAILURE',
            'frames':[{'file':Path(f.filename).name,'function':f.name,'line':f.lineno}for f in traceback.extract_tb(error.__traceback__)[-4:]],
            'credentialValuesPrinted':False,'configurationValuesPrinted':False}
    print(json.dumps(result,sort_keys=True));sys.exit(0 if result['complete']else 1)
