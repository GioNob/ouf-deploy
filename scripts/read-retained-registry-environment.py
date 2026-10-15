#!/usr/bin/python3
"""Read two byte-pinned historical inputs. Emit names/checks, never ENV values.

No Docker, DB, IAM, subprocess, network, file writes, or automatic retry.
Checks mirror environment predicates in the d8f23a4 preparation/profile.
They do not authorize a change or prove complete preparation.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

BASE=Path('/etc/ouf/deploy-snapshots/semantic-native-v11-intake-9ec18cf053e5925e42df93b75990343cc1d09696975fc2a224d76b4b28becdae')
FILES={'creation-request.private.json':'59181588fd8bbc0836f892789156532ebcc1cce304197560ca1274f05267d552',
       'private-runtime-declaration.json':'fc94b491d05e267b49da6e2e2fe50cc7e02e7986783bad7ebf1289b0914a0a68'}
RUNTIME={'PATH','JAVA_HOME','JAVA_VERSION','LANG','LANGUAGE','LC_ALL','TZ'}

def need(ok,code):
    if not ok:raise ValueError(code)

def read_bound(path,expected):
    need(path.resolve()==path,'EXACT_RETAINED_PATH_REQUIRED')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid==0 and before.st_nlink==1
             and stat.S_IMODE(before.st_mode)==0o600 and 0<before.st_size<=1048576,
             'ROOT_PRIVATE_BOUNDED_INPUT_REQUIRED')
        with os.fdopen(os.dup(fd),'rb') as source:raw=source.read(1048577)
        after=os.fstat(fd)
        identity=lambda v:(v.st_dev,v.st_ino,v.st_size,v.st_mtime_ns,v.st_ctime_ns,
                           v.st_uid,v.st_gid,v.st_mode,v.st_nlink)
        need(identity(before)==identity(after) and len(raw)==before.st_size
             and hashlib.sha256(raw).hexdigest()==expected,'RETAINED_INPUT_HASH_OR_GENERATION_DRIFT')
        def unique(pairs):
            value={}
            for key,item in pairs:
                need(key not in value,'DUPLICATE_RETAINED_JSON_KEY');value[key]=item
            return value
        return json.loads(raw,object_pairs_hook=unique)
    finally:os.close(fd)

def environment(rows):
    need(type(rows) is list and len(rows)<=256,'BOUNDED_ENVIRONMENT_REQUIRED')
    result={}
    for row in rows:
        need(type(row) is str and '=' in row and len(row)<=65536,'EXACT_ENVIRONMENT_ENTRY_REQUIRED')
        key,value=row.split('=',1)
        need(re.fullmatch('[A-Za-z_][A-Za-z_0-9]*',key) is not None and key not in result
             and '\x00' not in value,'ENVIRONMENT_NAME_OR_VALUE_INVALID')
        result[key]=value
    return result

def assess(request,declaration):
    env=environment(request['Env'])
    retained=environment(declaration['retainedNativeCreationFrame']['Config']['Env'])
    unexpected=sorted(k for k in env if not(k in RUNTIME or k.startswith(('OUF_','SPRING_','MANAGEMENT_')) or k=='PORT'))
    jvm=sorted(set(env)&{'JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS'})
    spring=sorted(k for k in env if k.startswith('SPRING_') and k!='SPRING_CONFIG_IMPORT')
    aliases=sorted(k for k in env if k.lower().replace('_','') in
                   {'oufsemanticprovidersschemagovenabled','oufsemanticdiscoveryworkerenabled'})
    passwords=sorted(set(env)&{'OUF_SEM_DB_PASSWORD','SPRING_DATASOURCE_PASSWORD'})
    target=declaration['databaseSecretProjection']['targetDirectory']
    checks={'retainedEnvironmentNamesAccepted':not unexpected,'jvmPropertyOverridesAbsent':not jvm,
        'springOverridesAbsent':not spring,'featureAliasOverridesAbsent':not aliases,
        'databasePasswordEnvironmentAbsent':not passwords,
        'databaseConfigtreeImportExact':env.get('SPRING_CONFIG_IMPORT')=='configtree:'+target+'/',
        'iamNotDisabled':env.get('OUF_IAM_ENABLED','true')!='false',
        'authorizationTokenFileReferencePresent':bool(env.get('OUF_AUTHORIZATION_REGISTRY_TOKEN_FILE')),
        'profileEnvironmentEntryBoundsPass':all(len(k+'='+v)<=16384 for k,v in env.items())}
    return {'schema':'ouf.retained-registry-environment-diagnosis.v1','status':'READ_COMPLETED_REVIEW_CHECK_RESULTS',
        'preparerCommit':'d8f23a433effbcb0ffb3581f658ce80f2963b595',
        'inputSha256':dict(FILES),'historicalCreationEnvironmentNames':sorted(env),
        'historicalNativeEnvironmentNames':sorted(retained),
        'creationOnlyEnvironmentNames':sorted(set(env)-set(retained)),
        'nativeOnlyEnvironmentNames':sorted(set(retained)-set(env)),
        'unexpectedRetainedEnvironmentNames':unexpected,'jvmPropertyOverrideNames':jvm,
        'springOverrideNames':spring,'featureAliasOverrideNames':aliases,
        'databasePasswordEnvironmentNames':passwords,'checks':checks,
        'failedChecks':sorted(k for k,v in checks.items() if not v),
        'environmentValuesPrinted':False,'environmentValueHashesPrinted':False,
        'filesRead':2,'fileWrites':0,'nativeCommands':0,'administrativeLoginAttempted':False,
        'readOnly':True,'serviceMutations':0,'databaseMutations':0,'iamResourceMutations':0,
        'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'automaticRetry':False,
        'budgetReset':False,'completePreparationProven':False,'chatbotEndToEndProven':False,'notReleaseAcceptance':True}

def main():
    need(os.geteuid()==0 and sys.flags.isolated and sys.flags.no_site,'ROOT_ISOLATED_NO_SITE_REQUIRED')
    values={name:read_bound(BASE/name,sha) for name,sha in FILES.items()}
    print(json.dumps(assess(values['creation-request.private.json'],values['private-runtime-declaration.json']),sort_keys=True))

if __name__=='__main__':
    try:main()
    except Exception as error:
        reason=str(error) if type(error) is ValueError and re.fullmatch('[A-Z][A-Z0-9_]{1,100}',str(error)) else type(error).__name__
        print(json.dumps({'schema':'ouf.retained-registry-environment-diagnosis.v1','status':'BLOCKED',
            'reason':reason,'readOnly':True,'runtimeAuthorityIssued':False,'automaticRetry':False,'notReleaseAcceptance':True}))
        sys.exit(1)
