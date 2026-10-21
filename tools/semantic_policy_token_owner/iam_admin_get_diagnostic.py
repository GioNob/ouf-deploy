"""One exact existing IAM GET, bounded private stderr, public fixed categories.

No login, credentials, key/token reads, writes, retries, IAM/service changes.
CLI text categories are observations, not authenticated proof of root cause.
"""
import os
import re
import signal
import subprocess
import sys
import tempfile
import iam_binding_candidate as binding

SNAPSHOT='policy-token-iam-metadata-830709d5bc5348309025c3a82212a62e.private.json'
SNAPSHOT_HASH='7e0f46ad0f66ee40b2ce0f662fdb70007744f81f933865264fdf279227681927'
FIELDS='id,clientId,enabled,serviceAccountsEnabled,publicClient,clientAuthenticatorType,protocol'
PATTERNS=(
    (r'session (?:has )?expired|failed to refresh access token|invalid_grant|refresh token[^\n]{0,80}(?:expired|invalid)|not logged in|no token specified','SESSION_AUTH_FAILURE_TEXT_OBSERVED'),
    (r'unauthorized|\bhttp[^\n]{0,48}\b401\b|\bstatus[^\n]{0,24}\b401\b','UNAUTHORIZED_TEXT_OBSERVED'),
    (r'forbidden|\bhttp[^\n]{0,48}\b403\b|\bstatus[^\n]{0,24}\b403\b','FORBIDDEN_TEXT_OBSERVED'),
    (r'connection refused|connectexception','CONNECTION_REFUSED_TEXT_OBSERVED'),
    (r'timed out|timeout','CONNECTION_TIMEOUT_TEXT_OBSERVED'),
    (r'container[^\n]{0,160}(?:is not running|not found)|no such container','CONTAINER_UNAVAILABLE_TEXT_OBSERVED'),
    (r'permission denied|accessdeniedexception','LOCAL_PERMISSION_FAILURE_TEXT_OBSERVED'),
    (r'https required|ssl required|sslhandshake|certificate','TLS_OR_HTTPS_FAILURE_TEXT_OBSERVED'),
    (r'unknown option|unmatched argument|command not found|no such file or directory','CLI_OR_FILE_FAILURE_TEXT_OBSERVED'))

def categories(raw):
    text=raw.decode('utf-8','replace').lower()
    return [label for pattern,label in PATTERNS if re.search(pattern,text)] or ['UNCLASSIFIED_CLI_FAILURE']

def command(argv,seconds=15):
    # Anonymous files avoid unbounded PIPE capture and never expose raw
    # stderr/HTTP bodies. Only a bounded memory projection leaves this scope.
    with tempfile.TemporaryFile()as stdout,tempfile.TemporaryFile()as stderr:
        result=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,timeout=seconds)
        stdout.seek(0);stderr.seek(0)
        return result.returncode,stdout.read(262145),stderr.read(65537)

def observe(report):
    report['phase']='EXACT_RETAINED_CLIENT_REFERENCE_READ'
    with binding.protected_parent()as directory:
        raw=binding.read_member(directory,SNAPSHOT)
        binding.require(binding.sha(raw)==SNAPSHOT_HASH,'RETAINED_METADATA_HASH_DRIFT')
        snapshot=binding.decode(raw);client=snapshot['client']['id']
        binding.require(snapshot.get('schema')=='ouf.policy-token-existing-iam-metadata.v1'
            and type(client)is str and re.fullmatch('[0-9a-fA-F-]{36}',client),'EXACT_EXISTING_CLIENT_REQUIRED')
        report['phase']='SELECTED_CONTAINER_STATE_READ';report['dockerMetadataReads']=1
        status,out,err=command(['/usr/bin/docker','inspect','--format','{{.State.Running}}','ouf-keycloak'],10)
        report['selectedContainerInspectExitCode']=status
        if status!=0:
            report.update(status='DIAGNOSIS_OBSERVED_NOT_ACCEPTED',diagnosticCategories=categories(err[:65536]),
                diagnosticTextTruncated=len(err)>65536,reason='SELECTED_CONTAINER_INSPECT_UNAVAILABLE');return
        binding.require(out.strip() in (b'true',b'false'),'CONTAINER_STATE_SCHEMA_UNPROVEN')
        report['selectedContainerRunning']=out.strip()==b'true'
        if out.strip()!=b'true':
            report.update(status='DIAGNOSIS_OBSERVED_NOT_ACCEPTED',reason='SELECTED_CONTAINER_NOT_RUNNING');return
        report['phase']='EXACT_EXISTING_IAM_GET_DIAGNOSIS';report['iamMetadataGetAttempts']=1
        status,out,err=command(['/usr/bin/docker','exec','ouf-keycloak','/opt/keycloak/bin/kcadm.sh','get',
            'clients/'+client,'--server','http://localhost:8080','-r','ouf','--fields',FIELDS])
        report.update(iamGetExitCode=status,diagnosticTextTruncated=len(err)>65536)
        if status!=0:
            report.update(status='DIAGNOSIS_OBSERVED_NOT_ACCEPTED',diagnosticCategories=categories(err[:65536]),
                reason='EXISTING_IAM_GET_FAILED_CATEGORIES_OBSERVED')
        else:
            binding.require(0<len(out)<=262144,'IAM_METADATA_RESPONSE_UNBOUNDED')
            value=binding.decode(out)
            binding.require(type(value)is dict and set(value)==set(FIELDS.split(',')) and value['id']==client,
                'EXACT_CLIENT_GET_SCHEMA_UNPROVEN')
            report.update(status='DIAGNOSIS_OBSERVED_NOT_ACCEPTED',exactSelectedClientGetSucceeded=True,
                diagnosticCategories=[],reason='CURRENT_SELECTED_GET_AVAILABLE_NO_AUTOMATIC_PREPARATION_REPLAY')
        binding.require(binding.read_member(directory,SNAPSHOT)==raw,'RETAINED_METADATA_CHANGED')

def main():
    report={'schema':'ouf.policy-token-admin-get-diagnostic.v1','phase':'DIAGNOSTIC_DELIVERY','status':'BLOCKED',
        'iamMetadataGetAttempts':0,'dockerMetadataReads':0,'privateKeysRead':0,'credentialFilesRead':0,'mountedTokenFilesRead':0,
        'privateEvidenceWrites':0,'iamMutations':0,'serviceMutations':0,'signaturesIssued':0,'tokenGrantRequests':0,
        'providerCalls':0,'rawDiagnosticTextPrinted':False,'diagnosticCategoriesAreNotRootCauseProof':True,
        'runtimeAuthorityIssued':False,'productionApplyReady':False,'budgetReset':False,'r12Touched':False,'notReleaseAcceptance':True}
    try:
        binding.require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.dont_write_bytecode,'ROOT_ISOLATED_DIAGNOSTIC_REQUIRED')
        def timeout(*_):raise binding.CandidateDenied('FINITE_DIAGNOSTIC_DEADLINE')
        signal.signal(signal.SIGALRM,timeout);signal.alarm(30)
        observe(report);code=0
    except Exception as error:
        report['reason']=str(error) if type(error)is binding.CandidateDenied else type(error).__name__
        if isinstance(error,OSError):report['errno']=error.errno
        code=1
    finally:signal.alarm(0)
    print(binding.encoded(report).decode());return code

if __name__=='__main__':raise SystemExit(main())
