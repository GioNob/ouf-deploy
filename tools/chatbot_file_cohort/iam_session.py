"""Reuse the documented interactive IAM login inside the single delivery.

The administrative Keycloak session is distinct from the HUMAN application
session. Password entry belongs to kcadm on /dev/tty, never to this Python
process, an argument, a pipe, a captured diagnostic, or a delivery receipt.
One durably consumed login attempt; uncertain completion is GET-reconciled.
"""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import resource
import subprocess
import tempfile

import iam_binding_candidate as evidence
import iam_governance_intake as governance
from iam_owner_action import publish
from tools.semantic_policy_token_owner.producer import protected_directory

SNAPSHOT = 'policy-token-iam-metadata-830709d5bc5348309025c3a82212a62e.private.json'
SNAPSHOT_HASH = '7e0f46ad0f66ee40b2ce0f662fdb70007744f81f933865264fdf279227681927'
FIELDS = 'id,clientId,enabled,serviceAccountsEnabled,publicClient,clientAuthenticatorType,protocol'
AUTH_FAILURE = re.compile(rb'session (?:has )?expired|failed to refresh access token|invalid_grant|'
                          rb'refresh token[^\n]{0,80}(?:expired|invalid)|not logged in|no token specified', re.I)
CLAIM = 'iam-admin-interactive-login.claim.json'


def _output_limit():
    resource.setrlimit(resource.RLIMIT_FSIZE, (262145,262145))


def _read(argv, env):
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        try:
            result = subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=out,stderr=err,
                timeout=20,env=env,preexec_fn=_output_limit)
        except (OSError,subprocess.TimeoutExpired):
            raise evidence.CandidateDenied('IAM_SESSION_PREFLIGHT_UNAVAILABLE') from None
        out.seek(0); err.seek(0)
        raw, diagnostic = out.read(262145), err.read(65537)
    evidence.require(len(raw)<=262144 and len(diagnostic)<=65536,'IAM_SESSION_PREFLIGHT_UNBOUNDED')
    return result.returncode,raw,diagnostic


@contextmanager
def _terminal():
    fd = os.open('/dev/tty',os.O_RDWR|os.O_NOCTTY)
    try:
        evidence.require(os.isatty(fd),'IAM_ADMIN_LOGIN_REQUIRES_CURRENT_OPERATOR_TTY')
        yield fd
    finally:
        os.close(fd)


def _interactive_login(argv, env):
    # No Python read from this descriptor. kcadm performs its normal password
    # prompt and terminal echo handling, exactly as the documented -it command.
    with _terminal() as fd:
        try:
            return subprocess.run(argv,stdin=fd,stdout=fd,stderr=fd,env=env,timeout=300).returncode
        except subprocess.TimeoutExpired:
            return None  # Unknown login outcome: the caller performs one GET.


def ensure_admin_session(engine,docker_binding,staging_directory,emit=print):
    """Read-only preflight, or one operator password prompt before any rollout.

    A failed GET alone does not prove an expired session. Only the established
    explicit authentication categories select the interactive login path.
    Permission/transport/unknown failures never become login or mutation loops.
    """
    evidence.require(governance.executable(docker_binding['path'])==docker_binding,
                     'IAM_SESSION_DOCKER_EXECUTABLE_DRIFT')
    with protected_directory(staging_directory):
        pass
    with evidence.protected_parent() as parent:
        raw=evidence.read_member(parent,SNAPSHOT)
        evidence.require(evidence.sha(raw)==SNAPSHOT_HASH,'IAM_SESSION_RETAINED_CLIENT_DRIFT')
        snapshot=evidence.decode(raw)
    client=snapshot['client']
    evidence.require(snapshot.get('schema')=='ouf.policy-token-existing-iam-metadata.v1'
        and re.fullmatch('[0-9a-fA-F-]{36}',client['id']),'IAM_SESSION_EXACT_RETAINED_CLIENT_REQUIRED')
    status,container=engine.request('GET','/v1.44/containers/ouf-keycloak/json')
    evidence.require(status==200 and container.get('Name')=='/ouf-keycloak'
        and re.fullmatch('[0-9a-f]{64}',container.get('Id','')),'IAM_SESSION_EXACT_RUNNING_CONTAINER_REQUIRED')
    state=container.get('State',{})
    evidence.require(state.get('Running') is True and type(state.get('Pid')) is int and state['Pid']>0
        and type(state.get('StartedAt')) is str and state['StartedAt'],'IAM_SESSION_CURRENT_PROCESS_REQUIRED')
    generation={'id':container['Id'],'pid':state['Pid'],'startedAt':state['StartedAt']}
    env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','TERM':'xterm-256color',
         'DOCKER_CONFIG':str(staging_directory)}
    base=[docker_binding['path'],'--host','unix://'+engine.path,'exec']
    tail=[generation['id'],'/opt/keycloak/bin/kcadm.sh']
    read=base+tail+['get','clients/'+client['id'],'--server','http://localhost:8080',
                    '-r','ouf','--fields',FIELDS]

    def guard():
        evidence.require(governance.executable(docker_binding['path'])==docker_binding,
                         'IAM_SESSION_DOCKER_EXECUTABLE_DRIFT')
        status,current=engine.request('GET','/v1.44/containers/'+generation['id']+'/json')
        evidence.require(status==200 and current.get('Id')==generation['id']
            and current.get('Name')=='/ouf-keycloak' and current.get('State',{}).get('Running') is True
            and current['State'].get('Pid')==generation['pid']
            and current['State'].get('StartedAt')==generation['startedAt'],'IAM_SESSION_CONTAINER_GENERATION_CHANGED')

    def observe():
        guard(); code,body,diagnostic=_read(read,env);guard()
        if code==0:
            value=evidence.decode(body)
            evidence.require(type(value) is dict and set(value)==set(FIELDS.split(','))
                and all(value[k]==client[k] for k in FIELDS.split(',')),
                'IAM_SESSION_CURRENT_CLIENT_CORE_DRIFT')
            return True,False
        return False,bool(AUTH_FAILURE.search(diagnostic+body))

    available,auth_failure=observe()
    attempted=False
    if not available:
        evidence.require(auth_failure,'IAM_SESSION_FAILURE_NOT_PROVEN_AUTHENTICATION')
        # Verify an interactive terminal exists before consuming the attempt.
        with _terminal():
            pass
        claim={'schema':'ouf.chatbot-iam-admin-interactive-login.v1','container':generation,
            'retainedSnapshotHash':SNAPSHOT_HASH,'maximumLoginAttempts':1,
            'automaticReplayAllowed':False,'passwordReadByDelivery':False}
        with protected_directory(staging_directory) as parent:
            evidence.require(not os.path.lexists(Path(staging_directory)/CLAIM)
                and publish(parent,CLAIM,evidence.encoded(claim)),'IAM_ADMIN_LOGIN_ATTEMPT_ALREADY_CONSUMED')
        guard()
        emit('La sessione amministrativa IAM richiede accesso. Inserisci la password di oufadmin '
             'nel prompt Keycloak qui sotto; il programma di consegna non la legge né la registra.')
        attempted=True
        login=base+['-it']+tail+['config','credentials','--server','http://localhost:8080',
                               '--realm','master','--user','oufadmin']
        _interactive_login(login,env)
        available,_=observe()
        evidence.require(available,'IAM_ADMIN_LOGIN_NOT_RECONCILED_NO_AUTOMATIC_REPLAY')
    result={'schema':'ouf.chatbot-iam-admin-session-preflight.v1','status':'SELECTED_IAM_GET_AVAILABLE',
        'administrativeLoginAttempted':attempted,'maximumLoginAttempts':1,
        'passwordReadByDelivery':False,'rawDiagnosticPrinted':False,
        'clientSecretRead':False,'serviceTokenGrantRequests':0,'iamResourceMutations':0,
        'serviceMutations':0,'runtimeAuthorityIssued':False,'notReleaseAcceptance':True}
    emit(json.dumps(result,sort_keys=True,separators=(',',':')))
    return result
