"""Compile private bootstrap draft from current retained runtime. No SQL or runtime authority."""

import hashlib,http.client,json,os,re,signal,socket,stat,sys,tempfile

from pathlib import Path

OWNER = Path('/etc/ouf/deploy-snapshots/ingestion-owner-recovery-execution-d6o9cpwd')

OWNER_PLAN = 'e5f69f89aa40b8c9b963134d38a6aecaf864499346f9e366539c1eb1aefa0938'

OWNER_RESULT = '7d3902327a9b3641129f4416b66324c4cf727d0e54708216f9df098388a15618'

class Denied(Exception):
    pass

def require(ok, code):
    if not ok:
        raise Denied(code)

def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def digest(value):
    return sha(encoded(value))

def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'DUPLICATE_JSON_KEY')
        result[key] = value
    return result

def decode(raw):
    def bad(_):
        raise Denied('NONFINITE_JSON')
    return json.loads(raw, object_pairs_hook=unique, parse_constant=bad)

def metadata(info):
    return tuple(getattr(info, name) for name in (
        'st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink',
        'st_size', 'st_mtime_ns', 'st_ctime_ns'))

def read(path, expected=None, maximum=8388608, projection=False):
    """FD-relative no-follow traversal; retain and recheck every ancestor FD."""
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'EXACT_PATH_REQUIRED')
    if projection:
        require(path == Path('/opt/ouf/installation/active-projection.json'), 'EXACT_PROJECTION_PATH_REQUIRED')
    descriptors = []
    ancestors = []
    try:
        parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptors.append(parent)
        current = Path('/')
        for name in path.parts[1:-1]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            descriptors.append(child)
            info = os.fstat(child)
            current /= name
            if projection and current == Path('/opt/ouf'):
                require(info.st_uid == info.st_gid == 1000 and stat.S_IMODE(info.st_mode) == 0o750,
                        'APPROVED_OUF_PARENT_CUSTODY_REQUIRED')
            else:
                require(info.st_uid == 0 and not info.st_mode & 0o022, 'ROOT_ANCESTRY_REQUIRED')
            if projection and current == path.parent:
                require(info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o700,
                        'PRIVATE_INSTALLATION_DIRECTORY_REQUIRED')
            identity = lambda v: (v.st_dev, v.st_ino, v.st_uid, v.st_gid, v.st_mode)
            ancestors.append((parent, name, child, identity(info)))
            parent = child
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        descriptors.append(fd)
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
                and 0 < info.st_size <= maximum, 'PRIVATE_FILE_CUSTODY_REQUIRED')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(maximum + 1)
        require(len(raw) == info.st_size and metadata(info) == metadata(os.fstat(fd))
                == metadata(os.stat(path.name, dir_fd=parent, follow_symlinks=False)), 'FILE_CHANGED_DURING_READ')
        require(expected is None or sha(raw) == expected, 'RETAINED_FILE_HASH_DRIFT')
        for ancestor, name, child, pin in ancestors:
            require(pin == identity(os.fstat(child))
                    == identity(os.stat(name, dir_fd=ancestor, follow_symlinks=False)), 'ANCESTRY_CHANGED_DURING_READ')
        return raw, list(metadata(info))
    finally:
        for fd in reversed(descriptors):
            os.close(fd)

def parsed(path, expected=None, maximum=8388608):
    return decode(read(path, expected, maximum)[0])

def runtime(value, ordered=True):
    state = value['State']
    require(state['Running'] is True and state.get('Paused', False) is False
            and state.get('Restarting', False) is False and type(state['Pid']) is int
            and state['Pid'] > 0, 'RUNNING_GENERATION_REQUIRED')
    mounts = value['Mounts']
    require(type(mounts) is list and len({m['Destination'] for m in mounts}) == len(mounts),
            'UNIQUE_MOUNTS_REQUIRED')
    return {'containerId': value['Id'], 'imageId': value['Image'], 'pid': state['Pid'],
            'startedAt': state['StartedAt'], 'configHash': digest(value['Config']),
            'hostConfigHash': digest(value['HostConfig']),
            'mountsHash': digest(sorted(mounts, key=lambda m: m['Destination']) if ordered else mounts),
            'networkSettingsHash': digest(value['NetworkSettings'])}

class EngineReader:
    def __init__(self, binding, references):
        self.path = Path(binding['socketPath'])
        self.pin = tuple(binding['socketBinding'])
        require(self.path.is_absolute() and '..' not in self.path.parts and len(self.pin) == 5,
                'EXACT_ENGINE_BINDING_REQUIRED')
        require(1 <= len(references) <= 8 and len(set(references)) == len(references)
                and all(re.fullmatch('[0-9a-f]{64}', r) for r in references), 'BOUNDED_EXACT_CONTAINERS_REQUIRED')
        self.paths = {'/v1.44/containers/' + r + '/json' for r in references}
        self.calls = 0
        self.maximum = 2 * len(references)

    def check(self):
        require(self.path.resolve() == self.path, 'ENGINE_SYMLINK_DENIED')
        info = self.path.lstat()
        require(stat.S_ISSOCK(info.st_mode) and info.st_uid == 0
                and stat.S_IMODE(info.st_mode) in (0o600, 0o660)
                and (info.st_dev, info.st_ino, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == self.pin,
                'ENGINE_SOCKET_DRIFT')

    def get(self, reference):
        path = '/v1.44/containers/' + reference + '/json'
        require(path in self.paths and self.calls < self.maximum, 'FINITE_CLOSED_ENGINE_GET_REQUIRED')
        self.check()
        engine_path = str(self.path)
        class Connection(http.client.HTTPConnection):
            def connect(connection):
                connection.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                connection.sock.settimeout(connection.timeout)
                connection.sock.connect(engine_path)
        connection = Connection('retained-engine', timeout=5)
        try:
            self.calls += 1
            connection.request('GET', path)
            reply = connection.getresponse()
            raw = reply.read(4194305)
            require(reply.status == 200 and 0 < len(raw) <= 4194304, 'BOUNDED_ENGINE_REPLY_REQUIRED')
            self.check()
            return decode(raw)
        finally:
            connection.close()

import copy

FLAGS=('--spring.flyway.enabled=false','--ouf.ingestion.startup.schema-mode=VALIDATE_ONLY')

def compile_config(config):
    require(type(config)is dict and config.get('Entrypoint')==['java','-jar','/app/app.jar'],
            'EXACT_JAVA_JAR_ENTRYPOINT_REQUIRED')
    command=config.get('Cmd') or []
    require(type(command)is list and len(command)<=64 and all(type(v)is str and 0<len(v)<=4096 for v in command),
            'BOUNDED_APPLICATION_COMMAND_REQUIRED')
    for value in command:
        key=value.split('=',1)[0].lower().replace('-','').replace('.','').replace('_','')
        require(value!='--' and not key.startswith(('springflyway','oufingestionstartupschemamode')),
                'STARTUP_POLICY_ARGUMENT_COLLISION')
    environment={}
    for item in config.get('Env',[]):
        key,separator,value=item.partition('=')
        require(separator and key and key not in environment,'UNIQUE_BOOTSTRAP_ENVIRONMENT_REQUIRED')
        environment[key]=value
    require('SPRING_FLYWAY_ENABLED' not in environment or environment['SPRING_FLYWAY_ENABLED']=='false',
            'STARTUP_POLICY_ENVIRONMENT_COLLISION')
    after=copy.deepcopy(config)
    after['Env']=[*config.get('Env',[])]
    if 'SPRING_FLYWAY_ENABLED' not in environment:after['Env'].append('SPRING_FLYWAY_ENABLED=false')
    after['Cmd']=[*command,*FLAGS]
    return after


DRAFT = Path('/etc/ouf/deploy-snapshots/ingestion-read-owner-draft-71atrj6k/draft-plan.json')
DRAFT_HASH = '2b2e04e379209e365c8fcf2da8ac52141afed9d2034dc5534722c32cdfbb32ec'
CANDIDATE = '0fe0de60c6d980fe97610acf195d4bfd46d3777f'
IMAGE = 'sha256:5dfdf2239fa9eb3ae2ff8510521322cf91718bc787eee179db8e65c515a30e8b'
ROUTES = 'ed619aa9415b2e70f61689c3830b3fc89135bc9ab72fc90f24daeba1e7bed8c7'
PROGRESS = {}


def compile_draft(owner, draft, actual):
    require(set(actual) == {'ingestion','gateway'}, 'EXACT_TWO_RUNTIME_BOOTSTRAPS_REQUIRED')
    require(owner['bindingPlan']['candidatePayloadChecksum'] == draft['owner']['candidatePayloadChecksum']
            and owner['bindingPlan']['candidatePayload'] == draft['owner']['candidatePayload'],
            'COMPLETED_OWNER7_PAYLOAD_MUST_MATCH_RETAINED_DEDICATED_REFERENCE')
    require(len(draft['gateway']['beforeRoutes']) == len(draft['gateway']['afterRoutes']) == 82
            and digest(draft['gateway']['beforeRoutes']) == ROUTES
            and draft['gateway']['retainedOtherRoutes'] == 80 and draft['gateway']['maximumPutRequests'] == 2,
            'EXACT_RETAINED_TWO_FUNCTION_ROUTE_DRAFT_REQUIRED')
    before,after=draft['gateway']['beforeRoutes'],draft['gateway']['afterRoutes']
    require(set(before)==set(after) and {k for k in before if before[k]!=after[k]}=={'mcp-ingestion-status','mcp-ingestion-history'},
            'EXACT80_OTHER_ROUTES_MUST_BE_PRESERVED')
    require(all(runtime(actual[name]) == owner['currentApplications'][name] for name in actual),
            'CURRENT_INGESTION_OR_GATEWAY_GENERATION_DRIFT')
    profile = compile_config(actual['ingestion']['Config'])
    environment = actual['gateway']['Config'].get('Env', [])
    names = [row.partition('=')[0] for row in environment]
    require(len(set(names)) == len(names) and 'OUF_INGESTION_READ_OWNER_KEY' not in names,
            'EXACT_NEW_GATEWAY_REFERENCE_ENVIRONMENT_REQUIRED')
    additions = draft['runtime']['ingestion']['environmentAdditions']
    before_names = [row.partition('=')[0] for row in actual['ingestion']['Config'].get('Env', [])]
    require(not set(additions) & set(before_names), 'NO_RETAINED_OWNER_READ_BOOTSTRAP_COLLISION')
    secret = owner['bindingPlan']['candidatePayload']['secrets']['references']['ingestionReadOwnerKey']
    require(draft['runtime']['ingestion']['readOnlyBindAddition']['Source'] == secret,
            'EXACT_ALREADY_PUBLISHED_OWNER_KEY_REFERENCE_REQUIRED')
    return {
        'schema':'ouf.ingestion-startup-bootstrap-draft.v1', 'kind':'DRAFT_ONLY_NO_RUNTIME_EXECUTOR',
        'ownerPlanBinding':{'path':str(OWNER/'execution-plan.json'),'sha256':OWNER_PLAN},
        'retainedDraftBinding':{'path':str(DRAFT),'sha256':DRAFT_HASH},
        'candidate':{'sourceCommit':CANDIDATE,'imageId':IMAGE,'packageRunId':39380965920,'artifactId':12245228551,
            'artifactZipSha256':'02974a024e66d2f3adb9933f654954868598f6dfcec8899bf76daced9a1aeb02'},
        'expectedRuntimeBindings':{name:owner['currentApplications'][name] for name in actual},
        'ingestion':{'bootstrapCmd':profile['Cmd'],'startupEnvironmentAddition':{'SPRING_FLYWAY_ENABLED':'false'},
            'ownerReadEnvironmentAdditions':additions,'readOnlyBindAddition':draft['runtime']['ingestion']['readOnlyBindAddition'],
            'schemaPolicy':'VALIDATE_ONLY','unchangedSqlMigrations':18,'allOtherConfigPreservedRequired':True},
        'gateway':{'imageUnchangedRequired':True,'environmentAddition':{'OUF_INGESTION_READ_OWNER_KEY':{'secretReference':'ingestionReadOwnerKey','path':secret}},
            'referenceValueResolved':False,'mountsUnchangedRequired':True,'allOtherConfigPreservedRequired':True},
        'routeDraft':draft['gateway'],'currentOwnerActiveRequeried':False,'liveGatewayRouteMapRead':False,
        'unprovenGates':['CANDIDATE_ARCHIVE_CUSTODY_AND_COMPLETE_CREATION_FRAME','SIGNED_RUNTIME_EXECUTOR_QUALIFICATION',
            'CURRENT_HUMAN_AND_SEPARATE_NATIVE_REVIEW','CURRENT_OWNER7_STRONG_ETAG_AND_PAYLOAD',
            'LIVE_GATEWAY82_ROUTE_MAP','FRESH_DATABASE_ADMISSION_BEFORE_EFFECTS'],
        'completedOwnerActionReplayed':False,'completedPublicationReplayed':False,'newLoginAllowed':False,
        'secretGenerationAllowed':False,'databaseMigrationAllowed':False,'grantChangesAllowed':False,
        'sourceActivationAllowed':False,'jobDispatchAllowed':False,'runtimeAuthorityIssued':False,
        'runtimeExecutorQualified':False,'databaseAdmissionProven':False,'automaticReplayAllowed':False,'budgetReset':False,
        'completedTechnicalPhases':8,'functionalMilestonesProven':4,'notReleaseAcceptance':True,
    }


def write_new(path, value):
    raw=encoded(value)
    require(0 < len(raw) <= 8388608, 'BOUNDED_PRIVATE_DRAFT_REQUIRED')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(os.dup(fd),'wb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
    finally:os.close(fd)
    require(read(path,sha(raw))[0] == raw, 'PRIVATE_DRAFT_READBACK_REQUIRED')


def main():
    require(len(sys.argv)==1 and os.geteuid()==os.getegid()==0 and sys.flags.isolated
            and sys.flags.no_site and sys.dont_write_bytecode, 'ISOLATED_ROOT_NO_ARGUMENTS_REQUIRED')
    def expired(*_):raise Denied('FINITE_BOOTSTRAP_DRAFT_DEADLINE')
    signal.signal(signal.SIGALRM,expired);signal.alarm(90);os.umask(0o077)
    owner=parsed(OWNER/'execution-plan.json',OWNER_PLAN)
    result=parsed(OWNER/'update-result.json',OWNER_RESULT)
    require(result['complete']is True and result['planHash']==OWNER_PLAN,'EXACT_COMPLETED_OWNER7_REQUIRED')
    draft=parsed(DRAFT,DRAFT_HASH)
    selected={name:owner['currentApplications'][name] for name in ('ingestion','gateway')}
    reader=EngineReader(owner['engine'],[p['containerId']for p in selected.values()])
    actual={name:reader.get(pin['containerId'])for name,pin in selected.items()}
    plan=compile_draft(owner,draft,actual)
    require(all(runtime(reader.get(pin['containerId']))==runtime(actual[name])for name,pin in selected.items()),
            'RUNTIME_CHANGED_DURING_DRAFT_COMPILATION')
    require(parsed(OWNER/'execution-plan.json',OWNER_PLAN)==owner and parsed(OWNER/'update-result.json',OWNER_RESULT)==result
            and parsed(DRAFT,DRAFT_HASH)==draft,'RETAINED_DRAFT_SELECTION_CHANGED')
    root=OWNER.parent;logical=digest({'ownerPlan':OWNER_PLAN,'candidate':CANDIDATE,'image':IMAGE,'bootstrap':plan['ingestion']})
    claim=root/('ingestion-startup-bootstrap-draft-'+logical+'.claim.json')
    require(not os.path.lexists(claim),'BOOTSTRAP_DRAFT_ALREADY_PREPARED_NO_REPLAY')
    context=Path(tempfile.mkdtemp(prefix='ingestion-startup-bootstrap-draft-',dir=root));os.chmod(context,0o700)
    PROGRESS.update(contextPath=str(context),privateArtifactsOnly=True)
    write_new(claim,{'contextPath':str(context),'logicalRef':logical,'automaticReplayAllowed':False,'runtimeAuthorityIssued':False})
    write_new(context/'draft-plan.json',plan)
    report={'schema':'ouf.ingestion-startup-bootstrap-draft-result.v1','complete':True,'status':'DRAFT_COMPILED_NO_AUTHORITY',
        'contextPath':str(context),'draftPlanHash':digest(plan),'engineGetRequests':reader.calls,'runtimeBindingsStable':True,
        'candidateSourceCommit':CANDIDATE,'candidateImageId':IMAGE,'privateArtifactsOnly':True,'privatePreparationWrites':3,
        'proposedRuntimeReplacements':2,'proposedGatewayPuts':2,'retainedOtherRoutes':80,'currentOwnerActiveRequeried':False,
        'liveGatewayRouteMapRead':False,'credentialFilesOpened':0,'credentialValuesPrinted':False,'credentialHashesPrinted':False,
        'humanCredentialJournalsRead':0,'oauthRequests':0,'ownerRequests':0,'gatewayRequests':0,'databaseCalls':0,
        'containerLifecycleOperations':0,'candidateImageImported':False,'secretValuesGenerated':0,
        'completedOwnerActionReplayed':False,'completedPublicationReplayed':False,'completedDbPreflightReplayed':False,
        'newLoginPerformed':False,'refreshPerformed':False,'windowExtended':False,'runtimeAuthorityIssued':False,
        'runtimeExecutorQualified':False,'databaseAdmissionProven':False,'automaticReplayAllowed':False,'budgetReset':False,
        'completedTechnicalPhases':8,'functionalMilestonesProven':4,'notReleaseAcceptance':True}
    write_new(context/'preparation-result.json',report)
    fd=os.open(context,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
    print(encoded(report).decode(),flush=True)


if __name__=='__main__':
    try:main()
    except (Exception,KeyboardInterrupt)as error:
        print(encoded({'schema':'ouf.ingestion-startup-bootstrap-draft-result.v1','complete':False,'status':'STOP_RECONCILE',
            'reasonCode':str(error)if type(error)is Denied else 'PRIVATE_DETAILS_REDACTED','checkpoint':PROGRESS,
            'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,'budgetReset':False,
            'completedTechnicalPhases':8,'functionalMilestonesProven':4}).decode(),flush=True)
        raise SystemExit(2)
