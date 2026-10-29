#!/usr/bin/env python3
"""One concrete signed Onboarding V35 update; no grant/source activation.

The frozen proposal is immutable. Any necessary config/native-manifest mapping
is independently bound in a NEW final review before controlling-terminal consent.
"""
import ast,copy,gzip,hashlib,importlib.util,json,os,re,shutil,signal,stat,sys,time,types
from pathlib import Path
HELPER='/etc/ouf/deploy-snapshots/onboarding-v35-plan-c12c1435b8717924/plan.py'
HELPER_HASH='c12c1435b8717924a2051a0d51b32775fed35688ba15cf744c2a1da68b1bee23'
FROZEN='/etc/ouf/deploy-snapshots/onboarding-budget-v35-54d86bbcd2ea47fd/native-plan-v1/execution-plan.json'
FROZEN_HASH='b17c2c99cc791cced8ee00ed190e30b75c518ae84e2dd4a9ae7eef521390c8bd'
PARENT='/etc/ouf/deploy-snapshots'
IMAGE_IMPORT_HASH='2e7255c7222cfe69a2fd115fcb9b05cf4f31bd6cc24af6532718621bce9f112d'
class Stop(RuntimeError):pass
def require(ok,code):
    if not ok:raise Stop(code)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(v):return hashlib.sha256(encoded(v)).hexdigest()
def protected(path,expected=None):
    p=Path(path);require(p.is_absolute()and p.resolve()==p,'EXACT_V35_EXECUTOR_SOURCE_REQUIRED')
    for parent in p.parents:
        s=parent.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==s.st_gid==0 and not s.st_mode&0o022,'PROTECTED_V35_EXECUTOR_SOURCE_ANCESTRY')
    fd=os.open(p,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW)
    try:
        s=os.fstat(fd);pin=lambda v:tuple(getattr(v,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
        require(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o400
            and 0<s.st_size<=131072,'PRIVATE_V35_EXECUTOR_SOURCE_REQUIRED')
        raw=os.read(fd,131073);require(len(raw)==s.st_size and pin(s)==pin(os.fstat(fd))==pin(p.lstat())
            and(expected is None or hashlib.sha256(raw).hexdigest()==expected),'V35_EXECUTOR_SOURCE_BYTES_CHANGED')
    finally:os.close(fd)
    return raw
def module(name,path,expected=None):
    raw=protected(path,expected);m=types.ModuleType(name);m.__file__=str(path);m.__qualified_source_sha256__=hashlib.sha256(raw).hexdigest()
    sys.modules[name]=m;exec(compile(raw,str(path),'exec'),m.__dict__);return m
def label_projection(request,image):
    # Docker merges image label defaults only for keys absent in the request.
    # Bind the exact effective map; never accept a label subset or manager keys.
    wanted=request['Labels'];defaults=image.get('Labels')or{}
    require(type(wanted)is dict and type(defaults)is dict,'EXACT_V35_LABEL_MAPS_REQUIRED')
    additions={key:value for key,value in defaults.items()if key not in wanted}
    require(set(additions)<={'org.opencontainers.image.source'},'UNREVIEWED_V35_IMAGE_METADATA_LABEL_ADDITION')
    merged={**defaults,**wanted}
    require(all(merged[k]==v for k,v in wanted.items()),'ALL_EXPLICIT_V35_LABELS_MUST_BE_PRESERVED')
    return {'profile':'DOCKER_IMAGE_LABEL_DEFAULTS_V1','expectedLabels':merged,'imageDefaultAdditions':additions,'explicitRequestLabelsUnchanged':True}
def image_import_definitions(n,raw):
    require(hashlib.sha256(raw).hexdigest()==IMAGE_IMPORT_HASH,'ORIGINAL_QUALIFIED_V35_IMAGE_IMPORT_SOURCE_REQUIRED')
    values=[ast.literal_eval(node.value)for node in ast.parse(raw).body if isinstance(node,ast.Assign)
        and len(node.targets)==1 and isinstance(node.targets[0],ast.Name)and node.targets[0].id=='FIELDS']
    require(len(values)==1,'ORIGINAL_IMAGE_IMPORT_FIELDS_REQUIRED')
    namespace={'require':require,'FIELDS':values[0],'os':os,'time':time,'signal':signal,
        'subprocess':__import__('subprocess'),'selectors':__import__('selectors')}
    return n.definitions(raw,('matched','load'),namespace)
def create_context(parent,name):
    p=Path(parent);require(p.is_absolute()and p.resolve()==p and re.fullmatch('onboarding-v35-apply-[a-f0-9]{64}',name),'CANONICAL_V35_EXECUTION_CONTEXT_REQUIRED')
    for d in(p,*p.parents):
        s=d.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==s.st_gid==0 and not s.st_mode&0o022,'PROTECTED_V35_CONTEXT_ANCESTRY_REQUIRED')
    fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.mkdir(name,0o700,dir_fd=fd);os.fsync(fd)
    finally:os.close(fd)
    return p/name
def bootstrap():
    n=module('verified_v35_frozen_plan_definitions',HELPER,HELPER_HASH)
    p,q,l,c,d,m,r,configuration,replacement=n.bootstrap()
    root=Path(__file__).resolve().parent
    core=module('verified_v35_execution_protocol',root/'protocol.py')
    ports=module('verified_v35_native_ports',root/'ports.py')
    quarantine=module('verified_v35_quarantine',root/'quarantine.py')
    ports.quarantine=quarantine
    return Context(n,p,q,l,c,d,m,r,configuration,replacement,core,ports,root)
class Context:
    def __init__(self,n,p,q,l,c,d,m,r,configuration,replacement,core,ports,code_root):
        self.n,self.p,self.q,self.l,self.c,self.d,self.m,self.r=n,p,q,l,c,d,m,r
        self.configuration_raw,self.replacement_raw=configuration,replacement;self.core,self.ports_module=core,ports
        self.importer=image_import_definitions(n,protected(code_root/'image_import.py',IMAGE_IMPORT_HASH))
        self.files=m.Facts();self.frozen=self.files.json(FROZEN,FROZEN_HASH)
        completion=self.files.json(Path(FROZEN).parent/'complete.json')
        require(completion['privatePlanHash']==FROZEN_HASH and completion['complete']is True
            and completion['status']=='ONBOARDING_V35_CURRENT_CONFIGURATION_AND_PLAN_FROZEN','COMPLETED_EXACT_FROZEN_V35_PLAN_REQUIRED')
        require(self.frozen['schema']=='ouf.onboarding-v35-frozen-native-plan.v1'and self.frozen['kind']=='FROZEN_PROPOSAL_NOT_EXECUTABLE_AUTHORITY'
            and self.frozen['proposalHash']==n.PROPOSAL_HASH and self.frozen['inputHash']==d.INPUT_HASH
            and self.frozen['targetApplyAuthorized']is False and self.frozen['runtimeAuthorityIssued']is False
            and self.frozen['databaseMigration']['flywayChecksum']==1095739786
            and [v['name']for v in self.frozen['stages']]==list(core.STAGES),'EXACT_V35_PROPOSAL_NOT_OLD_AUTHORITY_REQUIRED')
        for ref in self.frozen['retainedFiles']:self.files.json(ref['path'],ref['sha256'])
        self.inputs=self.files.json(d.INPUT,d.INPUT_HASH)
        require(self.inputs['bootId']==self.frozen['bootId']==Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'SAME_V35_FROZEN_BOOT_REQUIRED')
        self.profile=copy.deepcopy(self.frozen['boundDatabaseProfile']);self.contract,self.manifest,self.image,self.jar=p.packaged(m,self.files)
        oldpath=str(Path(q.OWNER)/'execution-plan.json');mapping={v['path']:v['sha256']for v in self.frozen['retainedFiles']}
        require(oldpath in mapping,'FROZEN_V35_OLD_OWNER_LINEAGE_BINDING_REQUIRED');self.oldplan=self.files.json(oldpath,mapping[oldpath])
        self.source_bindings={str(code_root/'protocol.py'):core.__qualified_source_sha256__,str(code_root/'ports.py'):ports.__qualified_source_sha256__,str(code_root/'quarantine.py'):ports.quarantine.__qualified_source_sha256__,
            str(Path(__file__).resolve()):hashlib.sha256(protected(Path(__file__).resolve())).hexdigest(),HELPER:HELPER_HASH}
        self.source_bindings[str(code_root/'image_import.py')]=IMAGE_IMPORT_HASH
        self.source_bindings[str(Path(HELPER).parent/'configuration.py')]=n.CONFIG_HASH
        self.source_bindings[str(Path(HELPER).parent/'replacement.py')]=n.REPLACEMENT_HASH
        self.preflight_counts={k:0 for k in core.LIMITS};self.before=None;self.native_archive=None;self.native_archive_pin=None
        require(self.frozen['proposedAuthorityDirectory']==str(Path(PARENT)/('onboarding-v35-apply-'+self.frozen['logicalOperationRef'])),
            'ONE_FIXED_V35_LOGICAL_CONTEXT_REQUIRED')
        self.root=create_context(PARENT,Path(self.frozen['proposedAuthorityDirectory']).name)
        m.new_file(self.root,'preparation.claim.json',{'schema':'ouf.onboarding-v35-native-preparation-claim.v1','frozenPlanHash':FROZEN_HASH,
            'logicalOperationRef':self.frozen['logicalOperationRef'],'automaticReplayAllowed':False,'budgetReset':False})
        (self.root/'empty-docker-config').mkdir(mode=0o700)
        from engine_creation import Engine
        self.engine=Engine(self.frozen['engine']['socketPath'],tuple(self.frozen['engine']['socketBinding']))
        previous=r.json_at(r.REVIEW,r.REVIEW_HASH);binding=previous['proposal']['inputsBinding']
        retained=r.json_at(binding['path'],binding['sha256']);self.authority_inputs=retained['review']['authorityInputs']
    def check_sources(self):
        for path,expected in self.source_bindings.items():protected(path,expected)
        self.files.recheck()
        require(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==self.frozen['bootId'],'V35_BOOT_CHANGED')
        require(not os.listdir(self.root/'empty-docker-config'),'CREDENTIAL_FREE_V35_DOCKER_CONFIG_REQUIRED')
    def preflight_reserve(self,kind):
        require(self.preflight_counts[kind]<self.core.LIMITS[kind],'V35_PREFLIGHT_BUDGET_EXHAUSTED')
        self.preflight_counts[kind]+=1;self.m.new_file(self.root,'preflight-'+kind+'-%03d.json'%self.preflight_counts[kind],{'attempt':self.preflight_counts[kind],'attemptNotCompletion':True})
    def inspect(self,cid):
        allowed={self.frozen['replacements']['onboarding']['oldRuntimeBinding']['containerId'],*[v['containerId']for v in self.frozen['unchangedApplications'].values()]}
        require(cid in allowed,'ONLY_FROZEN_V35_PREFLIGHT_IDS');self.preflight_reserve('engineGets')
        status,actual=self.engine.request('GET','/v1.44/containers/'+cid+'/json')
        require(status==200 and actual['Id']==cid,'EXACT_V35_PREFLIGHT_INSPECTION_REQUIRED')
        return actual
    def current_configuration(self):
        from tools.ingestion_readiness_patch_execution import runtime_bindings
        from tools.chatbot_file_cohort.gateway import private_config
        actual=self.inspect(self.frozen['replacements']['onboarding']['oldRuntimeBinding']['containerId'])
        require(runtime_bindings.observed(actual,runtime_bindings.SORTED)==self.frozen['replacements']['onboarding']['oldRuntimeBinding']
            and self.m.process(actual)==self.inputs['currentProcessIdentities']['onboarding'],'CURRENT_V35_OLD_OWNER_GENERATION_REQUIRED')
        peers={}
        for name,binding in self.frozen['unchangedApplications'].items():
            row=self.inspect(binding['containerId']);require(runtime_bindings.observed(row,runtime_bindings.NATIVE)==binding
                and row['State']['Running']is True and self.m.process(row)==self.inputs['currentProcessIdentities'][name],'CURRENT_V35_PEER_GENERATION_REQUIRED');peers[name]=row
        expected=self.frozen['nativeFlywayConfiguration']['ownerOverlays'][0]['binding']
        def owner(path):
            require(path==self.n.OWNER_OVERLAY==expected['path'],'ONLY_NAMED_V35_OWNER_CONFIGURATION');self.preflight_reserve('ownerConfigurationReads')
            return private_config(path,expected)
        def jar(path,checksum,maximum):
            require(path==self.jar['path']and checksum==self.jar['sha256'],'ONLY_V35_CANDIDATE_JAR');return self.p.hash_file(self.m,path,maximum,checksum)
        namespace={'hashlib':hashlib,'json':json,'os':os,'Path':Path,'re':re,'urlsplit':__import__('urllib.parse',fromlist=['urlsplit']).urlsplit,
            'zipfile':__import__('zipfile'),'require':require,'env':lambda rows:self.d.environment({'Config':{'Env':rows}}),'private_file':jar,'private_config':owner}
        verifier=self.n.definitions(self.configuration_raw,('application_json_metadata','owner_json_overlay','overlay_text','additional_location','verify'),namespace)
        identity=self.profile['identity'];binding={'user':identity['runtimeRole'],'database':identity['database'],'schema':identity['schema']}
        result=verifier.verify(actual,{'jar':{'path':self.jar['path'],'sha256':self.jar['sha256']}},peers['postgres'],binding,
            identity['postgresPort'],self.contract['applicationYamlSha256'])
        require(result==self.frozen['nativeFlywayConfiguration'],'SAME_COMPLETE_V35_CONFIGURATION_CLASSIFICATION_REQUIRED')
        self.check_sources();return actual
    def native_image(self,actual):
        import image_custody
        oldaudit=self.oldplan['replacements']['onboarding']['imageAudit']
        require(image_custody.runtime_image_id(oldaudit)==actual['Image'],'CURRENT_ENGINE_IMAGE_IDENTITY_PROFILE_MUST_BE_PROVEN_BY_COMPLETED_OWNER')
        native=oldaudit.get('nativeIdentity')is not None
        if native:require(oldaudit['nativeIdentity']==image_custody.native_identity(oldaudit),'EXACT_EXISTING_NATIVE_IDENTITY_PROFILE_REQUIRED')
        archive=Path(self.p.PACKAGE)/'image.tar.gz';self.native_archive=self.root/'native-image.tar'
        require(shutil.disk_usage(self.root).free>self.contract['archiveBytes']*3+67108864,'V35_NATIVE_IMAGE_PREPARATION_SPACE_REQUIRED')
        fd=os.open(self.native_archive,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
        try:
            with self.m.opened(archive,self.contract['archiveBytes'])as(source_fd,source_stat),os.fdopen(os.dup(source_fd),'rb')as source,gzip.GzipFile(fileobj=source)as expanded,os.fdopen(os.dup(fd),'r+b')as target:
                require(list(self.m.identity(source_stat))==self.image['metadata'],'ORIGINAL_V35_CI_ARCHIVE_CHANGED')
                tarsha,tarsize=image_custody.hashed(expanded,image_custody.LIMIT);expanded.seek(0)
                audit=image_custody.archive(expanded,tarsha,self.contract['imageId'],self.manifest['testedCommit'])
                image_custody.tagless_archive(expanded,target,audit,containerd=native);target.flush();os.fsync(target.fileno())
                target.seek(0);native_sha,native_bytes=image_custody.hashed(target,image_custody.LIMIT)
            if native:audit['nativeIdentity']=image_custody.native_identity(audit)
            native_id=image_custody.runtime_image_id(audit)
            self.native_archive_pin={'path':str(self.native_archive),'sha256':native_sha,'bytes':native_bytes,'metadata':list(self.m.identity(os.fstat(fd)))}
        finally:os.close(fd)
        self.candidate={'nativeImageId':native_id,'configurationImageId':self.contract['imageId'],'sourceCommit':self.manifest['testedCommit'],
            'rootfs':{'type':'layers','diff_ids':[v['diffId']for v in audit['layers']]},'imageConfig':audit['imageConfig']}
        replacement=copy.deepcopy(self.frozen['replacements']['onboarding']);replacement['request']['Image']=native_id
        replacement['imageAudit']=audit;replacement['imageArchive']=copy.deepcopy(self.native_archive_pin)
        projection=label_projection(replacement['request'],audit['imageConfig'])
        image_env=audit['imageConfig'].get('Env')or[];request_env=replacement['request']['Env']
        require(all(type(v)is str and '='in v for v in image_env+request_env)
            and {v.split('=',1)[0]for v in image_env}<={v.split('=',1)[0]for v in request_env},'NO_UNREVIEWED_V35_IMAGE_ENVIRONMENT_DEFAULTS')
        self.native_plan={'runtimeLabelProjection':projection,'schema':'ouf.onboarding-v35-executable-native-plan.v1','frozenPlanHash':FROZEN_HASH,
            'replacement':replacement,'unchangedApplications':copy.deepcopy(self.frozen['unchangedApplications']),
            'engine':self.frozen['engine'],'databaseProfile':self.profile,'nativeFlywayConfiguration':self.frozen['nativeFlywayConfiguration'],
            'candidate':self.candidate,'nativeArchive':self.native_archive_pin,'nativeImageIdentityProfileProven':True,
            'identityRefinementOnly':{'containerdManifestIdentity':native,'configurationImageId':self.contract['imageId'],'nativeImageId':native_id},
            'originalCiArchiveUnchanged':True,'configurationAndLayerBytesUnchanged':True,'imageRebuilt':False,'imageRelabelled':False,
            'humanBudgetOrSourceActivationAuthorized':False}
        same=copy.deepcopy(replacement['request']);same['Image']=self.frozen['replacements']['onboarding']['request']['Image']
        require(same==self.frozen['replacements']['onboarding']['request'],'ONLY_PROVEN_NATIVE_IMAGE_ID_REFINEMENT_ALLOWED')
        self.m.new_file(self.root,'native-image-audit.json',audit);self.m.new_file(self.root,'native-plan.json',self.native_plan)
    def check_native_archive(self):
        pin=self.native_archive_pin
        with self.m.opened(pin['path'],2147483648)as(_,s):require(list(self.m.identity(s))==pin['metadata'],'PREPARED_NATIVE_V35_ARCHIVE_CHANGED')
    def sql(self,after=False):
        base=self.q.query(self.d,self.profile['identity']['runtimeRole'])
        require(base.count(" 'database',current_database()")==1,'EXACT_BASE_V35_READ_ONLY_QUERY_REQUIRED')
        base=base.replace(" 'database',current_database()"," 'databaseBytes',pg_database_size(current_database()), 'database',current_database()")
        if after:
            marker=" 'history',coalesce"
            require(base.count(marker)==1,'EXACT_V35_POST_MIGRATION_QUERY_REQUIRED')
            base=base.replace(marker," 'budgetSessionCount',(SELECT count(*) FROM ouf_onboarding.managed_readiness_budget_session),"+marker)
        return base
    def validate_sql(self,facts,after=False,before=None):
        report=self.d.qualify_snapshot(facts,self.profile)
        require(report['postgres17Utf8']and facts['standby']is False and report['selectedConfigurationMatches']is True
            and report['selectedReviewCount']==1 and report['selectedReadinessAttempts']==3 and report['selectedReadinessGeneration']==4
            and report['selectedReadinessPhase']=='PAUSED'and report['activeReadinessLeases']==0,'CURRENT_V35_DATABASE_SOURCE_PREREQUISITES_REQUIRED')
        identity=self.profile['identity'];roles=[v for v in facts['roles']if v['name']==identity['runtimeRole']]
        require(len(roles)==1 and all(roles[0][k]is False for k in('superuser','createRole','createDb','replication','bypassRls')),'V35_RUNTIME_ROLE_MUST_REMAIN_NARROW')
        cap=facts['capacity'];require(cap['preparedTransactions']==0 and cap['currentConnections']+3<cap['maximumConnections']-cap['reservedForSuperusers'],
            'CURRENT_V35_CONTROL_HEADROOM_REQUIRED')
        if not after:
            history=self.p.assess_history(facts,self.contract);schema=self.p.assess_schema(facts,identity)
            require(history['all34SqlMigrationChecksumsMatchCandidate']and history['allHistoryRowsSuccessful']and history['nonSqlHistoryTypesRecognized']
                and not history['v35AlreadyRecorded']and all(schema.values()),'CURRENT_EXACT_V34_SCHEMA_AND_PRIVILEGES_REQUIRED')
            if before:require(facts['history']==before['history']and facts['selectedReview']==before['selectedReview'],'V35_SOURCE_OR_HISTORY_CHANGED_BEFORE_MIGRATION')
            return report
        require(before is not None,'V35_BEFORE_SNAPSHOT_REQUIRED')
        expected=copy.deepcopy(before['history']);expected.append({'rank':max(v['rank']for v in expected)+1,'version':'35',
            'script':'V35__managed_readiness_budget_sessions.sql','type':'SQL','checksum':1095739786,'success':True})
        require(facts['history']==expected and facts['budgetSessionCount']==0,'ONE_EXACT_V35_HISTORY_APPEND_AND_ZERO_BUDGET_SESSIONS_REQUIRED')
        selected=copy.deepcopy(facts['selectedReview']);require(selected[0].pop('readiness_session_id','ABSENT')is None
            and selected==before['selectedReview'],'ALL_RETAINED_SOURCE_FIELDS_AND_NULL_NEW_SESSION_REQUIRED')
        require(facts['revisionJournalTriggers']==before['revisionJournalTriggers'],'SOURCE_REVISION_APPEND_ONLY_TRIGGER_MUST_REMAIN_UNCHANGED')
        relations_by_name={v['name']:v for v in facts['relations']}
        require(all(relations_by_name.get(v['name'])==v for v in before['relations']),'ALL_RETAINED_RELATIONS_AND_PRIVILEGES_MUST_BE_UNCHANGED')
        filtered=[v for v in facts['columns']if v['relation']!='managed_readiness_budget_session'
            and not(v['relation']=='managed_onboarding_review'and v['name']=='readiness_session_id')]
        require(filtered==before['columns'],'ALL_RETAINED_COLUMN_DEFINITIONS_MUST_BE_UNCHANGED')
        relations={v['name']:v for v in facts['relations']};table=relations.get('managed_readiness_budget_session',{})
        require(table.get('owner')==identity['runtimeRole']and table.get('runtimeOwns')is True,'V35_BUDGET_TABLE_OWNERSHIP_REQUIRED')
        columns={v['name']:v for v in facts['columns']if v['relation']=='managed_onboarding_review'}
        require(columns['readiness_session_id']['type']=='uuid'and columns['readiness_session_id']['notNull']is False
            and columns['readiness_session_id']['default']is None,'V35_NULLABLE_SESSION_COLUMN_REQUIRED')
        constraints={v['name']:v for v in facts['constraints']if v['relation']=='managed_onboarding_review'}
        require('managed_onboarding_review_readiness_attempts_check'not in constraints
            and all(constraints.get(v,{}).get('validated')is True for v in('managed_review_cumulative_attempts_nonnegative',
                'managed_review_legacy_attempt_limit','managed_readiness_same_challenge_session')),'EXACT_V35_REVIEW_CONSTRAINTS_REQUIRED')
        expected_columns={'session_id','challenge_id','tenant_id','subject_id','command_key','request_hash','configuration_hash','decision_ref',
            'reason','profile','base_attempts','prior_generation','prior_started_at','prior_phase','prior_last_code','prior_session_id',
            'maximum_attempts','maximum_elapsed_seconds','issued_at','expires_at','state'}
        require({v['name']for v in facts['columns']if v['relation']=='managed_readiness_budget_session'}==expected_columns,'EXACT_V35_BUDGET_TABLE_COLUMN_SET_REQUIRED')
        return report
    def preflight_sql(self):
        from tools.ingestion_readiness_patch_execution.database_read import bounded_read
        require(self.preflight_counts['sqlSessions']==0,'ONE_V35_PREFLIGHT_SQL_ONLY');self.preflight_reserve('sqlSessions')
        argv=self.q.arguments(self.d,self.profile,self.root/'empty-docker-config');argv[-1]=self.sql()
        status,raw,_=bounded_read(argv);require(status==0 and 0<len(raw)<=524288,'V35_FRESH_PREFLIGHT_SQL_UNPROVEN')
        facts=self.m.decode(raw);self.validate_sql(facts);self.before=facts;self.m.new_file(self.root,'before-database.json',raw)
        return facts
def operator(ctx):
    from tools.semantic_registry_recovery_execution.postboot_authority import authority_metadata
    from tools.semantic_lease_recovery.recovery_journal import Journal
    core=ctx.core;ctx.check_sources();print(encoded({'schema':'ouf.onboarding-v35-progress.v1','phase':'PREFLIGHT_CURRENT_CONFIGURATION_AND_NATIVE_IMAGE','runtimeEffectsDispatched':0}).decode(),flush=True)
    actual=ctx.current_configuration();ctx.native_image(actual);before=ctx.preflight_sql()
    bound=min(1073741824,max(67108864,2*before['databaseBytes']+33554432))
    require(shutil.disk_usage(ctx.root).free>bound+16777216,'V35_QUIESCED_BACKUP_SPACE_REQUIRED')
    profile,policy=authority_metadata(ctx.authority_inputs)
    closure={path:expected for path,expected in sorted(ctx.source_bindings.items())}
    review={'schema':'ouf.onboarding-v35-native-review.v1','executionRoot':str(ctx.root),'frozenPlanHash':FROZEN_HASH,
        'nativePlan':ctx.native_plan,'nativePlanHash':core.digest(ctx.native_plan),'sourceClosure':closure,'sourceClosureHash':core.digest(closure),
        'logicalOperationRef':ctx.frozen['logicalOperationRef'],'bootId':ctx.frozen['bootId'],'maximumSeconds':900,
        'negativeCleanup':{'maximumAdditionalSeconds':30,'startupSeconds':180,'candidateStopOnly':True,'maximumStops':1},
        'maximums':copy.deepcopy(core.LIMITS),'stages':list(core.STAGES),'maximumBackupBytes':bound,
        'preflightCounts':copy.deepcopy(ctx.preflight_counts),'beforeDatabaseHash':core.digest(before),
        'sqlQueryHashes':{'before':hashlib.sha256(ctx.sql().encode()).hexdigest(),'after':hashlib.sha256(ctx.sql(True).encode()).hexdigest()},
        'verification':{'trustPolicy':ctx.authority_inputs['trustPolicy'],'openssl':ctx.authority_inputs['executables']['openssl'],'context':ctx.authority_inputs['context']},
        'databaseRestoreAuthorized':False,'humanBudgetOrSourceActivationAuthorized':False,'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False}
    core.validate_review(review);ctx.m.new_file(ctx.root,'review.json',review)
    decision=core.terminal_decision(review,ctx.root/'review.json')
    require(ctx.r.json_at(ctx.root/'review.json',core.digest(review))==review,'V35_REVIEW_CHANGED_DURING_TERMINAL_DECISION')
    ctx.current_configuration();require(authority_metadata(ctx.authority_inputs)==(profile,policy),'CURRENT_V35_INSTALLATION_POLICY_CHANGED')
    gate=core.issue(review,ctx.root,profile,decision,ctx.m.new_file,ctx.r.json_at)
    print(encoded({'schema':'ouf.onboarding-v35-issued.v1','reviewHash':core.digest(review),'authorityHash':core.sha(gate.raw),
        'runtimeAuthorityIssued':True,'runtimeEffectsDispatched':0,'automaticReplayAllowed':False,'budgetReset':False}).decode(),flush=True)
    ports=ctx.ports_module.NativePorts(core,ctx,ctx.root,review,gate);execution=core.Execution(gate,Journal(ctx.root),ports);execution.initialize()
    try:
        ctx.watchdog_pid=ctx.ports_module.quarantine.launch(ctx,review,gate,execution.journal)
        result=execution.run()
    except BaseException:
        try:ctx.ports_module.quarantine.stop_unproven(ctx,review,gate.raw,execution.journal,'CONTROLLER_STOPPED')
        except BaseException:
            ctx.m.new_file(ctx.root,'controller-quarantine-unproven.json',{'status':'STOP_RECONCILE','negativeEffectMayBePartial':True,'automaticReplayAllowed':False})
        raise
    from tools.semantic_provider_deployment_signing import ExistingEd25519Signer
    context=review['verification']['context'];signer=ExistingEd25519Signer(profile['keyBindings']['attestor'],profile['keyRefs']['attestor'],gate.verifier,
        {'role':'CREATION_ATTESTATION','issuerRef':context['attestorRef'],'installationRef':context['installationRef'],'entityRef':context['entityRef']})
    gate.check();ctx.m.new_file(ctx.root,'result.json',result);core.authentication_file(ctx.root/'authority',core.sha(core.encoded(result))+'.CREATION_ATTESTATION.json',signer.sign(core.encoded(result)))
    require(gate.verifier(core.encoded(result),'CREATION_ATTESTATION',context['attestorRef'],context['installationRef'],context['entityRef'])is True,'SIGNED_V35_FINAL_RECEIPT_REQUIRED')
    return result
def main():
    ctx=None
    try:
        require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
            and len(sys.argv)==1,'ONE_ISOLATED_ROOT_V35_NATIVE_EXECUTION_REQUIRED')
        def cancelled(*_):raise Stop('V35_NATIVE_EXECUTION_INTERRUPTED_RECONCILE_ONLY')
        for sig in(signal.SIGINT,signal.SIGTERM,signal.SIGHUP):signal.signal(sig,cancelled)
        ctx=bootstrap();result=operator(ctx)
    except Exception as error:
        reason=str(error)if type(error).__name__ in ('Stop','Denied','CreationDenied','ImageCustodyDenied')and re.fullmatch('[A-Z0-9_]{1,120}',str(error))else'V35_NATIVE_EXECUTION_UNPROVEN'
        result={'schema':'ouf.onboarding-v35-native-update-result.v1','status':'STOP_RECONCILE','complete':False,'reasonCode':reason,
            'contextPath':str(ctx.root)if ctx else None,'runtimeEffectsMayBePartial':True,'humanBudgetsGranted':0,'sourceActivations':0,
            'originalRequestRepeated':False,'credentialValuesPrinted':False,'addressesPrinted':False,'automaticReplayAllowed':False,
            'automaticRollbackPerformed':False,'budgetReset':False,'releaseAcceptance':False}
    print(encoded(result).decode(),flush=True);return 0 if result.get('complete')is True else 2
if __name__=='__main__':raise SystemExit(main())

