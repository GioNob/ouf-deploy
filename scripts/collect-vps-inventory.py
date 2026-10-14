#!/usr/bin/python3
"""Single finite resource-read-only OUF inventory. No rollout, login or retry.

Only redacted metadata is emitted. Unknown/error areas never become PASS.
Docker exec starts short-lived read processes; no container lifecycle changes.
Audit output/temporary files are the only host writes.
"""
import argparse
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import resource
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit, unquote

BASE=Path('/etc/ouf/deploy-snapshots')
REVIEW='92b3276992b3b3ec459e734196671728b8a49a99a02185e2c6f7c1da87ce82a1'
DECLARATION='fc94b491d05e267b49da6e2e2fe50cc7e02e7986783bad7ebf1289b0914a0a68'
CREATION='59181588fd8bbc0836f892789156532ebcc1cce304197560ca1274f05267d552'
INTAKE='395c92d7bcb8dadfa3bb248a3e94b37bd36a396cc07c16ee5d1d57a646e00239'
NATIVE=BASE/'semantic-native-v11-intake-9ec18cf053e5925e42df93b75990343cc1d09696975fc2a224d76b4b28becdae'
EXPECTED=('ouf-semantic','ouf-onboarding','ouf-ingestion','ouf-udp','ouf-mcp','ouf-postgres','ouf-keycloak','ouf-apisix','ouf-gateway-control-plane')
IDENT=re.compile(r'[A-Za-z_][A-Za-z0-9_]{0,62}')
CODE=re.compile(r'[A-Z][A-Z0-9_]{1,159}')
MAX_SECONDS=240
CAPABILITIES=('ouf.managed-source.file.upload','ouf.managed-source.file.profile','ouf.managed-source.onboarding.create','ouf.managed-source.onboarding.review.prepare','ouf.managed-source.onboarding.read','ouf.semantic.propose','ouf.semantic.review.prepare','ouf.semantic.proposal.read','ouf.semantic.consultation.read','ouf.semantic.review','ouf.semantic.approve','ouf.semantic.publish','ouf.onboarding.configuration.write','urban.object.search')

def need(ok,code):
    if not ok:raise ValueError(code)
def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(value):return hashlib.sha256(encoded(value)).hexdigest()
def safe_error(error):
    text=str(error)
    return text if type(error) is ValueError and CODE.fullmatch(text) else type(error).__name__
def ident(value):
    need(type(value) is str and IDENT.fullmatch(value),'DATABASE_IDENTIFIER_UNSUPPORTED')
    return '"'+value+'"'
def literal(value):return "'"+value.replace("'","''")+"'"
def environment(row):
    result={}
    for item in row.get('Config',{}).get('Env') or []:
        need(type(item) is str and '=' in item,'ENVIRONMENT_METADATA_UNREADABLE')
        key,value=item.split('=',1);need(key not in result,'DUPLICATE_ENVIRONMENT_METADATA')
        result[key]=value
    return result
def binding(row):
    return {'containerId':row['Id'],'imageId':row['Image'],'pid':row['State']['Pid'],
        'startedAt':row['State']['StartedAt'],'configHash':digest(row['Config']),
        'hostConfigHash':digest(row['HostConfig']),'mountsHash':digest(row['Mounts']),
        'networkSettingsHash':digest(row['NetworkSettings'])}
def named_changes(old,new):
    keys=set(old)|set(new)
    return sorted(k for k in keys if re.fullmatch(r'[A-Za-z0-9_.-]{1,100}',k) and old.get(k)!=new.get(k))
def compare(old,new):
    a,b=binding(old),binding(new)
    changed=[key for key in a if a[key]!=b[key]]
    return {'equal':not changed,'changedBindingFields':changed,
        'historicalBinding':a,'currentBinding':b,
        'changedConfigKeys':named_changes(old['Config'],new['Config']),
        'changedHostConfigKeys':named_changes(old['HostConfig'],new['HostConfig']),
        'changedEnvironmentNames':named_changes(environment(old),environment(new)),
        'changedNetworkSettingsKeys':named_changes(old['NetworkSettings'],new['NetworkSettings']),
        'mountsChanged':old['Mounts']!=new['Mounts'],'valuesDisclosed':False}
def file_bytes(path,expected=None,limit=2097152,root_private=False):
    path=Path(path);need(path.is_absolute() and '..' not in path.parts,'ABSOLUTE_SELECTED_FILE_REQUIRED')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size<=limit,
             'BOUNDED_REGULAR_SELECTED_FILE_REQUIRED')
        if root_private:
            need(before.st_uid==before.st_gid==0 and stat.S_IMODE(before.st_mode)==0o600,'PRIVATE_ROOT_SNAPSHOT_REQUIRED')
        raw=b''
        while len(raw)<=limit:
            part=os.read(fd,min(65536,limit+1-len(raw)))
            if not part:break
            raw+=part
        def pin(s):return (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_mode,s.st_uid,s.st_gid)
        need(len(raw)==before.st_size and pin(before)==pin(os.fstat(fd))==pin(path.lstat()),'SELECTED_FILE_CHANGED_DURING_READ')
        sha=hashlib.sha256(raw).hexdigest()
        need(expected is None or sha==expected,'SELECTED_HISTORICAL_HASH_MISMATCH')
        return raw,{'sha256':sha,'uid':before.st_uid,'gid':before.st_gid,'mode':oct(stat.S_IMODE(before.st_mode)),'bytes':len(raw)}
    finally:os.close(fd)
def failure(code,diagnostic):
    match=re.search(rb'(?:ERROR|FATAL):\s+([0-9A-Z]{5}):',diagnostic)
    return {'exitCode':code,'sqlstate':match[1].decode() if match else None,'rawDiagnosticPrinted':False}
def limit_output():resource.setrlimit(resource.RLIMIT_FSIZE,(8388609,8388609))

def admin_key(raw):
    lines=raw.decode().splitlines();entries=[(i,len(v)-len(v.lstrip(' '))) for i,v in enumerate(lines) if re.fullmatch(r' *admin_key: *(?:#.*)?',v)]
    need(len(entries)==1,'ONE_ADMIN_KEY_SECTION_REQUIRED');start,depth=entries[0];records=[];row=None
    for line in lines[start+1:]:
        if not line.strip() or line.lstrip().startswith('#'):continue
        if len(line)-len(line.lstrip(' '))<=depth:break
        m=re.fullmatch(r' +(- +)?(name|key|role): *(.*?) *',line);need(m is not None,'ADMIN_KEY_SYNTAX_UNSUPPORTED')
        if m[1]:
            if row is not None:records.append(row)
            row={}
        need(row is not None and m[2] not in row,'AMBIGUOUS_ADMIN_KEY_RECORD')
        value=m[3]
        if value.startswith('"'):value=json.loads(value)
        elif value.startswith("'"):
            need(value.endswith("'"),'ADMIN_KEY_LITERAL_REQUIRED');value=value[1:-1]
        need(type(value) is str and re.fullmatch('[A-Za-z0-9._=+-]{1,4096}',value),'ADMIN_KEY_LITERAL_REQUIRED')
        row[m[2]]=value
    if row is not None:records.append(row)
    if not records:
        key,meta=file_bytes('/opt/ouf/secrets/apisix-admin-key',limit=8192)
        key=key.decode('ascii').strip()
        need(re.fullmatch('[A-Za-z0-9._=+-]{1,4096}',key),'EXTERNAL_ADMIN_KEY_UNSUPPORTED');return key
    need(len(records)<=8 and all(set(v)=={'name','key','role'} for v in records),'ADMIN_KEY_RECORD_UNSUPPORTED')
    admins=[v for v in records if v['role']=='admin'];need(len(admins)==1,'ONE_ADMIN_KEY_REQUIRED');return admins[0]['key']

HTTP_READ_PROGRAM="""import sys,json,http.client,ctypes,os
x=json.load(sys.stdin);fd=int(sys.argv[1]);lib=ctypes.CDLL(None,use_errno=True)
if lib.setns(fd,0)!=0:raise OSError(ctypes.get_errno(),'NETNS_READ_FAILED')
os.close(fd);c=http.client.HTTPConnection('127.0.0.1',9180,timeout=5)
c.request('GET','/apisix/admin/routes',headers={'X-API-KEY':x['key']})
r=c.getresponse();body=r.read(8388609)
if len(body)>8388608:raise ValueError('ROUTE_REPLY_UNBOUNDED')
print(json.dumps({'status':r.status,'body':json.loads(body)}));c.close()
"""

class Native:
    def __init__(self,docker,config,seconds=MAX_SECONDS):
        self.docker=str(docker);self.config=str(config);self.deadline=time.monotonic()+seconds;self.calls=0
        self.binary_hash=hashlib.sha256(Path(docker).read_bytes()).hexdigest()
        self.socket=Path('/var/run/docker.sock').resolve();s=self.socket.stat()
        need(stat.S_ISSOCK(s.st_mode) and s.st_uid==0,'ROOT_LOCAL_ENGINE_REQUIRED')
        self.socket_pin=(s.st_dev,s.st_ino)
    def remaining(self):
        left=self.deadline-time.monotonic();need(left>0,'INVENTORY_BUDGET_EXHAUSTED');return min(12,left)
    def run(self,args,data=None):
        self.remaining()
        s=self.socket.stat();need((s.st_dev,s.st_ino)==self.socket_pin,'ENGINE_SOCKET_CHANGED')
        need(args and args[0] in ('inspect','ps','info','exec','network','image'),'NON_READ_DOCKER_OPERATION_DENIED')
        if args[0]=='network':need(args[1]=='inspect','NON_READ_NETWORK_OPERATION_DENIED')
        if args[0]=='image':need(args[1]=='inspect','NON_READ_IMAGE_OPERATION_DENIED')
        return self.command([self.docker,'--host','unix://'+str(self.socket),'--config',self.config,*args],data)
    def command(self,args,data=None,pass_fds=()):
        self.calls+=1;need(self.calls<=128,'INVENTORY_CALL_LIMIT_EXHAUSTED')
        with tempfile.TemporaryFile() as out,tempfile.TemporaryFile() as err:
            try:
                input_args={'stdin':subprocess.DEVNULL} if data is None else {'input':data}
                result=subprocess.run(args,**input_args,stdout=out,stderr=err,timeout=self.remaining(),
                    env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'},preexec_fn=limit_output,pass_fds=pass_fds)
            except subprocess.TimeoutExpired:raise ValueError('NATIVE_READ_TIMEOUT') from None
            need(out.tell()<=8388608 and err.tell()<=262144,'NATIVE_READ_OUTPUT_LIMIT')
            out.seek(0);err.seek(0);return result.returncode,out.read(),err.read()
    def json(self,args):
        code,raw,err=self.run(args);need(code==0,'NATIVE_METADATA_READ_FAILED');return json.loads(raw)
    def inspect(self,cid):
        rows=self.json(['inspect','--type=container',cid]);need(len(rows)==1,'ONE_CONTAINER_REQUIRED');return rows[0]
    def query(self,pg,user,db,expression):
        ident(user);ident(db)
        sql=("\\set VERBOSITY verbose\nBEGIN READ ONLY; SET LOCAL statement_timeout='7s'; SET LOCAL lock_timeout='1s';\n"
            "SELECT json_build_object('transactionReadOnly',current_setting('transaction_read_only')='on','value',("+expression+"));\nROLLBACK;\n").encode()
        args=['exec','-i',pg,'env','PGAPPNAME=ouf-integration-inventory','PGOPTIONS=-c default_transaction_read_only=on',
              'psql','-X','-w','-q','-A','-t','-v','ON_ERROR_STOP=1','-U',user,'-d',db]
        code,raw,err=self.run(args,sql)
        if code:raise ValueError('PG_READ_FAILED_'+(failure(code,err)['sqlstate'] or 'UNKNOWN'))
        result=json.loads(raw);need(result.get('transactionReadOnly') is True,'READ_ONLY_TRANSACTION_NOT_PROVEN')
        return result['value']

def container_summary(row):
    state=row['State'];env=environment(row)
    labels=row['Config'].get('Labels') or {};revision=labels.get('org.opencontainers.image.revision')
    return {'binding':binding(row),'running':state.get('Running'),'paused':state.get('Paused'),
        'status':state.get('Status') if state.get('Status') in ('running','paused','exited','created','dead','restarting') else 'UNKNOWN',
        'imageRevision':revision if type(revision) is str and re.fullmatch('[0-9a-f]{40}',revision) else None,
        'environmentCount':len(env),'springExternalConfigChannels':[k for k in ('SPRING_CONFIG_IMPORT','SPRING_CONFIG_LOCATION','SPRING_CONFIG_ADDITIONAL_LOCATION','SPRING_APPLICATION_JSON') if env.get(k)],
        'mountCount':len(row['Mounts']),'networkCount':len(row['NetworkSettings'].get('Networks',{})),
        'restartPolicy':row['HostConfig'].get('RestartPolicy'),'userConfigured':bool(row['Config'].get('User'))}
def selected_configs(row):
    selected=[]
    targets={'/run/secrets/onboarding-ths.yaml','/run/secrets/ingestion-summary.properties','/usr/local/apisix/conf/config.yaml'}
    for mount in row['Mounts']:
        if mount.get('Destination') not in targets:continue
        raw,meta=file_bytes(mount['Source']);text=raw.decode('utf-8')
        # Key names only. Never emit YAML/properties scalar values or source paths.
        if text.lstrip().startswith('{'):
            parsed=json.loads(text)
            def flatten(v,prefix=''):
                keys=[]
                if type(v) is dict:
                    for key,value in v.items():
                        if not re.fullmatch('[A-Za-z0-9_.-]{1,100}',key):continue
                        name=prefix+'.'+key if prefix else key;keys.append(name);keys+=flatten(value,name)
                return keys
            keys=flatten(parsed)
        else:keys=[m[1] for line in text.splitlines() if (m:=re.match(r'^\s*([A-Za-z_][A-Za-z0-9_.-]{0,99})\s*[:=]',line))]
        selected.append({'target':mount['Destination'],'readOnly':mount.get('RW') is False,'metadata':meta,
                         'configurationKeys':sorted(set(keys))[:512],'keysTruncated':len(set(keys))>512,'scalarValuesPrinted':False})
    return selected
def db_selector(module,row,pg):
    env=environment(row);prefix={'semantic':'OUF_SEM','onboarding':'OUF_ONB','ingestion':'OUF_ING','udp':'OUF_UDP'}.get(module)
    raw=env.get('MCP_DATABASE_URL','') if module=='mcp' else env.get(prefix+'_DB_URL','')
    parsed=urlsplit(raw.removeprefix('jdbc:'));need(parsed.scheme in ('postgres','postgresql'),'DB_SELECTOR_UNAVAILABLE')
    user=unquote(parsed.username or '') if module=='mcp' else env.get(prefix+'_DB_USER','')
    db=unquote(parsed.path)[1:];ident(user);ident(db)
    network=pg['NetworkSettings']['Networks']['ouf-backend']
    peers={pg['Name'].lstrip('/'),pg['Config'].get('Hostname'),network.get('IPAddress'),*(network.get('Aliases') or [])}
    need(parsed.hostname in peers and parsed.port in (None,5432) and not parsed.query,
         'DB_PEER_OR_QUERY_REQUIRES_REVIEW')
    schema='ouf_sem' if module=='semantic' else 'ouf_'+module
    return user,db,schema
def db_inventory(native,pg,module,row):
    user,db,schema=db_selector(module,row,pg);q=ident(schema)
    identity=native.query(pg['Id'],user,db,"SELECT json_build_object('oid',oid::bigint,'allowConnections',datallowconn,'prepared',(SELECT count(*) FROM pg_prepared_xacts WHERE database=current_database()),'serverVersion',current_setting('server_version_num')::int) FROM pg_database WHERE datname=current_database()")
    history=("SELECT COALESCE(json_agg(json_build_object('version',version,'checksum',checksum) ORDER BY version),'[]'::json) FROM "+q+'.schema_migration' if module=='mcp' else "SELECT COALESCE(json_agg(json_build_object('version',version,'script',script,'type',type,'checksum',checksum,'success',success) ORDER BY installed_rank),'[]'::json) FROM "+q+'.flyway_schema_history')
    migrations=native.query(pg['Id'],user,db,history);need(type(migrations) is list and len(migrations)<=256,'MIGRATION_HISTORY_UNBOUNDED')
    for item in migrations:
        for key in ('script','type','version'):
            if key in item and item[key] is not None:
                need(type(item[key]) in (str,int) and re.fullmatch('[A-Za-z0-9_.-]{1,150}',str(item[key])),'MIGRATION_METADATA_UNSUPPORTED')
    admin=environment(pg).get('POSTGRES_USER');admin_info={'explicitBootstrapConfigured':bool(admin)}
    if admin:
        ident(admin)
        admin_info=native.query(pg['Id'],admin,db,"SELECT json_build_object('superuser',rolsuper,'roleExists',true,'postgresRoleExists',EXISTS(SELECT 1 FROM pg_roles WHERE rolname='postgres')) FROM pg_roles WHERE rolname=current_user")
        if module=='mcp':
            role=literal(user)
            admin_info['incident']=native.query(pg['Id'],admin,db,"SELECT json_build_object('exists',true,'oid',oid::bigint,'ownerHash',md5(pg_get_userbyid(relowner)),'aclHash',md5(COALESCE(relacl::text,'')),'workloadOwnerAuthority',pg_has_role((SELECT oid FROM pg_roles WHERE rolname="+role+"),relowner,'USAGE'),'workloadTrigger',has_table_privilege("+role+",oid,'TRIGGER')) FROM pg_class WHERE oid=to_regclass('ouf_mcp.security_incident')")
    return {'identity':identity,'migrationCount':len(migrations),'migrations':migrations,'historyHash':digest(migrations),
        'administration':admin_info,'selectorSource':'CONTAINER_ENV_BASELINE','effectiveExternalOverridesValidated':False,
        'transactionReadOnly':True,'rowValuesRead':False}

class Inventory:
    def __init__(self,native):self.native=native;self.areas={};self.raw={};self.rows={}
    def check(self,name,read):
        try:
            self.native.remaining();value=read();self.areas[name]={'status':'OBSERVED','data':value};return value
        except Exception as error:self.areas[name]={'status':'UNAVAILABLE','reason':safe_error(error)};return None
    def historical(self,key,path,sha):
        raw,meta=file_bytes(path,sha,root_private=True);self.raw[key]=json.loads(raw)
        return {'metadata':meta,'expectedHashMatched':True}
    def collect(self):
        info=self.check('engine',lambda:self.native.json(['info','--format','{{json .}}']))
        if info is not None:self.areas['engine']['data']={k:info.get(k) for k in ('ServerVersion','Driver','CgroupDriver','DockerRootDir','Containers','ContainersRunning','NCPU','MemTotal')}
        native_projection=self.check('activeProjection',lambda:self.projection())
        self.check('historicalReview',lambda:self.historical('review',BASE/('semantic-candidate-installation-input-review-'+REVIEW+'.private.json'),REVIEW))
        self.check('historicalDeclaration',lambda:self.historical('declaration',NATIVE/'private-runtime-declaration.json',DECLARATION))
        self.check('historicalCreationRequest',lambda:self.historical('creation',NATIVE/'creation-request.private.json',CREATION))
        self.check('coordinationIntake',lambda:self.historical('intake',BASE/('semantic-native-v11-intake-'+INTAKE)/'intake.json',INTAKE))
        listing=self.check('containerInventory',lambda:self.container_inventory())
        # Independent fallback selection permits DB/config observations even if listing fails.
        for name in EXPECTED:
            if name not in self.rows:
                row=self.check('container/'+name,lambda name=name:self.native.inspect(name))
                if row is not None:self.rows[name]=row;self.areas['container/'+name]['data']=container_summary(row)
        for name,row in list(self.rows.items()):
            self.check('config/'+name,lambda row=row:selected_configs(row))
            self.check('image/'+name,lambda row=row:self.image(row))
        if 'declaration' in self.raw:
            old=self.raw['declaration'].get('retainedNativeCreationFrame')
            if type(old) is dict:
                actual=self.check('exactRetainedRegistryRead',lambda:self.native.inspect(old['Id']))
                if actual is not None:
                    self.areas['exactRetainedRegistryRead']['data']=container_summary(actual)
                    self.check('registryHistoricalComparison',lambda:compare(old,actual))
                    self.check('registryNativeRunc',lambda:self.runc(actual))
        pg=self.rows.get('ouf-postgres')
        if pg:
            for module in ('semantic','onboarding','ingestion','udp','mcp'):
                row=self.rows.get('ouf-'+module)
                if row:self.check('database/'+module,lambda module=module,row=row:db_inventory(self.native,pg,module,row))
        self.check('networks',lambda:self.networks())
        if 'ouf-keycloak' in self.rows:self.check('iamEffectiveCatalogue',lambda:self.iam_catalogue())
        if 'ouf-apisix' in self.rows:self.check('gatewayLiveRoutes',lambda:self.gateway_routes())
        if pg and 'ouf-onboarding' in self.rows:self.check('ownerActiveGrants',lambda:self.owner_grants(pg))
        if pg and 'ouf-onboarding' in self.rows:self.check('existingTeatriInput',lambda:self.existing_input(pg))
        self.check('retainedRecoveryHistory',lambda:self.retained_history())
        for name,reason in [('currentRuntimeAuthorityLedger','EXACT_CURRENT_LEDGER_SELECTION_REQUIRED'),
                ('freshMcpRead','CONVERSATION_CONNECTOR_ROUTING_UNAVAILABLE')]:
            self.areas[name]={'status':'NOT_COLLECTED','reason':reason}
        self.check('stableAllContainers',lambda:self.stability())
        self.check('stableNativeTool',lambda:self.tool_stability())
        missing=[name for name,area in self.areas.items() if area['status']!='OBSERVED']
        comparison=self.areas.get('registryHistoricalComparison',{}).get('data',{})
        return {'schema':'ouf.vps-read-only-inventory.v1','status':'NATIVE_INVENTORY_COLLECTED_COVERAGE_GAPS_REMAIN',
            'completeEnvironmentInventory':False,'areas':self.areas,'unavailableAreas':missing,
            'registryChangedBindingFields':comparison.get('changedBindingFields'),
            'maximumElapsedSeconds':MAX_SECONDS,'maximumNativeCalls':128,'nativeCalls':self.native.calls,
            'automaticRetry':False,'applicationWrites':0,'databaseMutations':0,'iamResourceMutations':0,
            'serviceMutations':0,'containerLifecycleOperations':0,'interactiveAuthenticationAttempted':False,
            'cachedIamGetMayRefreshAdministrativeSession':True,
            'runtimeAuthorityIssued':False,'budgetReset':False,'chatbotEndToEndProven':False,'notReleaseAcceptance':True}
    def projection(self):
        raw,meta=file_bytes('/opt/ouf/installation/active-projection.json');v=json.loads(raw)
        return {'metadata':meta,'gatewayIssuerConfigured':bool(v.get('gateway',{}).get('issuerUrl')),
            'publicApiOriginConfigured':bool(v.get('gateway',{}).get('publicApiBaseUrl')),
            'mcpWorkloadClientConsistent':v.get('iam',{}).get('workloadClients',{}).get('mcpServer')==v.get('mcp',{}).get('environment',{}).get('MCP_OIDC_CLIENT_ID'),
            'credentialValuesPrinted':False}
    def container_inventory(self):
        code,raw,err=self.native.run(['ps','-a','--no-trunc','--format','{{.ID}}']);need(code==0,'CONTAINER_LIST_UNAVAILABLE')
        ids=raw.decode().splitlines();need(len(ids)<=64 and all(re.fullmatch('[0-9a-f]{64}',cid) for cid in ids),'CONTAINER_INVENTORY_LIMIT')
        summaries={};ignored=0
        for cid in ids:
            row=self.native.inspect(cid);name=row['Name'].lstrip('/')
            if re.fullmatch(r'ouf-[a-z0-9_-]{1,80}',name):self.rows[name]=row;summaries[name]=container_summary(row)
            else:ignored+=1
        return {'oufContainers':summaries,'otherContainerCount':ignored,'otherNamesDisclosed':False}
    def image(self,row):
        rows=self.native.json(['image','inspect',row['Image']]);need(len(rows)==1,'ONE_IMAGE_REQUIRED');v=rows[0]
        return {'id':v['Id'],'size':v.get('Size'),'created':v.get('Created'),
            'repoDigestCount':len(v.get('RepoDigests') or []),'rootfsLayersHash':digest(v.get('RootFS',{}).get('Layers')),
            'imageConfigHash':digest(v.get('Config',{})),'imageMatchesContainer':v['Id']==row['Image']}
    def runc(self,actual):
        intake=self.raw['intake'];directory=BASE/('semantic-native-v11-intake-'+INTAKE)
        raw,_=file_bytes(directory/'retained-execution-configuration.json',intake['fileHashes']['retained-execution-configuration.json'],root_private=True)
        execution=json.loads(raw);ab=execution['runtimeAdapterBinding'];raw,_=file_bytes(ab['path'],ab['sha256'],root_private=True);adapter=json.loads(raw)
        path=Path(adapter['runtimePath']);need(path.is_absolute(),'ABSOLUTE_RUNC_REQUIRED')
        raw,_=file_bytes(path,adapter['runtimeSha256'],limit=64000000)
        need(path.stat().st_uid==0 and not path.stat().st_mode&0o022 and path.stat().st_mode&0o111,'ROOT_RUNC_REQUIRED')
        def read():
            code,body,err=self.native.command([str(path),'--root','/run/docker/runtime-runc/moby','state',actual['Id']]);need(code==0,'RUNC_READ_UNAVAILABLE');return json.loads(body)
        first=read();second=read();cid=actual['Id'];bundle=first.get('bundle')
        profiles={'/run/containerd/io.containerd.runtime.v2.task/moby/'+cid:'SYSTEM_CONTAINERD','/run/docker/containerd/daemon/io.containerd.runtime.v2.task/moby/'+cid:'DOCKER_MANAGED_CONTAINERD'}
        return {'idMatched':first.get('id')==cid,'pidMatched':first.get('pid')==actual['State']['Pid'],'running':first.get('status')=='running','bundleProfile':profiles.get(bundle,'UNKNOWN'),'stableDoubleRead':first==second}
    def networks(self):
        ids=sorted({net['NetworkID'] for row in self.rows.values() for net in row['NetworkSettings'].get('Networks',{}).values()})
        result=[]
        for netid in ids:
            v=self.native.json(['network','inspect',netid])[0]
            result.append({'id':v['Id'],'name':v['Name'] if re.fullmatch('ouf-[A-Za-z0-9_-]{1,80}',v['Name']) else None,
                'driver':v.get('Driver'),'internal':v.get('Internal'),'enableIPv6':v.get('EnableIPv6'),
                'endpointCount':len(v.get('Containers',{})),'ipamHash':digest(v.get('IPAM',{}))})
        return result
    def stability(self):
        changed=[]
        for name,row in self.rows.items():
            fresh=self.native.inspect(row['Id'])
            if binding(fresh)!=binding(row):changed.append(name)
        return {'allStable':not changed,'changedContainers':changed}
    def tool_stability(self):
        need(hashlib.sha256(Path(self.native.docker).read_bytes()).hexdigest()==self.native.binary_hash,'DOCKER_EXECUTABLE_CHANGED')
        return {'dockerHash':self.native.binary_hash,'unchanged':True}
    def iam_catalogue(self):
        cid=self.rows['ouf-keycloak']['Id']
        def get(path,fields):
            need(re.fullmatch('[A-Za-z0-9_/-]{1,180}',path),'IAM_READ_PATH_UNSUPPORTED')
            return self.native.json(['exec',cid,'/opt/keycloak/bin/kcadm.sh','get',path,'-r','ouf','--fields',fields])
        clients=get('clients','id,clientId,enabled,publicClient,serviceAccountsEnabled')
        scopes=get('client-scopes','id,name,protocol')
        need(type(clients) is list and len(clients)<=256 and type(scopes) is list and len(scopes)<=512,'IAM_INVENTORY_UNBOUNDED')
        selected=[]
        for item in clients:
            name=item.get('clientId','')
            if name not in ('ouf-chatgpt','ouf-ths','ouf-mcp','ouf-mcp-server','ouf-semantic','ouf-onboarding','ouf-ingestion','ouf-udp','ouf-gateway'):continue
            uid=item['id'];need(re.fullmatch('[a-fA-F0-9-]{36}',uid),'IAM_CLIENT_ID_UNSUPPORTED')
            defaults=get('clients/'+uid+'/default-client-scopes','name')
            optional=get('clients/'+uid+'/optional-client-scopes','name')
            def names(rows):
                need(type(rows) is list and len(rows)<=512,'IAM_SCOPE_REPLY_UNBOUNDED')
                return sorted(v['name'] for v in rows if type(v.get('name')) is str and re.fullmatch('[A-Za-z0-9_.:-]{1,150}',v['name']))
            selected.append({'clientId':name,'enabled':item.get('enabled'),'publicClient':item.get('publicClient'),
                'serviceAccountsEnabled':item.get('serviceAccountsEnabled'),'defaultScopes':names(defaults),'optionalScopes':names(optional)})
        return {'clientCount':len(clients),'oufClients':selected,'scopeCount':len(scopes),
            'availableRequiredScopes':sorted(v['name'] for v in scopes if v.get('name') in CAPABILITIES),
            'cachedSessionOnly':True,'interactiveLogin':False,'clientSecretsRequested':False,'iamResourceWrites':0}
    def gateway_routes(self):
        row=self.rows['ouf-apisix'];mounts=[m for m in row['Mounts'] if m.get('Destination')=='/usr/local/apisix/conf/config.yaml']
        need(len(mounts)==1 and mounts[0].get('RW') is False,'READ_ONLY_APISIX_CONFIG_REQUIRED')
        raw,meta=file_bytes(mounts[0]['Source']);key=admin_key(raw)
        fd=os.open('/proc/'+str(row['State']['Pid'])+'/ns/net',os.O_RDONLY)
        try:
            code,body,err=self.native.command([str(Path(sys.executable).resolve()),'-I','-B','-S','-c',HTTP_READ_PROGRAM,str(fd)],encoded({'key':key}),pass_fds=(fd,))
        finally:os.close(fd)
        need(code==0,'GATEWAY_ADMIN_READ_UNAVAILABLE');v=json.loads(body)
        need(v.get('status')==200,'GATEWAY_ADMIN_GET_DENIED');v=v['body'];rows=v.get('list')
        need(type(rows) is list and len(rows)<=4096 and v.get('total')==len(rows),'INCOMPLETE_ROUTE_INVENTORY')
        summaries=[]
        for entry in rows:
            route=entry.get('value',entry);rid=str(route.get('id',''))
            need(re.fullmatch('[A-Za-z0-9_.-]{1,150}',rid),'ROUTE_IDENTIFIER_UNSUPPORTED')
            uri=route.get('uri')
            summaries.append({'id':rid,'routeHash':digest(route),'selectorHash':digest({k:route.get(k) for k in ('uri','uris','methods','vars')}),
                'selectorFamily':'TRUSTED_HUMAN' if type(uri) is str and ('trusted-human' in uri or 'human' in rid) else 'OTHER',
                'upstreamHash':digest(route.get('upstream')),'pluginNames':sorted(k for k in route.get('plugins',{}) if re.fullmatch('[A-Za-z0-9_-]{1,80}',k)),
                'pluginValuesPrinted':False})
        return {'routeCount':len(rows),'routes':summaries,'fullRoutesHash':digest(rows),'configHash':meta['sha256'],'readMethod':'GET_NETNS_LOOPBACK','credentialPrinted':False}
    def owner_grants(self,pg):
        user,db,schema=db_selector('onboarding',self.rows['ouf-onboarding'],pg)
        allowed=','.join(literal(c) for c in CAPABILITIES)
        expression=("SELECT json_build_object('version',a.version,'bundleRefHash',md5(a.bundle_id),'contentHash',b.content_hash,"
            "'capabilityCount',jsonb_array_length(COALESCE(b.bundle_payload->'capabilities','[]'::jsonb)),"
            "'grantCount',jsonb_array_length(COALESCE(b.bundle_payload->'grants','[]'::jsonb)),"
            "'selectedCapabilities',(SELECT COALESCE(json_agg(c->>'capabilityId'),'[]'::json) FROM jsonb_array_elements(COALESCE(b.bundle_payload->'capabilities','[]'::jsonb)) c WHERE c->>'capabilityId' IN ("+allowed+")),"
            "'selectedActorGrantCounts',(SELECT COALESCE(json_object_agg(cap,n),'{}'::json) FROM (SELECT g->>'capabilityId' cap,count(*) n FROM jsonb_array_elements(COALESCE(b.bundle_payload->'grants','[]'::jsonb)) g WHERE g->>'subjectId'='b93d8cf6-cd14-4ee6-91d7-84cd76c4f500' AND g->>'tenantId'='ouf-lab' AND g->>'capabilityId' IN ("+allowed+") GROUP BY g->>'capabilityId') x)) "
            "FROM ouf_authorization.active_policy_bundle a JOIN ouf_authorization.policy_bundle b ON b.bundle_id=a.bundle_id AND b.version=a.version WHERE a.singleton_key=true")
        v=self.native.query(pg['Id'],user,db,expression);need(type(v) is dict,'ACTIVE_POLICY_PROJECTION_UNAVAILABLE')
        need(type(v.get('contentHash')) is str and re.fullmatch('(sha256:)?[a-f0-9]{64}',v['contentHash']),'ACTIVE_POLICY_HASH_UNSUPPORTED')
        v['projectionOnlyNotEffectivePermissionProof']=True;v['transactionReadOnly']=True;return v
    def retained_history(self):
        intake=self.raw['intake'];sha=intake['fileHashes']['r12-recovery-history.json']
        raw,meta=file_bytes(BASE/('semantic-native-v11-intake-'+INTAKE)/'r12-recovery-history.json',sha,root_private=True)
        value=json.loads(raw)
        return {'metadata':meta,'historicalOnly':True,'schema':value.get('schema') if type(value.get('schema')) is str and re.fullmatch('[a-zA-Z0-9_.-]{1,120}',value['schema']) else None,'budgetReset':False,'doesNotProveCurrentAuthority':True}
    def existing_input(self,pg):
        user,db,schema=db_selector('onboarding',self.rows['ouf-onboarding'],pg)
        expression="SELECT json_build_object('assetFound',true,'profileVersion',f.version,'contentHash',a.content_hash,'sourceAlreadyBound',a.source_id IS NOT NULL,'rows',(f.metadata->>'rows')::int,'columns',(f.metadata->>'columns')::int,'ownerMatches',a.uploaded_by='b93d8cf6-cd14-4ee6-91d7-84cd76c4f500') FROM ouf_onboarding.managed_file_asset a JOIN ouf_onboarding.file_profile f ON f.asset_id=a.asset_id WHERE a.asset_id='6609b245-86ed-4315-8ce0-73f2a8555bf3'::uuid AND f.profile_id='7984c39c-7396-4248-ab0a-f2efc390b49c'::uuid"
        v=self.native.query(pg['Id'],user,db,expression);need(type(v) is dict,'EXISTING_ASSET_PROFILE_UNAVAILABLE')
        need(re.fullmatch('(sha256:)?[a-f0-9]{64}',str(v.get('contentHash'))),'ASSET_HASH_UNSUPPORTED')
        return v

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.parse_args()
    need(os.geteuid()==os.getegid()==0 and os.sys.flags.isolated,'ISOLATED_ROOT_INVENTORY_REQUIRED')
    docker=Path(shutil.which('docker') or '/usr/bin/docker').resolve();info=docker.stat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022,'ROOT_DOCKER_EXECUTABLE_REQUIRED')
    with tempfile.TemporaryDirectory(prefix='ouf-read-only-inventory-') as config:
        result=Inventory(Native(docker,config)).collect()
    print(encoded(result).decode(),flush=True)

if __name__=='__main__':
    try:main()
    except Exception as error:
        print(json.dumps({'schema':'ouf.vps-read-only-inventory.v1','status':'UNAVAILABLE','reason':safe_error(error),
            'completeEnvironmentInventory':False,'applicationWrites':0,'runtimeAuthorityIssued':False,'automaticRetry':False}),flush=True)
        raise SystemExit(1)
