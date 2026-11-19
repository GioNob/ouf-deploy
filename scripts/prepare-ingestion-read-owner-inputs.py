"""Installation-specific authentication contract metadata read; no credentials or OAuth."""
import copy,tempfile,zipfile
from contextlib import contextmanager
import ast,base64,hashlib,http.client,ipaddress,json,os,re,signal,socket,stat,sys,time
from pathlib import Path
CONTEXT=Path('/etc/ouf/deploy-snapshots/mcp-ingestion-read-transport-execution-srz6__wf')
SOURCE='0be8fb13db3ff1ea014920bbbbb3738a8a434240'
ROUTES='d5a4040e30e289c150f9d2862ff41e83e22809a9e2202ac19388e744f2c5e927'
MCP='8b199a6767bd39dadf82f6d70f964ab6da9c914a3b327229214d88991893647b'
def require(ok,code):
 if not ok:raise ValueError(code)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(v):return hashlib.sha256(v).hexdigest()
def digest(v):return sha(encoded(v))
def read(path,expected=None,maximum=8388608):
 path=Path(path);require(path.is_absolute()and path.resolve()==path,'EXACT_PRIVATE_PATH_REQUIRED')
 for parent in path.parents:
  row=parent.lstat();require(stat.S_ISDIR(row.st_mode)and row.st_uid==0 and not row.st_mode&0o022,'PRIVATE_ROOT_ANCESTRY_REQUIRED')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  row=os.fstat(fd);require(stat.S_ISREG(row.st_mode)and row.st_uid==row.st_gid==0
   and stat.S_IMODE(row.st_mode)==0o600 and row.st_nlink==1 and 0<row.st_size<=maximum,'PRIVATE_CUSTODY_REQUIRED')
  with os.fdopen(os.dup(fd),'rb')as f:raw=f.read(maximum+1)
  pin=lambda s:tuple(getattr(s,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
  require(len(raw)==row.st_size and pin(row)==pin(os.fstat(fd))==pin(path.lstat())
   and(expected is None or sha(raw)==expected),'PRIVATE_BYTES_CHANGED');return raw
 finally:os.close(fd)
def parsed(path,expected=None,maximum=8388608):return json.loads(read(path,expected,maximum))

def history(parse=parsed):
 package=parse(CONTEXT/'package.json');package_hash=digest(package)
 require(package['sourceCommit']==SOURCE and package['schema']=='ouf.mcp-ingestion-read-transport-package.v1'
  and package['closure']['declaration']['moduleCount']==205
  and package['closure']['declaration']['entryModule']=='tools.mcp_read_transport_gateway82_continuation.entry',
  'EXACT_COMPLETED205_PACKAGE_REQUIRED')
 require(parse(CONTEXT/'runtime.claim.json')=={'packageHash':package_hash,'automaticReplayAllowed':False},'EXACT_CONSUMED205_RUNTIME_CLAIM_REQUIRED')
 case=parse(CONTEXT/'case.json',package['fileHashes']['case.json'])
 preparation=parse(case['preparationClaimBinding']['path'],case['preparationClaimBinding']['sha256'])
 require(preparation['context']==str(CONTEXT)and preparation['maximumCumulativeOAuthAttempts']==256
  and preparation['budgetReset']is False and preparation['automaticReplayAllowed']is False,'EXACT_COMPLETED205_PREPARATION_REQUIRED')
 sources=parse(CONTEXT/'sources.json',package['fileHashes']['sources.json']);hashes=package['closure']['declaration']['sourceHashes']
 require(len(sources)==205 and set(sources)==set(hashes)
  and all(sha(base64.b64decode(v,validate=True))==hashes[n]for n,v in sources.items()),'EXACT205_SOURCE_HASHES_REQUIRED')
 p=parse(CONTEXT/'execution-plan.json');j=parse(CONTEXT/'recovery.json');r=parse(CONTEXT/'update-result.json')
 review=parse(CONTEXT/'review.json');decision=parse(CONTEXT/'decision.json');scope=review['scopes']['mcpReadTransportUpdate']
 stages=['VERIFY_INPUTS']+['mcp.'+n for n in('IMPORT_IMAGE','DISABLE_OLD_RESTART','STOP_OLD','DETACH_OLD_ENDPOINT','RENAME_OLD','CREATE_REPLACEMENT','START_REPLACEMENT','READINESS','RESTORE_RESTART_POLICY')]+['VERIFY_FINAL']
 require(scope['planHash']==digest(p)and decision['reviewHash']==digest(review)and review['sourceClosureHash']==digest(package['closure'])
  and j['schema']=='ouf.mcp-ingestion-read-transport-update-journal.v1'and j['scopeHash']==digest(scope)
  and j['nextStage']==len(stages)and len(j['effects'])==len(stages)and j['incidentState']=='RECOVERED'
  and [e['stage']for e in j['effects']]==stages and all(e['state']=='APPLIED'for e in j['effects'])
  and all(e['intentHash']==digest({'planHash':digest(p),'stage':e['stage']})for e in j['effects'])
  and j['budgetReset']is False and r['schema']=='ouf.mcp-ingestion-read-transport-update-result.v1'
  and r['status']=='MCP_TRANSPORT_UPDATE_READBACK_COMPLETE'and r['contextPath']==str(CONTEXT)
  and r['sourceCommit']=='1f2c28d7abadae78680b040ba7b58be62ef85ee9'and r['oauthAttemptsAfter']==236
  and r['result']['complete']is True and r['result']['applicationReady']is True
  and r['result']['journalVersion']==j['version']==27 and r['result']['acceptanceGranted']is False
  and r['finalEvidence']==j['effects'][-1]['evidence']and r['finalEvidence']['mcp']['health']['httpStatus']==204
  and r['finalEvidence']['mcp']['runtimeBinding']['containerId']==MCP
  and r['finalEvidence']['mcp']['runtimeBinding']['pid']==312624
  and r['finalEvidence']['mcp']['runtimeBinding']['startedAt']=='2026-10-19T13:07:59.712730076Z'
  and r['finalEvidence']['routeMapHash']==ROUTES
  and r['gatewayWrites']==r['databaseMigrationsPerformed']==r['grantChanges']==r['jobsRetried']==0
  and r['sourceActivated']is False and r['publicMetadataChanged']is False,'EXACT_COMPLETED_MCP236_READBACK_REQUIRED')
 require(p['gateway']['beforeRoutes']==p['gateway']['afterRoutes']and len(p['gateway']['afterRoutes'])==82
  and digest(p['gateway']['afterRoutes'])==ROUTES,'EXACT_RETAINED82_ROUTE_MAP_REQUIRED')
 return p,r,package_hash

def runtime(v,ordered=True):
 require(type(v)is dict and v['State']['Running']is True and not v['State'].get('Paused',False)
  and not v['State'].get('Restarting',False)and type(v['State']['Pid'])is int and v['State']['Pid']>0,'EXACT_RUNNING_GENERATION_REQUIRED')
 return {'containerId':v['Id'],'imageId':v['Image'],'pid':v['State']['Pid'],'startedAt':v['State']['StartedAt'],
  'configHash':digest(v['Config']),'hostConfigHash':digest(v['HostConfig']),
  'mountsHash':digest(sorted(v['Mounts'],key=lambda m:m['Destination'])if ordered else v['Mounts']),
  'networkSettingsHash':digest(v['NetworkSettings'])}

class Reader:
 def __init__(self,binding,containers):
  self.path=Path(binding['socketPath']);self.binding=tuple(binding['socketBinding']);self.calls=0
  require(len(containers)==3 and len(set(containers))==3 and all(re.fullmatch('[0-9a-f]{64}',v)for v in containers),'EXACT_THREE_CONTAINERS_REQUIRED')
  self.allowed={'/v1.44/containers/'+v+'/json'for v in containers}
 def check(self):
  require(self.path.is_absolute()and self.path.resolve()==self.path,'EXACT_ENGINE_SOCKET_PATH_REQUIRED')
  row=self.path.lstat();require(stat.S_ISSOCK(row.st_mode)and row.st_uid==0
   and stat.S_IMODE(row.st_mode)in(0o600,0o660)
   and(row.st_dev,row.st_ino,row.st_uid,row.st_gid,stat.S_IMODE(row.st_mode))==self.binding,'EXACT_RETAINED_ENGINE_SOCKET_REQUIRED')
 def get(self,path):
  require(path in self.allowed and self.calls<6,'EXACT_SIX_READ_ONLY_INSPECTS_REQUIRED')
  self.check();engine_path=str(self.path)
  class Connection(http.client.HTTPConnection):
   def connect(self):
    self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(self.timeout);self.sock.connect(engine_path)
  connection=Connection('retained-engine',timeout=10)
  try:
   self.calls+=1;connection.request('GET',path);reply=connection.getresponse();raw=reply.read(4194305)
   require(reply.status==200 and len(raw)<=4194304,'BOUNDED_SUCCESSFUL_ENGINE_INSPECT_REQUIRED');self.check();return json.loads(raw)
  finally:connection.close()

NEW_CONTEXT=Path('/etc/ouf/deploy-snapshots/installation-binding-apply-execution-w8nfc1ko')
NEW_RESULT_HASH='032ed7f9f1de0be2760a79c5e36911f82e1385bf1a7c1287205fa4bd0fbeb387'
NEW_SOURCE='6e36d6f5faa8c0c8e129aac7d843fcf9e7d535e4'
NEW_ROUTES='ed619aa9415b2e70f61689c3830b3fc89135bc9ab72fc90f24daeba1e7bed8c7'
def completed_routes(parse=parsed):
 result=parse(NEW_CONTEXT/'update-result.json');require(digest(result)==NEW_RESULT_HASH,'EXACT_COMPLETED259_TARGET_RECEIPT_REQUIRED')
 package=parse(NEW_CONTEXT/'package.json');closure=package['closure'];decl=closure['declaration']
 require(package['sourceCommit']==NEW_SOURCE and decl['moduleCount']==226
  and decl['entryModule']=='tools.installation_route_reconcile.entry'and package['declarationHash']==digest(decl),'EXACT_COMPLETED226_CLOSURE_REQUIRED')
 sources=parse(NEW_CONTEXT/'sources.json',package['fileHashes']['sources.json'])
 require(len(sources)==226 and set(sources)==set(decl['sourceHashes'])
  and all(sha(base64.b64decode(v,validate=True))==decl['sourceHashes'][n]for n,v in sources.items()),'EXACT226_SOURCE_BYTES_REQUIRED')
 require(parse(NEW_CONTEXT/'runtime.claim.json')=={'packageHash':digest(package),'automaticReplayAllowed':False},'EXACT_CONSUMED226_RUNTIME_CLAIM_REQUIRED')
 plan=parse(NEW_CONTEXT/'execution-plan.json');review=parse(NEW_CONTEXT/'review.json');decision=parse(NEW_CONTEXT/'decision.json');journal=parse(NEW_CONTEXT/'recovery.json')
 scope=review['scopes']['installationRouteReconciliation'];stages=['VERIFY_INPUTS','RECONCILE_PUBLISHED_PROJECTION','GATEWAY_STATUS_ROUTE','GATEWAY_HISTORY_ROUTE','RECONCILE_PREDECESSOR_COMPLETION','VERIFY_FINAL']
 require(plan['kind']=='INSTALLATION_ROUTE_RECONCILIATION'and scope['planHash']==digest(plan)
  and scope['stages']==stages and review['sourceClosureHash']==digest(closure)and decision['reviewHash']==digest(review)
  and journal['schema']=='ouf.installation-binding-native-journal.v1'and journal['scopeHash']==digest(scope)
  and journal['nextStage']==6 and len(journal['effects'])==6 and journal['incidentState']=='RECOVERED'and journal['budgetReset']is False
  and [e['stage']for e in journal['effects']]==stages and all(e['state']=='APPLIED'and e['intentHash']==digest({'planHash':digest(plan),'stage':e['stage']})for e in journal['effects']),
  'EXACT_SIX_COMPLETED_ROUTE_RECONCILIATION_STAGES_REQUIRED')
 routes=plan['gateway']['afterRoutes'];require(len(routes)==82 and digest(routes)==NEW_ROUTES,'EXACT_COMPLETED_NEW82_ROUTES_REQUIRED')
 return routes,digest(package),digest(closure)

def auth_contract(routes,owner):
 names={'OUF_ING_IAM_ENABLED','OUF_ING_IAM_ISSUER','OUF_ING_IAM_AUDIENCE'};env={}
 for value in owner['Config'].get('Env',[]):
  key,sep,contents=value.partition('=')
  if key in names:
   require(sep and key not in env,'UNIQUE_SELECTED_OWNER_IAM_BINDINGS_REQUIRED');env[key]=contents
 enabled=env.get('OUF_ING_IAM_ENABLED','false').lower();require(enabled in('true','false'),'EXACT_BOOLEAN_OWNER_IAM_ENABLED_REQUIRED')
 rows=[]
 for mode in('status','history'):
  cap='ouf.ingestion.'+mode;selected=[r for r in routes.values()if r.get('uri')=='/internal/capabilities/v1/execute/'+cap and r.get('methods')==['POST']]
  require(len(selected)==1,'EXACT_ONE_COMPLETED_INGESTION_READ_ROUTE_REQUIRED');r=selected[0];plugin=r['plugins']['serverless-post-function']
  require(plugin['phase']=='access'and len(plugin['functions'])==1,'EXACT_ACCESS_PHASE_FUNCTION_REQUIRED');lua=plugin['functions'][0]
  require(type(lua)is str and 0<len(lua)<=131072,'BOUNDED_APPROVED_LUA_REQUIRED')
  clears=bool(re.search(r"lower\s*==\s*['\"]authorization['\"]",lua)and re.search(r'ngx\.req\.clear_header\(name\)',lua))
  sets=bool(re.search(r"ngx\.req\.set_header\(\s*['\"][Aa]uthorization['\"]",lua))
  oidc=r['plugins']['openid-connect']
  rows.append({'capability':cap,'oidcBearerOnly':oidc.get('bearer_only')is True,'oidcTlsVerification':oidc.get('ssl_verify')is True,
   'approvedLuaContainsAuthorizationRemovalLoop':clears,'approvedLuaContainsExplicitAuthorizationSetHeader':sets,
   'approvedLuaSha256':sha(lua.encode()),'candidateBearerBoundaryConflict':enabled=='true'and clears and not sets})
 return {'ownerIamEnabledEnvironment':enabled=='true','ownerIamIssuerConfigured':bool(env.get('OUF_ING_IAM_ISSUER')),
  'ownerIamAudienceConfigured':bool(env.get('OUF_ING_IAM_AUDIENCE')),'routeContracts':rows,
  'heuristicSourceProjectionOnly':True,'deployedIamFilterImplementationInspected':False,'specific401CauseProven':False}


def selected_directory_custody(info, path, exception):
    selected = exception['parents'].get(path) if exception else None
    if selected is not None:
        return (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == selected
    return info.st_uid == 0 and (not info.st_mode & 18)

def selected_file_custody(info, exception):
    selected = exception['file'] if exception else None
    if selected is not None:
        uid, gid, mode = selected
        return info.st_uid == uid and (gid is None or info.st_gid == gid) and (stat.S_IMODE(info.st_mode) == mode)
    return info.st_uid == 0 and stat.S_IMODE(info.st_mode) in (256, 288, 292, 384, 416, 420)

def private_config(path, expected=None):
    """Read an exact selected file with pinned, no-follow path custody.

    The three existing selections above have different named owners. All
    other paths, including newly staged APISIX config, retain root custody.
    """
    target = Path(path)
    require(target.is_absolute() and '..' not in target.parts, 'EXACT_APISIX_CONFIG_PATH_REQUIRED')
    exception = _EXISTING_CONFIG_CUSTODY.get(str(target))
    fds = []
    ancestors = []
    try:
        parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        fds.append(parent)
        current = '/'
        for name in target.parts[1:-1]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            fds.append(child)
            info = os.fstat(child)
            current = os.path.join(current, name)
            require(selected_directory_custody(info, current, exception), 'APISIX_CONFIG_ANCESTRY_NOT_CUSTODIED')
            ancestors.append((parent, name, child, (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode)))
            parent = child
        fd = os.open(target.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        fds.append(fd)
        s = os.fstat(fd)
        pin = lambda v: (v.st_dev, v.st_ino, v.st_uid, v.st_gid, v.st_mode, v.st_nlink, v.st_size, v.st_mtime_ns, v.st_ctime_ns)
        require(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and (0 < s.st_size <= 1048576) and selected_file_custody(s, exception), 'ROOT_CONTROLLED_SELECTED_APISIX_CONFIG_REQUIRED')
        raw = b''
        while len(raw) <= 1048576:
            part = os.read(fd, 65536)
            if not part:
                break
            raw += part
        require(len(raw) == s.st_size and pin(s) == pin(os.fstat(fd)) == pin(os.stat(target.name, dir_fd=parent, follow_symlinks=False)), 'APISIX_CONFIG_READ_DRIFT')
        binding = {'path': str(target), 'sha256': hashlib.sha256(raw).hexdigest(), 'metadata': list(pin(s))}
        require(expected is None or binding == expected, 'APISIX_SELECTED_CONFIG_CHANGED')
        identity = lambda v: (v.st_dev, v.st_ino, v.st_uid, v.st_gid, v.st_mode)
        for parent, name, child, seal in ancestors:
            require(seal == identity(os.fstat(child)) == identity(os.stat(name, dir_fd=parent, follow_symlinks=False)), 'APISIX_CONFIG_ANCESTRY_CHANGED')
        return (raw, binding)
    finally:
        for fd in reversed(fds):
            os.close(fd)

ACTIVE_PATH='/opt/ouf/installation/active-projection.json'
_EXISTING_CONFIG_CUSTODY={ACTIVE_PATH:{'parents':{'/opt/ouf':(1000,1000,0o750),'/opt/ouf/installation':(0,0,0o700)},'file':(0,0,0o600)}}
GATEWAY_SOURCE='6bcb28906eee08e0ebe3507b8b58dd987012c8e6'
INGESTION_SOURCE='663faa03288f9ad7775382b9757e44eaba4f51ca'
CANDIDATE={'applicationClasses': {'GatewayReadReceiptVerifier': '01349a6b93b3a38278c07c9534c4bd274ceac969947b08e40300d7b808956936', 'IngestionGatewayReadSecurityConfiguration': 'bce3102ca21241334ba655aaa5b5a6ed61722a0c97c9ec5eebec7deb87cb4c27', 'IngestionIamDisabledConfiguration': '818f36a66bf5de0b1521683efab29010cd8763aaabfb590532cccd388fa44fc0', 'IngestionIamSecurityConfiguration': '68edae63eb5d011f380f7a5757c997897e56778732d2cc514caf1a8672ec6ebd'}, 'applicationJarSha256': '56d770d221a87fdee4fe5c954a458736522aef4a1489b0e94497bb64057416a4', 'highCriticalVulnerabilityGatePassed': True, 'imageArchiveBytes': 136664339, 'imageArchiveSha256': '54eab6e127b0c2adf14e5a2b705270eba3e49dae2f4d5b456323a764c9e96059', 'imageEntrypoint': ['java', '-jar', '/app/app.jar'], 'imageId': 'sha256:51a514d8e07ad7448f98a3886e0c9c6d5b50829f85d320785038a2c76eae46f3', 'imageStartedByCandidateExport': False, 'imageUser': '10002:10002', 'migrationChanges': 0, 'migrationInventory': {'V10__quarantine_lifecycle.sql': '41f8c2362122caa3e9e4d82df0588452a87efdde0f2c518ee47e1bd3570a03dc', 'V11__classified_source_resilience.sql': '97243be62e65879aed425855895456ef0f9e1579cf0b271bcbfc2b0864069e17', 'V12__governed_lifecycle_and_historical_replay.sql': '9fa09325985424125528420db82bce2c52f7ae75dffc7759207c7eb1666b5b2c', 'V13__pressure_admission_retry_budget.sql': '30402c3c225297436b9bc4e65dceca2c3ba29a3caeffc79692ea7cccf50a000d', 'V14__published_activation_schedule.sql': '5d6acf3516504590fe84d833803db55b87b3858a35c31a88a56e3599ceba916d', 'V15__human_recovery_sessions.sql': 'e9abf1e1c192be62a4624f8a7ba551be28013ab3a58698a4ad13231fba29abaa', 'V16__incident_observation_time.sql': '6fcf10b6bfbc8e71002fb9378e6a1ff45b70abb4a8f5cd863a1f207c42cb2eb9', 'V17__incident_publication_and_cursor.sql': '3695a5853afac3923a3428a54739d55d09cf31cc147bf46bfab8505f1c2d0716', 'V18__incident_publication_bookmarks.sql': '7519073ac4075c40ed743489a2aefc7f63d8dcd3b1078e6108e50104f2fa8220', 'V1__ingestion_runtime_core.sql': '8b439684da2cc31c62cfebf4ce4d939f9c8ac9b533a8c9490f5455384c064bb8', 'V2__durable_ack_and_replay.sql': '5e3b53341e396f7bf4ba937db2c61e96e9fdedac6420eb0de15350457ee6c528', 'V3__trusted_operations.sql': 'a6e9eb043defdcd8590b94c690911955ec8957ba016b70967e9aef90943bedf4', 'V4__scheduler_and_source_health.sql': 'b112711bd994cff5b0bdd3671937754f6e33fd85a705a102eed23fe9f207b44c', 'V5__replay_execution_lifecycle.sql': '4e24738272c8fae7233d2601736662eff80d5913fbef6c88ab6dc1f511f65763', 'V6__protected_operational_log.sql': '5bf72f99f9c861678d3e8469ed2f71cd9cd55fccb835dbcd685e9c0d9fe6d46f', 'V7__execution_worker_and_snapshot.sql': '48527993d3d8b50d98dc396e6d9b013410cd9db28d35fb76bff14cc23e46f9f2', 'V8__schema_surveillance.sql': '33853cbd55d09ad901d4af6589ad36c1d4d6da1116f10a14bdb3bb2f0bd8332c', 'V9__runtime_issue_governance.sql': 'ed0236c8b6b6c66767813a0da7d3d92457ba0968c7e4376a35b0119f22a752d9'}, 'notReleaseAcceptance': True, 'runtimeAuthorityIssued': False, 'schema': 'ouf.ingestion-read-owner-candidate.v1', 'sourceCommit': '663faa03288f9ad7775382b9757e44eaba4f51ca', 'trivyReportSha256': '570e1e19df74303288ee497bda3217948aedd013b24ee9f315f3c9d2402bba1d'}
CANDIDATE_ZIP_SHA256="1a26522ab9507bb85fbd6924c0c48c67720493516ec4471a4b3577a8f853ec3f"
def prepare_inputs(plan,projection,gateway,ingestion):
 require(projection['installationId']=='ouf-lab-netcup-01'and projection['revision']==6
  and projection['checksum']=='ded675196fa5b7f9c398b249f737ff19df26d66e81afa65ddcf9a5ecfb034a98','EXACT_COMPLETED_OWNER6_PROJECTION_REQUIRED')
 payload=plan['bindingPlan']['candidatePayload'];iam=payload['iam'];refs=payload['secrets']['references']
 require(payload['installationId']==projection['installationId']and payload['secrets']['provider']=='FILES'
  and iam['issuerUrl']==projection['gateway']['issuerUrl']and iam['gatewayAudience']==projection['gateway']['requiredAudience']
  and iam['workloadClients']['mcpServer']==projection['iam']['workloadClients']['mcpServer'],
  'EXACT_VERSIONED_OWNER_PAYLOAD_AND_FILES_PROVIDER_REQUIRED')
 def names(container):
  result=[]
  for entry in container['Config'].get('Env',[]):
   key,sep,_=entry.partition('=');require(sep and re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,127}',key),'BOUNDED_ENVIRONMENT_NAME_REQUIRED');result.append(key)
  require(len(result)==len(set(result))and len(result)<=1024,'UNIQUE_BOUNDED_ENVIRONMENT_NAMES_REQUIRED')
  return sorted(key for key in result if key.startswith(('OUF_','SPRING_','JAVA_'))or any(word in key for word in('OWNER','DELEGATION','KEY_FILE')))
 def mounts(container):
  require(len(container.get('Mounts',[]))<=64,'BOUNDED_CURRENT_MOUNT_SET_REQUIRED')
  return [{k:r[k]for k in('Type','Source','Destination','RW','Propagation')if k in r}for r in container.get('Mounts',[])]
 gn=names(gateway);on=names(ingestion)
 require(all(type(k)is str and type(v)is str and v for k,v in refs.items())and len(refs)<=256,'BOUNDED_APPROVED_SECRET_REFERENCES_REQUIRED')
 inputs={'schema':'ouf.ingestion-read-owner-installation-inputs.private.v1','installationId':projection['installationId'],
  'retainedOwnerRevision':6,'retainedOwnerGeneration':6,'retainedOwnerPayload':payload,'retainedProjection':projection,
  'gatewaySourceCommit':GATEWAY_SOURCE,'ingestionCandidateSourceCommit':INGESTION_SOURCE,
  'runtimeBindings':{'gateway':runtime(gateway,ordered=plan['gateway']['transport'].get('runtimeBindingProfile')=='ouf.apisix-runtime-binding.mount-set.v1'),
    'ingestion':runtime(ingestion)},
  'gatewayEnvironmentNames':gn,'ingestionEnvironmentNames':on,'gatewayMountReferences':mounts(gateway),'ingestionMountReferences':mounts(ingestion),
  'requiredOwnerKeyReferenceName':'ingestionReadOwnerKey','requiredGatewayOwnerKeyEnvironmentName':'OUF_INGESTION_READ_OWNER_KEY',
  'secretReferenceAlreadyPresent':'ingestionReadOwnerKey'in refs,'gatewayEnvironmentAdditionRequired':'OUF_INGESTION_READ_OWNER_KEY'not in gn,
  'ingestionProfileEnablementStillRequired':True,'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,'budgetReset':False}
 summary={'ownerRevisionRetained':6,'ownerGenerationRetained':6,'approvedSecretProvider':'FILES',
  'existingSecretReferenceNames':sorted(refs),'gatewayAuthEnvironmentNames':[x for x in gn if 'KEY'in x or 'OWNER'in x or 'DELEGAT'in x],
  'ingestionAuthEnvironmentNames':[x for x in on if 'IAM'in x or 'GATEWAY'in x or 'SPRING_CONFIG'in x],
  'secretReferenceAlreadyPresent':inputs['secretReferenceAlreadyPresent'],'gatewayEnvironmentAdditionRequired':inputs['gatewayEnvironmentAdditionRequired'],
  'gatewayMountCount':len(inputs['gatewayMountReferences']),'ingestionMountCount':len(inputs['ingestionMountReferences']),
  'rawEnvironmentValuesPersisted':False,'rawEnvironmentValuesPrinted':False,'secretValuesReadFromFiles':0}
 return inputs,summary

def write_new(path,raw):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  with os.fdopen(os.dup(fd),'wb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
 finally:os.close(fd)
 fd=os.open(Path(path).parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)

@contextmanager
def candidate_bundle(path):
 path=Path(path);require(path.is_absolute()and path.name=='candidate.zip','EXACT_CANDIDATE_ZIP_PATH_REQUIRED')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  st=os.fstat(fd);pin=lambda v:tuple(getattr(v,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
  require(stat.S_ISREG(st.st_mode)and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600 and 0<st.st_size<=536870912,'BOUNDED_PRIVATE_CANDIDATE_ZIP_REQUIRED')
  h=hashlib.sha256()
  with os.fdopen(os.dup(fd),'rb')as f:
   for chunk in iter(lambda:f.read(1048576),b''):h.update(chunk)
  require(h.hexdigest()==CANDIDATE_ZIP_SHA256,'EXACT_ACTIONS_CANDIDATE_ZIP_BYTES_REQUIRED')
  with os.fdopen(os.dup(fd),'rb')as f,zipfile.ZipFile(f)as bundle:
   infos=bundle.infolist();require(len(infos)==3 and {v.filename for v in infos}=={'image.tar.gz','metadata.json','trivy-image.json'}and not any(v.is_dir()or v.flag_bits&1 for v in infos),'EXACT_THREE_CANDIDATE_ARTIFACT_MEMBERS_REQUIRED')
   require(bundle.getinfo('metadata.json').file_size<=65536 and json.loads(bundle.read('metadata.json'))==CANDIDATE,'EXACT_CI_CANDIDATE_METADATA_REQUIRED')
   require(bundle.getinfo('image.tar.gz').file_size==CANDIDATE['imageArchiveBytes'],'EXACT_CANDIDATE_IMAGE_SIZE_REQUIRED')
   require(bundle.getinfo('trivy-image.json').file_size<=16777216 and sha(bundle.read('trivy-image.json'))==CANDIDATE['trivyReportSha256'],'EXACT_CANDIDATE_VULNERABILITY_REPORT_REQUIRED')
   yield bundle
  require(pin(st)==pin(os.fstat(fd))==pin(path.lstat()),'CANDIDATE_ZIP_READ_DRIFT')
 finally:os.close(fd)

def copy_candidate(bundle,path):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);h=hashlib.sha256();count=0
 try:
  with bundle.open('image.tar.gz')as source,os.fdopen(os.dup(fd),'wb')as out:
   for chunk in iter(lambda:source.read(1048576),b''):
    count+=len(chunk);require(count<=CANDIDATE['imageArchiveBytes'],'BOUNDED_EXACT_CANDIDATE_COPY_REQUIRED');h.update(chunk);out.write(chunk)
   out.flush();os.fsync(out.fileno())
  require(count==CANDIDATE['imageArchiveBytes']and h.hexdigest()==CANDIDATE['imageArchiveSha256'],'EXACT_CANDIDATE_IMAGE_ARCHIVE_BYTES_REQUIRED')
 finally:os.close(fd)
 parent=os.open(Path(path).parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(parent)
 finally:os.close(parent)
 return {'path':str(path),'sha256':h.hexdigest(),'bytes':count}

def main(candidate_path):
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_REQUIRED')
 os.umask(0o077);signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(ValueError('FINITE_INSTALLATION_INPUT_PREPARATION_DEADLINE')));signal.alarm(180)
 old,completed,_=history();routes,packagehash,closurehash=completed_routes()
 require(packagehash=='4b21a5733ccd6212432e3aa69dc08b8ad0f4f402d50044fa8c442da585130f82'and closurehash=='1191c3817a2c152b4070ec9c946fae29746b6f2b155e54d9dba504e3803bd965','EXACT_COMPLETED226_INPUT_PACKAGE_REQUIRED')
 plan=parsed(NEW_CONTEXT/'execution-plan.json');root=NEW_CONTEXT.parent
 logical=digest({'scope':'ouf.ingestion-read-owner-inputs.v1','completedPackageHash':packagehash,'gatewaySourceCommit':GATEWAY_SOURCE,'ingestionSourceCommit':INGESTION_SOURCE})
 claim=root/('ingestion-read-owner-input-preparation-'+logical+'.claim.json')
 require(not os.path.lexists(claim),'INPUT_PREPARATION_ALREADY_CLAIMED_NO_REPLAY')
 require(plan['projectionBinding']['path']==ACTIVE_PATH,'EXACT_PUBLISHED_OWNER_PROFILE_PATH_REQUIRED')
 raw,binding=private_config(ACTIVE_PATH,plan['currentPublishedProjectionBinding']);require(sha(raw)==plan['projectionHash'],'EXACT_PUBLISHED_OWNER_PROJECTION_BYTES_REQUIRED')
 projection=json.loads(raw);transport=old['gateway']['transport']
 expected={'gateway':transport['runtimeBinding'],'ingestion':old['unchangedApplications']['ingestion'],'mcp':completed['finalEvidence']['mcp']['runtimeBinding']}
 reader=Reader(old['engine'],[v['containerId']for v in expected.values()]);containers={}
 def inspect(name):
  actual=reader.get('/v1.44/containers/'+expected[name]['containerId']+'/json')
  require(runtime(actual,name!='gateway'or transport.get('runtimeBindingProfile')=='ouf.apisix-runtime-binding.mount-set.v1')==expected[name],'CURRENT_RETAINED_APPLICATION_GENERATION_CHANGED');return actual
 for name in expected:containers[name]=inspect(name)
 inputs,summary=prepare_inputs(plan,projection,containers['gateway'],containers['ingestion'])
 for name in expected:inspect(name)
 private_config(ACTIVE_PATH,binding)
 inputs.update(candidateMetadata=CANDIDATE,candidateArtifactRunId=39304976681,candidateArtifactId=12214420297,candidateArtifactZipSha256=CANDIDATE_ZIP_SHA256,predecessorContextPath=str(NEW_CONTEXT),predecessorPackageHash=packagehash,predecessorClosureHash=closurehash,
  publishedProjectionBinding=binding,retainedGatewayRouteMapHash=NEW_ROUTES,ownerActiveRequeried=False,lastReportedOAuthAttempts=259,maximumCumulativeOAuthAttempts=264)
 with candidate_bundle(candidate_path)as bundle:
  destination=Path(tempfile.mkdtemp(prefix='ingestion-read-owner-inputs-',dir=root));os.chmod(destination,0o700)
  print('OUF_INGESTION_OWNER_INPUT_CONTEXT='+str(destination),flush=True)
  write_new(claim,encoded({'contextPath':str(destination),'logicalRef':logical,'automaticReplayAllowed':False,'budgetReset':False}))
  image=copy_candidate(bundle,destination/'candidate-image.tar.gz')
  inputs['candidateImageBinding']=image
  write_new(destination/'inputs.json',encoded(inputs))
 report={'schema':'ouf.ingestion-read-owner-installation-inputs.v1','complete':True,'contextPath':str(destination),'inputsHash':digest(inputs),
  'logicalRef':logical,'privatePreparationWrites':4,'candidateImageStaged':True,'candidateImageId':CANDIDATE['imageId'],'candidateImageImported':False,'candidateArtifactRunId':39304976681,'readOnlyRuntime':True,**summary,
  'currentContainerGenerationsVerified':True,'engineGetRequests':reader.calls,'ownerActiveRequeried':False,'retainedOwnerSnapshotOnly':True,
  'liveGatewayRoutesRequeried':False,'gatewaySourceCommit':GATEWAY_SOURCE,'ingestionCandidateSourceCommit':INGESTION_SOURCE,
  'lastReportedOAuthAttempts':259,'maximumCumulativeOAuthAttempts':264,'currentHumanStateRequeried':False,
  'humanCredentialJournalsRead':0,'credentialFilesOpened':0,'bearerFilesOpened':0,'authorityFilesOpened':False,
  'oauthRequests':0,'ownerRequests':0,'gatewayWrites':0,'activeProjectionWrites':0,'containerLifecycleOperations':0,
  'databaseCalls':0,'sourceActivated':False,'jobsRetried':0,'journalWrites':0,'runtimeAuthorityIssued':False,
  'nativeApprovalStillRequired':True,'newHumanLoginAllowed':False,'automaticReplayAllowed':False,'budgetReset':False,
  'completedTechnicalPhases':8,'functionalMilestonesProven':4}
 write_new(destination/'preparation-result.json',encoded(report));signal.alarm(0);return report
if __name__=='__main__':
 try:
  require(len(sys.argv)==2,'ONE_AUTHENTICATED_CANDIDATE_ZIP_REQUIRED');result=main(sys.argv[1])
 except(Exception,KeyboardInterrupt)as error:
  safe=globals().get('_OUF_SAFE_CODES',set())
  result={'schema':'ouf.ingestion-read-owner-installation-inputs.v1','complete':False,'status':'STOP_RECONCILE','exceptionClass':type(error).__name__,
   'reasonCode':str(error)if str(error)in safe else'PRIVATE_DETAILS_REDACTED','automaticReplayAllowed':False,'budgetReset':False,'runtimeAuthorityIssued':False}
 print(encoded(result).decode(),flush=True);raise SystemExit(0 if result['complete']else 2)
