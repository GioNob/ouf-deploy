#!/usr/bin/env python3
"""Install the archived 1024-column UDP preserving both SeaweedFS networks.

No explicit migration, upload/profile, credential write, rollback or replay.
Normal Spring startup validates its unchanged V1-36 schema and may run workers.
"""
import copy, hashlib, json, os, re, subprocess, sys, time, zipfile
from pathlib import Path
from datetime import datetime, timezone

SOURCE='c0cf1702b2eb971718996a959414caee004af494'
PUBLISHER=SOURCE
OLD_JAR='15818fe09317c909271d05198cc6bc5e55558268427dac3e43e14259b308ed84'
WORK=Path('/var/lib/ouf-storage-migration/udp-wide-upgrade-20261109')
OBSERVED=WORK.parent/'udp-wide-preflight-qol14bw8'
FRAME='78bf456d7165d8a2b33bc7c3db8cc7c206f8e20fb0cfca95dbf1ad1201f6f058'
ZIP_SHA='f0f55c74a4674e78e6982ffa3575f2c7bcc96741dfdcde5da288863f0cf78340'
ARCHIVE_SHA='b7a8dd1ad2e8840ba5b873b4290c387a510d0ffcab33b7d8b9348038b3f77768'
JAR_SHA='7690ad46ec3e4973feeb0ee7f58c847605ce545b9177778378c36c0219dc1a7b'
CONFIG_ID='sha256:a1cbf9a90d75cc5e2496b3453d45a6f951cecb1ea799dd747ae82f8001e85301'
NATIVE_ID='sha256:c99b53016a1928e1536ab2cdae316b48e441e7ee80f41f0b10581afc324bbdec'
MARKER=WORK.parent/'udp-wide-current.json'
BACKEND='ouf-backend';PRIVATE='ouf-seaweedfs-private'
DOCKER=('/usr/bin/docker','--host','unix:///run/docker.sock','--config','/nonexistent')
GATE='OUF_APPLICATION_GATE=0; trap "OUF_APPLICATION_GATE=1" USR1; while [ "$OUF_APPLICATION_GATE" = 0 ]; do sleep 1 & wait "$!"; done; exec "$@"'
ENTRY=['/bin/sh','-c',GATE,'ouf-gated-application']

def need(ok,code):
    if not ok: raise RuntimeError(code)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def mounts(doc):return sorted(doc['Mounts'],key=lambda x:x['Destination'])
def process(doc):return Path('/proc',str(doc['State']['Pid']),'cmdline').read_bytes().rstrip(b'\0').decode().split('\0')

def two_network_policy(old,mac):
    nets=old['NetworkSettings']['Networks'];legacy=old['Config'].get('MacAddress')
    need(set(nets)=={BACKEND,PRIVATE} and mac.valid(legacy),'TWO_NETWORK_LEGACY_PROFILE_REQUIRED')
    need(all(mac.valid(ep.get('MacAddress')) for ep in nets.values()) and
         len({ep['MacAddress'].lower() for ep in nets.values()})==2,'DISTINCT_ENDPOINT_MACS_REQUIRED')
    matching=[n for n,ep in nets.items() if ep['MacAddress'].lower()==legacy.lower()]
    need(matching==[BACKEND] and old['HostConfig']['NetworkMode']==BACKEND,'LEGACY_MAC_MUST_MATCH_BACKEND')
    return {'profile':'TWO_NETWORK_BACKEND_LEGACY_MAC_DETACH_LAST_V1',
            'detachOrder':[PRIVATE,BACKEND],'originalConfigHash':mac.digest(old['Config']),
            'originalEndpointSetHash':mac.digest(nets),'originalHashesRewritten':False}

def old_guard(old,actual,remaining,name,mac):
    two_network_policy(old,mac)
    need(actual['Id']==old['Id'] and actual['Image']==old['Image'] and actual['Name']==name,'OLD_ID_IMAGE_NAME_CHANGED')
    need(actual['State']['Running'] is False and actual['State']['Pid']==0 and
         actual['State']['StartedAt']==old['State']['StartedAt'],'OLD_GENERATION_OR_STATE_CHANGED')
    need(actual['HostConfig']==old['HostConfig'] and mounts(actual)==mounts(old) and
         actual['Path']==old['Path'] and actual['Args']==old['Args'],'OLD_HOST_MOUNT_LAUNCH_CHANGED')
    expected=copy.deepcopy(old['Config'])
    if BACKEND not in remaining: expected.pop('MacAddress')
    need(actual['Config']==expected,'OLD_CONFIG_CHANGED_OUTSIDE_QUALIFIED_PHASE')
    need(set(actual['NetworkSettings']['Networks'])==set(remaining),'OLD_REMAINING_NETWORKS_CHANGED')

def request(old,image,app,mac):
    two_network_policy(old,mac)
    c,h=copy.deepcopy(old['Config']),copy.deepcopy(old['HostConfig'])
    need(c.get('User')=='10004:10004' and c.get('WorkingDir')=='/app','ONBOARDING_USER_WORKDIR_REQUIRED')
    need(Path(app[0]).name=='java' and app.count('-jar')==1 and app[app.index('-jar')+1]=='/app/app.jar','KNOWN_JAVA_LAUNCH_REQUIRED')
    need(h['RestartPolicy']=={'Name':'no','MaximumRetryCount':0} and not h.get('AutoRemove') and not h.get('VolumesFrom'),'SUPPORTED_RETAINED_LIFECYCLE_REQUIRED')
    declared={m['Target'] for m in h.get('Mounts') or []};declared.update(b.split(':')[1] for b in h.get('Binds') or [])
    need(all(m['Type']=='bind' and not m['RW'] and m['Destination'] in declared for m in old['Mounts']),'EXPLICIT_READ_ONLY_BINDINGS_REQUIRED')
    if h.get('OomKillDisable') is None:h['OomKillDisable']=False
    c.update(Image=image,Entrypoint=ENTRY,Cmd=list(app));c.pop('MacAddress')
    c['Env']=[('JAVA_VERSION=jdk-21.0.13+9' if x.startswith('JAVA_VERSION=') else x) for x in c['Env']]
    c['Labels']=dict(c.get('Labels') or {},**{'org.opencontainers.image.revision':PUBLISHER,'ouf.udp.wide-source':SOURCE})
    endpoints={}
    for net,ep in old['NetworkSettings']['Networks'].items():
        need(bool(ep.get('IPAddress')),'OBSERVED_IPV4_REQUIRED')
        ipam=copy.deepcopy(ep.get('IPAMConfig') or {});ipam['IPv4Address']=ep['IPAddress']
        if ep.get('GlobalIPv6Address'):ipam['IPv6Address']=ep['GlobalIPv6Address']
        endpoint={'IPAMConfig':ipam,'Aliases':list(ep.get('Aliases') or []),'MacAddress':ep['MacAddress']}
        for k in ('Links','DriverOpts'):
            if ep.get(k):endpoint[k]=copy.deepcopy(ep[k])
        endpoints[net]=endpoint
    c.update(HostConfig=h,NetworkingConfig={'EndpointsConfig':endpoints});return c

def verify_replacement(old,req,actual,started):
    expected={k:v for k,v in req.items() if k not in ('HostConfig','NetworkingConfig')}
    config=copy.deepcopy(actual['Config']);wanted=req['NetworkingConfig']['EndpointsConfig']
    if 'MacAddress' in config:need(config.pop('MacAddress')==wanted[BACKEND]['MacAddress'],'NEW_LEGACY_MAC_CHANGED')
    need(config==expected,'NEW_CONFIG_CHANGED')
    host=copy.deepcopy(req['HostConfig'])
    if started and old['HostConfig'].get('OomKillDisable') is None and host.get('OomKillDisable') is False:host['OomKillDisable']=None
    need(actual['HostConfig']==host and actual['Image']==req['Image'] and mounts(actual)==mounts(old),'NEW_IMAGE_HOST_MOUNTS_CHANGED')
    nets=actual['NetworkSettings']['Networks'];need(set(nets)==set(wanted),'NEW_NETWORK_SET_CHANGED')
    for net,ep in wanted.items():
        now=nets[net]
        need(now['IPAMConfig']==ep['IPAMConfig'] and set(now.get('Aliases') or [])==set(ep['Aliases'])|{actual['Id'][:12]},'NEW_NETWORK_ADDRESSES_ALIASES_CHANGED')
        if started:need(now['IPAddress']==ep['IPAMConfig']['IPv4Address'] and now['MacAddress']==ep['MacAddress'],'NEW_NETWORK_IP_MAC_CHANGED')
    need(actual['State']['Running'] is started,'NEW_RUNNING_STATE_CHANGED')

def replace(engine,old,req,mac,record,report,stopped_check):
    policy=two_network_policy(old,mac);record('network-policy.json',policy)
    cid=old['Id'];name=old['Name'];retained=name+'-before-wide-20261109'
    need(re.fullmatch('/[A-Za-z0-9_.-]+',name) and len(retained)<200,'BOUNDED_NAME_REQUIRED')
    record('old.private.json',old);record('request.private.json',req)
    record('stop-intent.json',{'containerId':cid});report['oldStopDispatched']=True
    engine.api('POST','/containers/'+cid+'/stop?t=35');stopped=engine.inspect(cid)
    old_guard(old,stopped,[BACKEND,PRIVATE],name,mac);record('stopped.private.json',stopped);stopped_check()
    remaining=dict(stopped['NetworkSettings']['Networks'])
    for i,net in enumerate(policy['detachOrder']):
        record('detach-'+str(i)+'-intent.json',{'containerId':cid,'network':net})
        engine.api('POST','/networks/'+net+'/disconnect',{'Container':cid,'Force':False});remaining.pop(net)
        actual=engine.inspect(cid);old_guard(old,actual,remaining,name,mac)
        need(actual['NetworkSettings']['Networks']==remaining,'REMAINING_STOPPED_ENDPOINT_CHANGED')
        record('detached-'+str(i)+'.private.json',actual)
    report['oldMacTransition']=policy['profile']
    record('rename-intent.json',{'name':retained});engine.api('POST','/containers/'+cid+'/rename?name='+retained[1:])
    old_guard(old,engine.inspect(cid),[],retained,mac)
    record('create-intent.json',{'requestSha256':sha(json.dumps(req,sort_keys=True).encode())})
    new=engine.api('POST','/containers/create?name='+name[1:],req)['Id'];report['replacementContainerId']=new;record('created.json',{'containerId':new})
    current=engine.inspect(new);verify_replacement(old,req,current,False);record('created.private.json',current)
    record('gate-start-intent.json',{'containerId':new});engine.api('POST','/containers/'+new+'/start')
    current=engine.inspect(new);verify_replacement(old,req,current,True);record('gated.private.json',current)
    report['replacementGateStarted']=True;return current

READINESS=r'''import http.client,json,sys
c=http.client.HTTPConnection('127.0.0.1',8080,timeout=2)
try:
 c.request('GET','/actuator/health/readiness');r=c.getresponse();b=r.read(65537)
 sys.exit(0 if r.status==200 and len(b)<=65536 and json.loads(b).get('status')=='UP' else 1)
finally:c.close()
'''
def readiness(doc):
    return subprocess.run(('/usr/bin/nsenter','--target',str(doc['State']['Pid']),'--net',sys.executable,'-I','-B','-S','-c',READINESS),capture_output=True,timeout=4).returncode==0


TABLES=('capability_retry_guard', 'compaction_manifest', 'compaction_manifest_entry', 'geometry_observation', 'governance_audit', 'governance_plan', 'handoff_event', 'handoff_intake', 'handoff_property_profile', 'human_geometry_decision', 'human_property_decision', 'human_resolution_decision', 'identity_lookup_coverage', 'identity_lookup_shape', 'identity_lookup_shape_catalog', 'identity_lookup_token', 'identity_preactivation_attestation', 'lake_maintenance_attempt', 'lake_maintenance_schedule', 'lake_object', 'lake_object_event', 'lake_shadow_rebuild_entry', 'lake_shadow_rebuild_event', 'lake_shadow_rebuild_plan', 'materialization_job', 'materialization_observation', 'merge_property_contribution_link', 'merge_resolution_issue', 'object_identity_history', 'object_revision', 'property_bitemporal_interval', 'property_conflict', 'property_contribution', 'property_policy_state', 'property_value', 'query_budget', 'relationship_contribution', 'relationship_current_support', 'relationship_identity_history', 'relationship_issue', 'relationship_reconciliation', 'relationship_revision', 'replay_event', 'replay_plan', 'resolution_decision', 'resolution_issue', 'resolution_review_package_confirmation', 'serving_access_audit', 'source_binding', 'source_binding_history', 'spatial_resolution_issue', 'split_resolution_issue', 'storage_reconciliation_finding', 'urban_geometry', 'urban_geometry_current', 'urban_geometry_role_current', 'urban_object', 'urban_object_current_state', 'urban_relationship')
def storage(c,doc,p,report):
    _,meta=c.mount_file(doc,'/run/ouf-seaweedfs/credentials',False)
    need(meta.get('status')=='MOUNTED_REGULAR_FILE' and meta.get('sameAsHostSource') and meta.get('readOnlyMount'),'STORAGE_CREDENTIAL_BINDING_CHANGED')
    raw,trust=c.mount_file(doc,'/run/ouf-seaweedfs/truststore.p12',True,4*1024*1024);report['truststoreReads']+=1
    need(raw is not None and sha(raw)==p.TRUST_SHA and trust.get('sameAsHostSource'),'SWITCH_TRUSTSTORE_CHANGED')
    return {'credentials':meta,'truststore':trust}

def database_query(p,hp):
    # Payloads stay inside PostgreSQL. All 59 source-declared tables are compared.
    parts=["SELECT '%s' name,json_build_object('rows',count(*),'fingerprint',md5(coalesce(string_agg(d,',' ORDER BY d),''))) value FROM (SELECT md5(row_to_json(t)::text) d FROM ouf_udp.%s t) x"%(t,t) for t in TABLES]
    return p.query(hp).replace("'applicationRoleSuperuser'", "'maintenanceWithinWindow',(SELECT count(*) FROM ouf_udp.lake_maintenance_schedule WHERE state='READY' AND next_run_at<=transaction_timestamp()+interval '10 minutes'),'retainedRows',(SELECT json_object_agg(name,value) FROM ("+' UNION ALL '.join(parts)+") r),'applicationRoleSuperuser'")

def verify_database(value,oid,prior=None):
    need(value.get('readOnly') is True and str(value.get('databaseOid'))==str(oid) and value.get('exactCandidateMigrationHistory') is True and value.get('applicationRoleSuperuser') is False,'EXACT_ORDINARY_V36_DATABASE_REQUIRED')
    a=value['activity']
    need(set(a['handoff_intake'])<={'PROCESSED'} and set(a['materialization_job'])<={'SUCCEEDED'} and
         set(a['lake_object'])<={'VERIFIED','COMPACTED','COLD','DELETED'} and set(a['lake_maintenance_schedule'])<={'READY','PAUSED'} and
         not a['lake_shadow_rebuild_plan'] and not any(a['unexpiredLeases'].values()) and a['maintenanceDue']==0,'UNFINISHED_WORK_REQUIRES_RECONCILIATION')
    need(value.get('maintenanceWithinWindow')==0,'MAINTENANCE_WINDOW_TOO_CLOSE')
    rows=value.get('retainedRows');need(isinstance(rows,dict) and set(rows)==set(TABLES),'RETAINED_TABLE_FINGERPRINTS_REQUIRED')
    need(all(type(v.get('rows'))is int and v['rows']>=0 and re.fullmatch('[a-f0-9]{32}',v.get('fingerprint','')) for v in rows.values()),'INVALID_TABLE_FINGERPRINT')
    if prior is not None:need(all(value[k]==prior[k] for k in ('migrations','activity','retainedRows')),'RETAINED_DATABASE_STATE_CHANGED')

def database(p,hp,c,h,doc,pg,label,report):
    user,name=p.db_binding(doc,pg,c,h);report['readOnlyDatabaseSessionsAttempted']+=1
    q=subprocess.run((*DOCKER,'exec','-i','-e','PGOPTIONS=-c default_transaction_read_only=on',pg['Id'],
        'psql','-X','-w','-q','-A','-t','-v','ON_ERROR_STOP=1','-h','/var/run/postgresql','-U',user,'-d',name),input=database_query(p,hp).encode(),capture_output=True,timeout=12)
    c.save_private(WORK,label+'-database.stderr.private',q.stderr[:65536]);need(q.returncode==0 and len(q.stdout)<=131072,'DATABASE_READ_FAILED')
    c.save_private(WORK,label+'-database.private.json',q.stdout);return p.result(hp,h.parse(q.stdout),p.manifest())

def run(report,archive):
    need(os.geteuid()==0 and sys.flags.isolated,'ISOLATED_ROOT_REQUIRED')
    import importlib.util
    def load(name,file,pin):
        path=Path(__file__).with_name(file);raw=path.read_bytes();need(sha(raw)==pin,'HELPER_HASH_CHANGED')
        spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);exec(compile(raw,str(path),'exec'),m.__dict__);return m
    p=load('preflight','read-udp-wide-preflight-20261108.py','fa8239a9c6ddd99ea6cddd9a11ae5246d3e63440a54d70c7c6eeef8f87d2664f')
    r=load('engine','upgrade-semantic-application-20261108.py','2e7e7e42367b3329f6ebd441bba665f974ea43871049d863415524610138efb1')
    mac=load('mac','retained_mac.py','cb5dbbee4a80ce71860dfe5d32362a662d98898c58fd82009e69c5eb6ac1f7ce')
    hp,c,h=p.helpers();p.manifest();engine=r.Engine()
    need(archive.is_file() and archive.stat().st_size==113722451 and r.file_sha(archive)==ZIP_SHA,'EXACT_CANDIDATE_ZIP_REQUIRED')
    need(not MARKER.exists(),'CURRENT_REPLACEMENT_MARKER_EXISTS');WORK.mkdir(mode=0o700);report['privateEvidenceDirectory']=str(WORK)
    record=lambda n,v:c.save_private(WORK,n,(json.dumps(v,sort_keys=True)+'\n').encode())
    record('attempt.json',{'sourceCommit':SOURCE,'artifactId':13635797332})
    with zipfile.ZipFile(archive) as z:
        need(sorted(z.namelist())==['SHA256SUMS','image.tar.gz','manifest.json'],'EXACT_ARCHIVE_MEMBERS_REQUIRED')
        c.save_private(WORK,'image.tar.gz',z.read('image.tar.gz'))
    need(r.file_sha(WORK/'image.tar.gz')==ARCHIVE_SHA,'EXACT_IMAGE_ARCHIVE_REQUIRED')
    plan=h.read(h.PLAN,1048576);need(sha(plan)==h.PLAN_SHA,'RETAINED_PLAN_CHANGED');roles=h.parse(plan)['roles']
    old=h.inspect(p.CID);observed=h.parse(h.read(OBSERVED/'udp.private.json',2*1024*1024))
    need(h.digest(h.frame(observed))==FRAME and h.frame(old)==h.frame(observed) and old['Image']==p.IMAGE and old['State']['Running'],'CURRENT_UDP_CHANGED')
    pg=h.inspect(roles['postgres']['containerId']);original=h.inspect(roles['udp']['containerId'])
    need(pg['Image']==roles['postgres']['nativeImage'] and pg['State']['Running'] and not original['State']['Running'],'POSTGRES_OR_OLD_MINIO_WRITER_CHANGED')
    app=process(old);need(r.file_sha(Path('/proc',str(old['State']['Pid']),'root/app/app.jar'))==OLD_JAR,'INSTALLED_JAR_CHANGED')
    need(len(old['Mounts'])==3 and not any('/app/app.jar'==m['Destination'] or '/app/app.jar'.startswith(m['Destination'].rstrip('/')+'/') for m in old['Mounts']),'EXPECTED_MOUNTS_REQUIRED')
    declarations=p.declarations(h.environment(old),app)
    need(all(declarations[k] for k in ('allStorageArgumentsMatchSeaweedfsSwitch','truststoreDeclarationMatchesSwitch','sharedCredentialsFileMatchesSwitch','profileMatchesSwitch')) and not declarations['staticAwsCredentialEnvironmentPresent'],'STORAGE_DECLARATIONS_CHANGED')
    original_storage=storage(c,old,p,report);two_network_policy(old,mac);need(readiness(old),'ORIGINAL_READINESS_REQUIRED')
    # Validate request before image load/stop; all original ENV including Spring JSON is retained.
    request(old,CONFIG_ID,app,mac)
    record('image-import-intent.json',{'archiveSha256':ARCHIVE_SHA});r.cli('load','--input',str(WORK/'image.tar.gz'),timeout=180);report['imageImported']=True
    image=json.loads(r.cli('image','inspect','ouf-udp:'+SOURCE))[0]
    need(image['Id'] in (CONFIG_ID,NATIVE_ID) and image['Config']['User']=='10004:10004' and image['Config']['Entrypoint']==['java','-jar','/app/app.jar'],'IMPORTED_IMAGE_CHANGED')
    req=request(old,image['Id'],app,mac);report['candidateImageId']=image['Id']
    before=database(p,hp,c,h,old,pg,'before',report);verify_database(before,'21556');report['activityBefore']=before['activity']
    began=time.monotonic()
    need(h.frame(h.inspect(p.CID))==h.frame(old) and h.frame(h.inspect(pg['Id']))==h.frame(pg) and process(old)==app and not h.inspect(original['Id'])['State']['Running'],'RUNTIME_CHANGED_BEFORE_STOP')
    def stopped_check():
        stopped=database(p,hp,c,h,old,pg,'stopped',report);verify_database(stopped,'21556',before)
        need(time.monotonic()-began<120,'SWITCH_WINDOW_EXCEEDED')
    current=replace(engine,old,req,mac,record,report,stopped_check)
    need(process(current)==ENTRY+app,'GATE_NOT_PROVEN')
    need(r.file_sha(Path('/proc',str(current['State']['Pid']),'root/app/app.jar'))==JAR_SHA,'CANDIDATE_JAR_CHANGED')
    need(storage(c,current,p,report)==original_storage,'STORAGE_MOUNT_METADATA_CHANGED')
    need(time.monotonic()-began<180,'SWITCH_WINDOW_EXCEEDED')
    record('application-start-intent.json',{'containerId':current['Id']});report['applicationStartDispatched']=True
    engine.api('POST','/containers/'+current['Id']+'/kill?signal=USR1')
    for _ in range(60):
        live=engine.inspect(current['Id']);need(live['State']['Running'],'APPLICATION_EXITED')
        if readiness(live):break
        time.sleep(1)
    else:raise RuntimeError('READINESS_NOT_UP')
    need(process(live)==app,'JAVA_INIT_ARGUMENTS_CHANGED');verify_replacement(old,req,live,True)
    old_guard(old,engine.inspect(old['Id']),[],old['Name']+'-before-wide-20261109',mac)
    need(not h.inspect(original['Id'])['State']['Running'],'OLD_MINIO_WRITER_RESTARTED')
    need(storage(c,live,p,report)==original_storage,'STORAGE_BINDING_CHANGED_AFTER_START')
    after=database(p,hp,c,h,live,pg,'after',report);verify_database(after,'21556',before)
    record('replacement.private.json',live)
    report.update(status='UDP_WIDE_1024_READY',readinessUp=True,readinessHttpStatus=200,migrationHistoryUnchanged=True,
        retainedTableCount=len(TABLES),retainedRowsUnchanged=True,oldRetainedStopped=True,oldMinioWriterStopped=True,
        bothNetworkAddressesAliasesMacPreserved=True,storageMountsAndTruststorePreserved=True,
        environmentPreservedExceptImageJavaVersion=True,javaProcessArgumentsPreserved=True,wideUdpFunctionalTested=False)
    record('complete.json',report)
    c.save_private(WORK.parent,MARKER.name,(json.dumps({'containerId':live['Id'],'imageId':live['Image'],'sourceCommit':SOURCE,'evidenceDirectory':str(WORK),'previousContainerId':old['Id']},sort_keys=True)+'\n').encode())

def main():
    report={'schema':'ouf.udp-wide-upgrade.v1','status':'HELD','credentialValuesEmitted':False,'credentialFileContentsRead':0,'credentialFileWrites':0,
        'readOnlyDatabaseSessionsAttempted':0,'truststoreReads':0,'imageImported':False,'oldStopDispatched':False,'applicationStartDispatched':False,
        'explicitMigrationDispatched':False,'applicationStartupMayAccessDatabaseAndExistingWork':True,'applicationStartupMayAccessS3':True,
        'databaseWritesByScript':0,'businessRequestsIssued':0,'s3RequestsByScript':0,'gatewayWrites':0,'permissionChanges':0,'automaticRollback':False,'automaticReplay':False}
    try:
        need(len(sys.argv)==2,'EXACT_ARCHIVE_ARGUMENT_REQUIRED');run(report,Path(sys.argv[1]))
    except FileExistsError:report['reason']='EXISTING_ATTEMPT_DO_NOT_REPLAY'
    except Exception as exc:
        report['reason']=str(exc) if type(exc) is RuntimeError and re.fullmatch('[A-Z][A-Z0-9_]{0,100}',str(exc)) else type(exc).__name__
        if report.get('replacementContainerId'):
            try:
                log=subprocess.run((*DOCKER,'logs','--tail','100',report['replacementContainerId']),capture_output=True,timeout=10)
                for name,data in (('stdout.private',log.stdout),('stderr.private',log.stderr)):
                    fd=os.open(WORK/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                    with os.fdopen(fd,'wb') as f:f.write(data)
                report['privateStartupLogsRetained']=True
            except Exception:report['privateStartupLogsRetained']=False
    report['observedAt']=datetime.now(timezone.utc).isoformat();print(json.dumps(report,sort_keys=True))
if __name__=='__main__':main()
