"""Disposable real APISIX replacement plus 9+1 -> 28 signed route continuation.

Only historical target-file reads are substituted with synthetic immutable
fixtures. Engine, namespaces, HTTP, mounted assets, signatures and journals are
real. No target credentials, database, IAM grants or deployment are involved.
"""
import copy
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import time
import unittest
from unittest.mock import patch

import test_chatbot_cohort_gateway as fixture
from tools.chatbot_file_cohort import gateway as g,gateway_runtime as r,gateway_recovery as recovery,gateway_retained as retained
from tools.chatbot_file_cohort.gateway_recovery_plan import compile_remaining
from tools.chatbot_file_cohort.gateway_numeric_preparation import prepare
from tools.semantic_lease_recovery.recovery_journal import Journal
from engine_creation import Engine


@unittest.skipUnless(os.environ.get('OUF_NATIVE_GATEWAY_PHASE5')=='1','explicit disposable APISIX CI only')
class NativePhaseFive(unittest.TestCase):
    def test_numeric_mounts_and_remaining_routes_preserve_prefix_and_consumed_claim(self):
        self.assertEqual(os.geteuid(),0)
        f=fixture.crypto.SignedCutover();f.setUp();self.addCleanup(f.doCleanups)
        docker_bin=shutil.which('docker');self.assertIsNotNone(docker_bin)
        def docker(*args):
            out=subprocess.run([docker_bin,*args],capture_output=True,text=True,timeout=180)
            self.assertEqual(out.returncode,0,out.stderr[:2000]);return out.stdout.strip()
        def remove(*args):
            subprocess.run([docker_bin,*args],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
        for name in ('ouf-backend','ouf-gateway-control'):
            docker('network','create',name);self.addCleanup(remove,'network','rm',name)
        image='apache/apisix@'+r.NUMERIC_IMAGE
        docker('pull',image)
        image_id=json.loads(docker('image','inspect',image))[0]['Id']
        self.assertIn(image_id,r.NUMERIC_IMAGE_IDS)
        etcd=docker('run','-d','--name','phase5-etcd','--network','ouf-backend','quay.io/coreos/etcd:v3.5.17',
            'etcd','--listen-client-urls=http://0.0.0.0:2379','--advertise-client-urls=http://phase5-etcd:2379')
        self.addCleanup(remove,'rm','-f',etcd)
        private=f.root/'native-phase5';private.mkdir(mode=0o700)
        config=private/'original.yaml'
        key='9'*64
        raw=('apisix:\n  node_listen: 9080\ndeployment:\n  role: traditional\n'
             '  role_traditional:\n    config_provider: etcd\n  etcd:\n    host:\n      - http://phase5-etcd:2379\n'
             '  admin:\n    admin_listen:\n      ip: 127.0.0.1\n      port: 9180\n'
             '    allow_admin:\n      - 127.0.0.1/32\n    admin_key:\n      - name: admin\n'
             '        key: 0123456789abcdef0123456789abcdef\n        role: admin\n'
             'nginx_config:\n  envs:\n  - SEMANTIC_PROPOSAL_KEY\n').encode()
        config.write_bytes(raw);config.chmod(0o444)
        cid=docker('run','-d','--name','ouf-apisix','--user','apisix','--network','ouf-backend',
            '--network-alias','ouf-apisix','--restart','unless-stopped',
            '--env','SEMANTIC_PROPOSAL_KEY='+key,'--mount',
            'type=bind,src='+str(config)+',dst=/usr/local/apisix/conf/config.yaml,readonly',image)
        self.addCleanup(remove,'rm','-f',cid)
        docker('network','connect','--alias','ouf-apisix','ouf-gateway-control',cid)
        info=os.stat('/var/run/docker.sock',follow_symlinks=False)
        engine=Engine('/var/run/docker.sock',(info.st_dev,info.st_ino,info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode)))
        # Bounded fixture startup only. Production retries are independently
        # tested against persistent deadlines and HUMAN revocation.
        deadline=time.monotonic()+60
        while True:
            try:
                binding=g.NamespaceAdmin.observe(engine,str(config));transport=g.NamespaceAdmin(engine,binding)
                status,body=transport.request('GET','/apisix/admin/routes')
                if status==200:break
            except (ValueError,OSError):pass
            self.assertLess(time.monotonic(),deadline,'disposable APISIX startup failed');time.sleep(1)
        schema=json.loads((fixture.GATEWAY/'schemas/mcp-gateway-onboarding-review-prepare-dispatch-v1.json').read_text())
        ids=[f'a-{i}'for i in range(9)]+['mcp-managed-file-review-prepare']+[f'z-{i:02}'for i in range(27)]
        changes=[];all_routes={}
        for index,rid in enumerate(ids):
            route={'id':rid,'uri':'/synthetic/'+str(index),'methods':['POST'],'status':1,'priority':0,
                'plugins':{'serverless-pre-function':{'phase':'access','functions':['return function() return ngx.exit(204) end']}}}
            if index==9:route['plugins']['request-validation']={'body_schema':schema}
            all_routes[rid]=route;changes.append({'id':rid,'before':None,'after':route})
        old={'schema':g.PROFILE,'gatewayModulePackageHash':'e'*64,'previousRoutes':{},'proposedRoutes':all_routes,
            'previousRuntimeHash':g.digest({}),'proposedRuntimeHash':g.digest(all_routes),'changes':changes,
            'transportBinding':binding,'automaticRollbackAllowed':False,'automaticWriteReplayAllowed':False}
        journal={'planHash':g.digest(old),'budgetReset':False,'nextStep':9,'effects':[]}
        expected={}
        for change in changes[:9]:
            self.assertIn(transport.request('PUT','/apisix/admin/routes/'+change['id'],change['after'])[0],(200,201))
            expected[change['id']]=change['after'];self.assertEqual(transport.routes(),expected)
            journal['effects'].append({'state':'APPLIED','routeId':change['id'],'intentHash':g.digest(change),'observedMapHash':g.digest(expected)})
        claim=changes[9]
        self.assertEqual(transport.request('PUT','/apisix/admin/routes/'+claim['id'],claim['after'])[0],400)
        journal['effects'].append({'state':'CLAIMED','routeId':claim['id'],'intentHash':g.digest(claim)})
        preserved=g.encoded(journal);preserved_map=transport.routes()
        _,old_config=g.private_config(config)
        updated,assets=prepare(fixture.ROOT,private,image_id,old_config)
        status,actual=engine.request('GET','/v1.44/containers/'+cid+'/json');self.assertEqual(status,200)
        self.assertIsNone(actual['HostConfig']['Binds'])
        self.assertEqual(actual['HostConfig']['Mounts'][0]['Target'],'/usr/local/apisix/conf/config.yaml')
        runtime=r.compile_runtime(actual,old_config,updated,'SEMANTIC_PROPOSAL_KEY',key,hashlib.sha256(key.encode()).hexdigest(),
            'phase5-native',numeric_assets=assets)
        planned=compile_remaining(old,journal,preserved_map,transport.routes(),r.proposed_transport(runtime),g.digest(runtime))
        planned['gatewayRuntimePlanHash']=g.digest(runtime)
        planned['governedReprocessing'].pop('executionIntegrationQualified')
        planned['governedReprocessing']['executionProfile']=recovery.PROFILE
        cohort={'gatewayPlanHash':g.digest(planned),'gatewayModulePackageHash':'e'*64,'cohortManifestHash':'c'*64,
            'replacements':[{'oldRuntimeBinding':{'containerId':'a'*64}}]}
        proof={'profile':recovery.PROFILE,'syntheticHistoryOnly':True}
        signed=json.loads(f.authority);signed.update(gatewayRuntimeInstallation=r.runtime_scope(runtime),
            applicationRegistryCutover={'postGrantRecovery':proof},applicationCohortInstallation=g.installation_scope(cohort),
            gatewayRoutePublication=g.publication_scope(planned))
        f.authority=fixture.crypto.encoded(signed);f.approval['executionAuthorityHash']=fixture.crypto.sha(f.authority)
        f.write(f.mandate,fixture.crypto.encoded(f.approval));f.approved=fixture.crypto.sha(f.mandate.read_bytes())
        for role in f.grant['roles']:f.sign(role)
        action=g.AggregateAction(f.gate(),f.authority,f.expected['sourceClosureHash'])
        d=private/'runtime';d.mkdir(mode=0o700)
        owner=r.GatewayRuntime(action,engine,runtime,Journal(d));owner.initialize()
        mount_observations={}
        native_request=engine.request
        def track_mounts(*args,**kwargs):
            code,body=native_request(*args,**kwargs)
            if code==200 and type(body)is dict and 'Mounts'in body:
                mount_observations[g.digest(body['Mounts'])]=copy.deepcopy(body['Mounts'])
            return code,body
        engine.request=track_mounts
        def remove_created():
            record=owner.record()
            if record['nextStep']>=4:remove('rm','-f',record['effects'][3]['evidence']['containerId'])
        self.addCleanup(remove_created)
        deadline=time.monotonic()+90
        while True:
            try:owner.apply();break
            except r.CohortPaused as paused:
                self.assertLess(time.monotonic(),deadline);time.sleep(min(5,max(0,paused.next_attempt_at-time.time())))
            except Exception:
                record=owner.record();actual=owner.inspect('ouf-apisix')
                current=Engine.runtime_binding(actual)
                started=record['effects'][5]['evidence']['runtimeBinding'] if record['nextStep']>=6 else {}
                print(json.dumps({'check':'SYNTHETIC_NATIVE_GENERATION_DIFF','step':record['nextStep'],
                    'differences':{k:{'started':started.get(k),'current':v}for k,v in current.items()if started.get(k)!=v},
                    'restartCount':actual['RestartCount'],'state':actual['State'],
                    'mounts':{h:mount_observations.get(h)for h in (started.get('mountsHash'),current.get('mountsHash'))}},sort_keys=True),flush=True)
                raise
        self.assertEqual(owner.transport().routes(),preserved_map)
        route_dir=private/'routes';route_dir.mkdir(mode=0o700)
        historical_runtime=owner.record();historical_bytes=owner.journal.record.read_bytes()
        receipt={'profile':retained.PROFILE,'sourceCommit':retained.SOURCE,'reviewHash':retained.REVIEW,
            'authorityHash':action.authority_hash,'runtimeJournalHash':g.digest(historical_runtime),
            'runtimeBindingHash':g.digest(historical_runtime['effects'][-1]['evidence']['runtimeBinding']),
            'runtimePlanHash':g.digest(runtime),'gatewayPlanHash':g.digest(planned),'historicalEffects':8,
            'newLifecycleEffectsAllowed':False,'newWorkerPreviouslyInstalled':False,'originalContinuationClaimHash':'a'*64}
        attempt={'prepared':{'gatewayRuntimePlan':runtime},'journal':historical_runtime,'receipt':receipt}
        previous={'prepared':{'gatewayPlan':old},'gatewayJournal':journal,'retainedGatewayAttempt':attempt}
        proof['retainedNumericGateway']=receipt
        signed=json.loads(f.authority);signed['applicationRegistryCutover']['postGrantRecovery']=proof
        f.authority=fixture.crypto.encoded(signed);f.approval['executionAuthorityHash']=fixture.crypto.sha(f.authority)
        f.write(f.mandate,fixture.crypto.encoded(f.approval));f.approved=fixture.crypto.sha(f.mandate.read_bytes())
        for role in f.grant['roles']:f.sign(role)
        action=g.AggregateAction(f.gate(),f.authority,f.expected['sourceClosureHash'])
        stack=self.enterContext(ExitStack())
        for name,value in [('AUTHORITY',receipt['authorityHash']),('RUNTIME',receipt['runtimeJournalHash']),('NATIVE',receipt['runtimeBindingHash'])]:
            stack.enter_context(patch.object(retained,name,value))
        stack.enter_context(patch.object(recovery,'retained_bindings'))
        stack.enter_context(patch.object(recovery,'read_predecessor',return_value=previous))
        adopted=private/'adopted-runtime';adopted.mkdir(mode=0o700)
        historical_owner=owner;owner=r.GatewayRuntime(action,engine,runtime,Journal(adopted))
        native_writes=[];native_request=engine.request
        def request(method,path,*args):
            if method!='GET':native_writes.append((method,path))
            return native_request(method,path,*args)
        engine.request=request
        owner.initialize();owner.apply();owner.apply()
        self.assertEqual(owner.record()['nextStep'],8);self.assertEqual(native_writes,[])
        self.assertEqual(historical_owner.journal.record.read_bytes(),historical_bytes)
        with self.assertRaisesRegex(Exception,'ALREADY_CONSUMED'):owner.initialize()
        with patch.object(recovery,'retained_bindings'),patch.object(recovery,'read_predecessor',return_value=previous):
            publisher=g.GatewayRoutes(action,cohort,planned,Journal(route_dir),owner.transport())
            publisher.initialize();result=publisher.apply();self.assertEqual(result['reconciledWrites'],28)
            self.assertEqual(result['routeCount'],37)
            after=publisher.record();publisher.apply();self.assertEqual(publisher.record(),after)
            self.assertEqual(owner.transport().routes(),planned['proposedRoutes'])
            self.assertEqual(g.encoded(journal),preserved)
            for rid in expected:self.assertEqual(planned['proposedRoutes'][rid],expected[rid])
            f.approval['state']='REVOKED';f.write(f.mandate,fixture.crypto.encoded(f.approval))
            with self.assertRaises(Exception):publisher.apply()
        print(json.dumps({'check':'GOVERNED_PHASE5_NATIVE','routes':37,'retainedEffects':9,'newWrites':28,
            'historicalClaimUnchanged':True,'numericReadOnlyMounts':2,'retainedBindsNull':True,'adoptedRuntimeSteps':8,'additionalLifecycleOperations':len(native_writes),'targetAccess':False}),flush=True)

if __name__=='__main__':unittest.main()
