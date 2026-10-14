"""One-use Gateway publication with real signatures and durable private journal.

APISIX route storage below is an explicit disposable fixture, not VPS evidence.
The namespace test additionally exercises the actual isolated subprocess/setns/HTTP transport.
"""
import copy
import json
import os
from pathlib import Path
import subprocess
import signal
import sys
import tempfile
import threading
import time
import unittest

ROOT=Path(__file__).resolve().parents[1]
APP=ROOT if (ROOT/'tools/semantic_application_cutover/engine_creation.py').is_file() else ROOT.parent/'file-profile-work'
TOKEN=ROOT if (ROOT/'tools/semantic_policy_token_owner/owner_installation.py').is_file() else ROOT.parent/'token-owner-installer-work'
GATEWAY=Path(os.environ.get('OUF_GATEWAY_SOURCE',ROOT.parent/'gateway-read-scope-work'))
sys.path[:0]=[str(ROOT),str(TOKEN),str(APP),str(GATEWAY),str(APP/'tests'),
    str(TOKEN/'tools/semantic_policy_token_owner'),str(APP/'tools/semantic_application_cutover'),
    str(APP/'tools/semantic_database_cutover'),str(APP/'tools/semantic_cohort_admission/cohort-draft')]
import test_cutover_authority_native as crypto
from tools.chatbot_file_cohort import gateway as g
from tools.chatbot_file_cohort import gateway_preparation as preparation
from engine_creation import Engine
from tools.semantic_lease_recovery.recovery_journal import Journal


class GatewayPublication(unittest.TestCase):
    def fixture(self):
        f=crypto.SignedCutover();f.setUp();self.addCleanup(f.doCleanups)
        before={'retained':{'id':'retained','uri':'/other','methods':['GET']},
                'changed':{'id':'changed','uri':'/review','methods':['POST'],'timeout':10}}
        after=copy.deepcopy(before);after['changed']['timeout']=55
        after['added']={'id':'added','uri':'/readiness','methods':['POST']}
        changes=[{'id':n,'before':before.get(n),'after':after[n]} for n in sorted(('changed','added'))]
        plan={'schema':g.PROFILE,'gatewayModulePackageHash':'e'*64,'previousRoutes':before,'proposedRoutes':after,
              'previousRuntimeHash':g.digest(before),'proposedRuntimeHash':g.digest(after),'changes':changes,
              'transportBinding':{'fixture':True},'automaticRollbackAllowed':False,'automaticWriteReplayAllowed':False}
        cohort={'gatewayPlanHash':g.digest(plan),'gatewayModulePackageHash':'e'*64,
                'cohortManifestHash':'c'*64,'replacements':[{'oldRuntimeBinding':{'containerId':'a'*64}}]}
        value=json.loads(f.authority)
        value.update(applicationCohortInstallation=g.installation_scope(cohort),gatewayRoutePublication=g.publication_scope(plan))
        f.authority=crypto.encoded(value);f.approval['executionAuthorityHash']=crypto.sha(f.authority)
        f.write(f.mandate,crypto.encoded(f.approval));f.approved=crypto.sha(f.mandate.read_bytes())
        for role in f.grant['roles']:f.sign(role)
        action=g.AggregateAction(f.gate(),f.authority,f.expected['sourceClosureHash'])
        native=g.NamespaceAdmin.__new__(g.NamespaceAdmin);native.binding={'fixture':True}
        native.reviewed_binding=copy.deepcopy(native.binding)
        native.state=copy.deepcopy(before);native.calls=[];native.lose_ack=False;native.omit=False
        native.check=lambda:None
        native.routes=lambda:copy.deepcopy(native.state)
        def request(method,path,body=None):
            self.assertEqual(method,'PUT');native.calls.append((method,path,copy.deepcopy(body)))
            if not native.omit:native.state[body['id']]=copy.deepcopy(body)
            if native.lose_ack:
                native.lose_ack=False;raise OSError('fixture ACK loss')
            return 500 if native.omit else 200,{}
        native.request=request
        directory=f.root/'routes';directory.mkdir(mode=0o700)
        owner=g.GatewayRoutes(action,cohort,plan,Journal(directory),native);owner.initialize()
        return owner,native,f

    def restart(self,owner):
        return g.GatewayRoutes(owner.action,owner.cohort_plan,owner.plan,Journal(owner.journal.root),owner.transport)

    def test_complete_map_retained_and_changed_route_timeout_updated_once(self):
        owner,native,_=self.fixture();result=owner.apply()
        self.assertEqual(result['routeCount'],3);self.assertEqual(result['reconciledWrites'],2)
        self.assertEqual(native.state['retained'],owner.plan['previousRoutes']['retained'])
        self.assertEqual(native.state['changed']['timeout'],55)
        self.restart(owner).apply();self.assertEqual(len(native.calls),2)

    def test_lost_ack_is_get_reconciled_never_replayed(self):
        owner,native,_=self.fixture();native.lose_ack=True
        with self.assertRaises(OSError):owner.apply()
        self.assertEqual(owner.record()['effects'][-1]['state'],'CLAIMED')
        self.restart(owner).apply();self.assertEqual(len(native.calls),2)

    def test_unknown_absent_effect_never_retry_or_rollback(self):
        owner,native,_=self.fixture();native.omit=True
        with self.assertRaisesRegex(ValueError,'OUTCOME_UNPROVEN_NO_REPLAY'):owner.apply()
        with self.assertRaisesRegex(ValueError,'OUTCOME_UNPROVEN_NO_REPLAY'):self.restart(owner).apply()
        self.assertEqual(len(native.calls),1);self.assertEqual(native.state,owner.plan['previousRoutes'])

    def test_current_human_revocation_denies_even_readback_resume(self):
        owner,native,f=self.fixture();native.lose_ack=True
        with self.assertRaises(OSError):owner.apply()
        f.approval['state']='REVOKED';f.write(f.mandate,crypto.encoded(f.approval))
        with self.assertRaisesRegex(Exception,'MANDATE_CHANGED'):self.restart(owner).apply()
        self.assertEqual(len(native.calls),1)

    def test_foreign_route_drift_blocks_before_mutation(self):
        owner,native,_=self.fixture();native.state['retained']['uri']='/changed-by-other-owner'
        with self.assertRaisesRegex(ValueError,'MAP_CHANGED_BEFORE_CLAIM'):owner.apply()
        self.assertEqual(native.calls,[])

    def test_tampered_claim_intent_is_not_reconciled(self):
        owner,native,_=self.fixture();native.lose_ack=True
        with self.assertRaises(OSError):owner.apply()
        before=owner.journal.read();after=copy.deepcopy(before);after['effects'][0]['intentHash']='f'*64
        owner.journal.compare_and_save(before,after)
        with self.assertRaisesRegex(ValueError,'HISTORY_INVALID'):self.restart(owner).apply()
        self.assertEqual(len(native.calls),1)


class Projection(unittest.TestCase):
    def test_actual_final_materializers_build_43_target_projected_routes(self):
        from tools.compile_config import compile_config
        from tools.apply_installation_projection import apply_projection
        runtime=apply_projection(compile_config(GATEWAY/'ouf-config'),
            json.loads((GATEWAY/'tests/fixtures/installation-projection-lab.json').read_text()))
        refs={'oidcSecretRef':'$ENV://OIDC_SECRET','delegationKeyEnv':'DKEY','authorizationKeyEnv':'AKEY',
              'udpKeyEnv':'UKEY','semanticReadKeyEnv':'RKEY','semanticProposalKeyEnv':'PKEY',
              'semanticReadRouteIds':{'search':'semantic-search','get':'semantic-get'}}
        rows=preparation.materialize_target(runtime,refs)
        self.assertEqual(len(rows),43)
        self.assertEqual(rows['trusted-human-onboarding-approvals-post']['upstream']['timeout']['read'],55)
        existing={'foreign':{'id':'foreign','uri':'/foreign','methods':['GET']}}
        package={'module':'gateway','artifactKind':'SOURCE_AND_ROUTE_PACKAGE','sourceCommit':'a'*40,
                 'cohortSourceLockSha256':'b'*64}
        plan=preparation.compile_gateway_plan(existing,runtime,refs,package,{'fixture':True})
        self.assertEqual(plan['proposedRoutes']['foreign'],existing['foreign'])
        self.assertEqual(len(plan['proposedRoutes']),44)
        existing['foreign']['uri']='/mcp'
        existing['foreign']['methods']=rows['mcp']['methods'] if 'mcp' in rows else next(r['methods'] for r in rows.values() if r.get('uri')=='/mcp')
        with self.assertRaisesRegex(ValueError,'SELECTOR_COLLISION'):preparation.compile_gateway_plan(existing,runtime,refs,package,{'fixture':True})

    def test_closed_admin_key_parser_accepts_only_selected_literal_section(self):
        raw=b'deployment:\n  role: traditional\n  admin:\n    admin_key:\n      - name: admin\n        key: "0123456789abcdef0123456789abcdef"\n        role: admin\n    admin_listen:\n      ip: 127.0.0.1\n'
        self.assertEqual(g.selected_admin_key(raw),'0123456789abcdef0123456789abcdef')
        for bad in (raw.replace(b'deployment:',b'other:'),raw.replace(b'"0123456789abcdef0123456789abcdef"',b'${SECRET}'),
                    raw.replace(b'        role: admin',b'        role: admin\n        role: viewer')):
            with self.assertRaises(ValueError):g.selected_admin_key(bad)


class NativeNamespaceTransport(unittest.TestCase):
    def test_actual_child_setns_loopback_http_leaves_parent_namespace_unchanged(self):
        if not hasattr(os,'setns'):
            if os.environ.get('OUF_NATIVE_NAMESPACES') == '1':self.fail('os.setns is required in native CI')
            self.skipTest('local Python lacks os.setns; native CI requires it')
        reader,writer=os.pipe();pid=os.fork()
        if pid==0:
            os.close(reader)
            try:
                fd=os.open('/proc/self/ns/net',os.O_RDONLY);os.setns(fd,0);os.close(fd)
                from http.server import HTTPServer,BaseHTTPRequestHandler
                state={'existing':{'id':'existing','uri':'/retained','methods':['GET']}}
                class Handler(BaseHTTPRequestHandler):
                    def log_message(self,*args):pass
                    def answer(self,value):
                        raw=json.dumps(value).encode();self.send_response(200)
                        self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
                    def do_GET(self):
                        assert self.headers['X-API-KEY']=='0123456789abcdef0123456789abcdef'
                        self.answer({'total':len(state),'list':[{'value':r} for r in state.values()]})
                    def do_PUT(self):
                        value=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                        state[value['id']]=value;self.answer({'value':value})
                server=HTTPServer(('127.0.0.1',9180),Handler)
                os.write(writer,b'READY');os.close(writer);server.serve_forever()
            except BaseException:
                os.write(writer,b'UNAVAILABLE');os._exit(1)
        os.close(writer);status=os.read(reader,32);os.close(reader)
        if status!=b'READY':
            os.waitpid(pid,0)
            if os.environ.get('OUF_NATIVE_NAMESPACES')=='1':self.fail('native namespace HTTP fixture unavailable')
            self.skipTest('local kernel denies native setns/socket; native CI forbids this skip')
        def stop():
            os.kill(pid,signal.SIGTERM);os.waitpid(pid,0)
        self.addCleanup(stop)
        temporary=tempfile.TemporaryDirectory(dir=ROOT,prefix='gateway-netns-');self.addCleanup(temporary.cleanup)
        directory=Path(temporary.name);directory.chmod(0o700);config=directory/'config.yaml'
        config.write_text('deployment:\n  admin:\n    admin_key:\n      - name: admin\n        key: 0123456789abcdef0123456789abcdef\n        role: admin\n')
        config.chmod(0o600)
        actual={'Id':'a'*64,'Name':'/ouf-apisix','Image':'sha256:'+'b'*64,
                'Config':{},'HostConfig':{},'NetworkSettings':{},
                'Mounts':[{'Destination':'/usr/local/apisix/conf/config.yaml','Type':'bind','RW':False,'Source':str(config)}],
                'State':{'Running':True,'Paused':False,'Pid':pid,'StartedAt':'fixture-generation'}}
        engine=Engine.__new__(Engine);engine.request=lambda *args:(200,copy.deepcopy(actual))
        binding=g.NamespaceAdmin.observe(engine,str(config));transport=g.NamespaceAdmin(engine,binding)
        stop_thread=threading.Event();worker=threading.Thread(target=stop_thread.wait);worker.start()
        self.addCleanup(lambda:(stop_thread.set(),worker.join(timeout=5)))
        self.assertTrue(worker.is_alive())
        before=os.stat('/proc/self/ns/net');rows=transport.routes();self.assertEqual(set(rows),{'existing'})
        route={'id':'created','uri':'/new','methods':['GET']}
        self.assertEqual(transport.request('PUT','/apisix/admin/routes/created',route)[0],200)
        self.assertEqual(transport.routes()['created'],route)
        self.assertTrue(worker.is_alive())
        after=os.stat('/proc/self/ns/net');self.assertEqual((before.st_dev,before.st_ino),(after.st_dev,after.st_ino))


if __name__=='__main__':unittest.main()
