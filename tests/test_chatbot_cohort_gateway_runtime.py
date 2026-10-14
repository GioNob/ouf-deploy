"""Prepared key custody and governed same-image APISIX replacement.

Uses real dual signatures and private Journal. Docker transport/effects are an
explicit disposable fixture; namespace HTTP is qualified separately.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

sys.path.insert(0,str(Path(__file__).resolve().parent))
from test_chatbot_cohort_gateway import crypto,g,preparation,GATEWAY,ROOT
from test_chatbot_cohort_containers import DockerFixture
from tools.chatbot_file_cohort import gateway_runtime as r
from tools.semantic_lease_recovery.recovery_journal import Journal

KEY='9'*64
CONFIG=b'nginx_config:\n  envs:\n  - RETAINED_KEY\ndeployment:\n  admin:\n    admin_key:\n      - name: admin\n        key: 0123456789abcdef0123456789abcdef\n        role: admin\n'

class APISIXFixture(DockerFixture):
    def request(self,method,path,body):
        p=urlsplit(path);parts=p.path.split('/');stage=parts[-1]
        if method=='POST' and stage in ('stop','connect'):
            self.calls.append((stage,parts[3],copy.deepcopy(body)))
            if self.omit_effect==stage:
                self.omit_effect=None;return 500,{},False
            if stage=='stop':
                self.find(parts[3])['State'].update(Running=False,Pid=0,Status='exited')
            else:
                self.find(body['Container'])['NetworkSettings']['Networks']['ouf-gateway-control']=copy.deepcopy(body['EndpointConfig'])
            drop=self.lose_ack==stage
            if drop:self.lose_ack=None
            return 204,None,drop
        return super().request(method,path,body)

class GatewayRuntime(unittest.TestCase):
    def fixture(self):
        f=crypto.SignedCutover();f.setUp();self.addCleanup(f.doCleanups)
        private=f.root/'gateway';private.mkdir(mode=0o700)
        original=private/'original.yaml';original.write_bytes(CONFIG);original.chmod(0o644)
        updated=private/'new.yaml';updated.write_bytes(preparation.expose_environment(CONFIG,'PROPOSAL_KEY'));updated.chmod(0o444)
        _,old_binding=g.private_config(original);_,new_binding=g.private_config(updated)
        old={'Id':'a'*64,'Name':'/ouf-apisix','Image':'sha256:'+'b'*64,'RestartCount':0,
             'State':{'Running':True,'Paused':False,'Status':'running','Pid':99,'StartedAt':'2026-10-14T00:00:00Z'},
             'Config':{'Image':'apisix:retained','User':'apisix','Hostname':'a'*12,'Env':['RETAINED_KEY='+'1'*64],
                       'Entrypoint':['/docker-entrypoint.sh'],'Cmd':['docker-start'],'Labels':{}},
             'HostConfig':{'OomKillDisable':None,'NetworkMode':'ouf-backend','RestartPolicy':{'Name':'unless-stopped','MaximumRetryCount':0},
                           'Binds':[str(original)+':/usr/local/apisix/conf/config.yaml:ro']},
             'Mounts':[{'Type':'bind','Source':str(original),'Destination':'/usr/local/apisix/conf/config.yaml','RW':False}],
             'NetworkSettings':{'Networks':{n:{'NetworkID':c*64,'Aliases':['ouf-apisix'],'IPAMConfig':None}
                 for n,c in [('ouf-backend','c'),('ouf-gateway-control','d')]}}}
        plan=r.compile_runtime(old,old_binding,new_binding,'PROPOSAL_KEY',KEY,hashlib.sha256(KEY.encode()).hexdigest(),'fixture')
        raw=json.loads(f.authority);raw['gatewayRuntimeInstallation']=r.runtime_scope(plan)
        f.authority=crypto.encoded(raw);f.approval['executionAuthorityHash']=crypto.sha(f.authority)
        f.write(f.mandate,crypto.encoded(f.approval));f.approved=crypto.sha(f.mandate.read_bytes())
        for role in f.grant['roles']:f.sign(role)
        action=g.AggregateAction(f.gate(),f.authority,f.expected['sourceClosureHash'])
        # Docker fixture preserves creation request bytes and reconstructs inspect state.
        native=APISIXFixture(f.root,{'old':old},{'replacements':[{'name':'ouf-apisix','oldMounts':plan['expectedMounts']}]})
        self.addCleanup(native.close)
        journal=private/'journal';journal.mkdir(mode=0o700)
        owner=r.GatewayRuntime(action,native.engine,plan,Journal(journal))
        class Ready:
            def request(self,*args):return 200,{'total':0,'list':[]}
            def routes(self):return {}
        owner.transport=lambda:Ready()
        owner.initialize();return owner,native,f

    def test_two_networks_old_retained_same_image_key_and_config_exact(self):
        owner,native,_=self.fixture();result=owner.apply();owner.apply()
        self.assertTrue(result['oldContainerRetained'])
        old=native.find(owner.plan['retiredName']);new=native.find('ouf-apisix')
        self.assertFalse(old['State']['Running']);self.assertEqual(new['Image'],old['Image'])
        self.assertIsNone(old['HostConfig']['OomKillDisable'])
        self.assertIsNone(new['HostConfig']['OomKillDisable'])
        self.assertIs(owner.plan['creationRequest']['HostConfig']['OomKillDisable'],False)
        self.assertEqual(set(new['NetworkSettings']['Networks']),{'ouf-backend','ouf-gateway-control'})
        self.assertEqual(r.environment(new['Config']['Env'])['PROPOSAL_KEY'],KEY)
        self.assertEqual(new['Mounts'][0]['Source'],owner.plan['newConfigBinding']['path'])
        self.assertEqual([c[0] for c in native.calls],['update','stop','rename','create','connect','start','update'])

    def test_external_admin_key_pin_survives_gateway_replacement_plan(self):
        owner,native,_=self.fixture()
        old=native.find('ouf-apisix')
        binding={'path':g.EXTERNAL_ADMIN_KEY,'sha256':'a'*64,'metadata':[1,2,1000,1000,0o100600,1,32,3,4]}
        args=(old,owner.plan['oldConfigBinding'],owner.plan['newConfigBinding'],
              'PROPOSAL_KEY',KEY,hashlib.sha256(KEY.encode()).hexdigest(),'fixture')
        with patch.object(r,'private_config',return_value=(b'synthetic',binding)) as read:
            planned=r.compile_runtime(*args,admin_key_binding=binding)
        read.assert_called_once_with(g.EXTERNAL_ADMIN_KEY,binding)
        self.assertEqual(planned['adminKeyBinding'],binding)
        self.assertEqual(r.proposed_transport(planned)['adminKeyBinding'],binding)
        with patch.object(r,'private_config',side_effect=ValueError('CREDENTIAL_DRIFT')):
            with self.assertRaisesRegex(ValueError,'CREDENTIAL_DRIFT'):
                r.compile_runtime(*args,admin_key_binding=binding)

    def test_every_write_ack_loss_reconciles_without_second_effect(self):
        for effect in ('update','stop','rename','create','connect','start'):
            with self.subTest(effect=effect):
                owner,native,_=self.fixture();native.lose_ack=effect
                with self.assertRaises(Exception):owner.apply()
                self.assertEqual(owner.record()['effects'][-1]['state'],'CLAIMED')
                owner.apply();self.assertEqual(len(native.calls),7)

    def test_changed_oom_control_still_fails_exact_host_readback(self):
        owner,native,_=self.fixture();owner.apply()
        native.find('ouf-apisix')['HostConfig']['OomKillDisable']=True
        with self.assertRaisesRegex(ValueError,'CANDIDATE_HOST_DRIFT'):owner.apply()
        self.assertEqual(len(native.calls),7)

    def test_second_generation_same_id_is_never_adopted_on_resume(self):
        owner,native,_=self.fixture();owner.apply()
        actual=native.find('ouf-apisix')
        actual['State'].update(Pid=9999,StartedAt='2026-10-14T04:00:00Z')
        self.assertEqual(actual['RestartCount'],0)
        with self.assertRaisesRegex(ValueError,'STARTED_GENERATION_CHANGED'):owner.apply()
        self.assertEqual(len(native.calls),7)

    def test_unknown_connect_does_not_retry(self):
        owner,native,_=self.fixture();native.omit_effect='connect'
        with self.assertRaisesRegex(ValueError,'NETWORK_DRIFT'):owner.apply()
        with self.assertRaisesRegex(ValueError,'NETWORK_DRIFT'):owner.apply()
        self.assertEqual(sum(c[0]=='connect' for c in native.calls),1)

    def test_revoked_human_denies_reconciliation(self):
        owner,native,f=self.fixture();native.lose_ack='create'
        with self.assertRaises(Exception):owner.apply()
        f.approval['state']='REVOKED';f.write(f.mandate,crypto.encoded(f.approval))
        with self.assertRaisesRegex(Exception,'MANDATE_CHANGED'):owner.apply()
        self.assertEqual(len(native.calls),4)

    def test_private_key_reused_and_partial_never_regenerated(self):
        owner,_,f=self.fixture();directory=f.root/'key';directory.mkdir(mode=0o700)
        try:first,binding,created=preparation.stage_proposal_key(directory)
        except OSError as error:
            if os.environ.get('OUF_NATIVE_UIDS')=='1':raise
            if error.errno not in (1,22):raise
            self.skipTest('local user namespace cannot own GID10001; native CI requires it')
        self.assertTrue(created);self.assertEqual(binding['gid'],10001);self.assertEqual(binding['modeOctal'],'0440')
        with patch.object(preparation.secrets,'token_hex',side_effect=AssertionError('must not generate')):
            second,same,created=preparation.stage_proposal_key(directory)
        self.assertFalse(created);self.assertEqual((first,binding),(second,same))
        path=Path(binding['path']);path.chmod(0o600);path.write_bytes(b'partial');path.chmod(0o440)
        with patch.object(preparation.secrets,'token_hex',side_effect=AssertionError('must not generate')):
            with self.assertRaisesRegex(ValueError,'PARTIAL_OR_CONFLICTING'):preparation.stage_proposal_key(directory)

    def test_complete_collector_uses_current_projection_all_upstreams_and_one_staged_key(self):
        owner,native,f=self.fixture()
        from tools.compile_config import compile_config
        from tools.apply_installation_projection import apply_projection
        compiled=compile_config(GATEWAY/'ouf-config')
        projection=json.loads((GATEWAY/'tests/fixtures/installation-projection-lab.json').read_text())
        runtime=apply_projection(compiled,projection)
        refs={'oidcSecretRef':'$ENV://OIDC_SECRET','delegationKeyEnv':'DKEY','authorizationKeyEnv':'AKEY',
              'udpKeyEnv':'UKEY','semanticReadKeyEnv':'RKEY','semanticProposalKeyEnv':'PKEY',
              'semanticReadRouteIds':{'search':'semantic-search','get':'semantic-get'}}
        previous=preparation.materialize_target(runtime,refs)
        previous['foreign']={'id':'foreign','uri':'/foreign','methods':['GET']}
        package=f.root/'package';package.mkdir(mode=0o700)
        gateway=package/'gateway';gateway.mkdir(mode=0o700)
        raw=g.encoded(compiled);(gateway/'compiled-route-declarations.json').write_bytes(raw)
        projected=f.root/'projection.json';projected.write_bytes(g.encoded(projection));projected.chmod(0o600)
        _,projected_binding=g.private_config(projected)
        record={'module':'gateway','artifactKind':'SOURCE_AND_ROUTE_PACKAGE','sourceCommit':'a'*40,
                'cohortSourceLockSha256':'b'*64,'compiledRouteDeclarationsSha256':hashlib.sha256(raw).hexdigest(),
                'files':{'compiled-route-declarations.json':hashlib.sha256(raw).hexdigest()}}
        actual=copy.deepcopy(native.find('ouf-apisix'))
        actual['Config']['Env']=[name+'='+c*64 for name,c in zip(('DKEY','AKEY','UKEY','RKEY'),'1234')]
        observations={'ouf-apisix':actual}
        selected=[('ouf-udp','ouf-udp-object-resolution'),('ouf-onboarding','ouf-onboarding'),
                  ('ouf-ingestion','ouf-ingestion-runtime'),('ouf-mcp','ouf-mcp-server'),
                  ('ouf-semantic','ouf-semantic'),('ouf-gateway-control-plane','ouf-gateway-control-plane')]
        for number,(name,alias) in enumerate(selected,1):
            row=copy.deepcopy(actual);row['Id']=format(number,'064x');row['Name']='/'+name
            net='ouf-gateway-control' if name=='ouf-gateway-control-plane' else 'ouf-backend'
            row['NetworkSettings']['Networks']={net:copy.deepcopy(actual['NetworkSettings']['Networks'][net])}
            row['NetworkSettings']['Networks'][net]['Aliases']=[name,alias]
            observations[name]=row
        native.engine.request=lambda method,path,body=None:(200,copy.deepcopy(observations[path.split('/')[3]]))
        binding={'runtimeBinding':g.Engine.runtime_binding(actual),'configBinding':owner.plan['oldConfigBinding'],
                 'networkNamespace':{'device':1,'inode':2},'transport':'EXACT_APISIX_NETNS_LOOPBACK_HTTP',
                 'port':9180,'maximumResponseBytes':g.MAX_RESPONSE,'timeoutSeconds':10}
        output=f.root/'prepared';output.mkdir(mode=0o700)
        # This seam isolates key staging already covered by the native UID test.
        key_binding={'path':str(output/'semantic-proposal-owner.key'),'sha256':hashlib.sha256(KEY.encode()).hexdigest(),
                     'uid':0,'gid':10001,'modeOctal':'0440','bytes':64}
        with patch.object(g.NamespaceAdmin,'observe',return_value=binding), \
             patch.object(g.NamespaceAdmin,'routes',return_value=previous), \
             patch.object(preparation,'stage_proposal_key',return_value=(KEY,key_binding,True)):
            result=preparation.prepare_gateway(package,record,native.engine,projected_binding,'ouf-semantic',output,'fixture')
        self.assertIsNotNone(result['gatewayRuntimePlan'])
        self.assertEqual(result['gatewayPlan']['proposalKeyBinding'],result['proposalKeyBinding'])
        self.assertEqual(result['gatewayPlan']['proposalIdentity'],result['proposalIdentity'])
        self.assertEqual(result['proposalIdentity'],{
            'issuer':runtime['x-ouf-installation']['issuerUrl'].rstrip('/'),
            'audience':runtime['x-ouf-installation']['gatewayAudience'],
            'workload':runtime['x-ouf-installation']['mcpServiceIdentity']})
        self.assertEqual(result['gatewayRuntimePlan']['proposalKeyHash'],key_binding['sha256'])
        self.assertEqual(result['runtimeMutations'],0)
        routes=result['gatewayPlan']['proposedRoutes']
        self.assertEqual(len(routes),44);self.assertEqual(routes['foreign'],previous['foreign'])
        self.assertIn('ouf-gateway-control-plane:8081',{n for row in routes.values() for n in row.get('upstream',{}).get('nodes',{})})
        self.assertEqual(result['gatewayPlan']['transportBinding'],r.proposed_transport(result['gatewayRuntimePlan']))

    def test_exact_allowlist_delta_and_source_routes_reference_match(self):
        updated=preparation.expose_environment(CONFIG,'PROPOSAL_KEY')
        self.assertEqual(updated.replace(b'  - PROPOSAL_KEY\n',b''),CONFIG)
        self.assertEqual(preparation.expose_environment(updated,'PROPOSAL_KEY'),updated)
        from tools.compile_config import compile_config
        from tools.apply_installation_projection import apply_projection
        runtime=apply_projection(compile_config(GATEWAY/'ouf-config'),json.loads((GATEWAY/'tests/fixtures/installation-projection-lab.json').read_text()))
        refs={'oidcSecretRef':'$ENV://OIDC_SECRET','delegationKeyEnv':'DKEY','authorizationKeyEnv':'AKEY',
              'udpKeyEnv':'UKEY','semanticReadKeyEnv':'RKEY','semanticProposalKeyEnv':'PKEY',
              'semanticReadRouteIds':{'search':'semantic-search','get':'semantic-get'}}
        routes=preparation.materialize_target(runtime,refs)
        values={n:c*64 for n,c in zip(('DKEY','AKEY','UKEY','RKEY'),'1234')}
        self.assertEqual(preparation.observe_references(routes,runtime,values,'PKEY'),refs)
        runtime['x-ouf-installation']['mcpServiceIdentity']='wrong-current-workload'
        with self.assertRaisesRegex(ValueError,'IDENTITY_DRIFT'):preparation.observe_references(routes,runtime,values,'PKEY')

if __name__=='__main__':unittest.main()
