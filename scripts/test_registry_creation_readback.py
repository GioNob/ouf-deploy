import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import socketserver
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('reader',ROOT/'read-chatbot-registry-creation-20261015.py')
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
PRIVATE='PRIVATE_SENTINEL_MUST_NOT_PRINT'

def sample():
    request={'Image':'sha256:'+'4'*64,'Env':['SECRET='+PRIVATE],
        'Entrypoint':['java'],'HostConfig':{'OomKillDisable':False}}
    actual={'Id':'1'*64,'Name':'/ouf-semantic-cutover-'+'a'*64,'Image':request['Image'],
        'Config':{k:v for k,v in request.items() if k!='HostConfig'},
        'HostConfig':{'OomKillDisable':None},'State':{'Status':'created','Running':False,
            'Paused':False,'Pid':0,'StartedAt':'','ExitCode':0},'RestartCount':0,
        'Mounts':[],'NetworkSettings':{}}
    return request,actual

class ReaderTest(unittest.TestCase):
    def setUp(self):r.ERRORS.clear();r.GET_REQUESTS=0
    def test_created_container_reports_exact_comparator_field_without_configuration_values(self):
        request,actual=sample();value=r.creation_comparison(request,actual,'a'*64)
        self.assertFalse(value['currentComparatorConfigurationPass'])
        self.assertEqual(value['effectiveHostConfigurationMismatchFields'],['OomKillDisable'])
        self.assertNotIn(PRIVATE,json.dumps(value));self.assertTrue(value['exactCreatedState'])
        actual['Config']['Env']=['OTHER_PRIVATE_VALUE']
        self.assertEqual(r.creation_comparison(request,actual,'a'*64)['configurationMismatchFields'],['Env'])
    def test_running_oom_pair_is_only_observed_under_existing_running_comparator(self):
        request,actual=sample();actual['State'].update(Running=True,Status='running',Pid=123)
        value=r.creation_comparison(request,actual,'a'*64)
        self.assertTrue(value['currentComparatorConfigurationPass']);self.assertFalse(value['exactCreatedState'])
        actual['HostConfig']['OomKillDisable']=True
        self.assertFalse(r.creation_comparison(request,actual,'a'*64)['currentComparatorConfigurationPass'])
    def test_only_allowlisted_creation_codes_are_publicly_projected(self):
        raw=json.dumps({'MESSAGE':'CreationDenied: CREATION_CONFIG_DRIFT\nCreationDenied: '+PRIVATE}).encode()
        value=r.journal_projection(raw)
        self.assertEqual(value['observedCreationCodes'],['CREATION_CONFIG_DRIFT'])
        self.assertNotIn(PRIVATE,json.dumps(value))
    def test_actual_unix_http_requests_are_get_only_and_validate_selector_before_connect(self):
        calls=[]
        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                line=self.rfile.readline().decode().strip();calls.append(line)
                while self.rfile.readline() not in (b'\r\n',b''):pass
                body=b'{}'
                self.wfile.write(b'HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\n'+body)
        with tempfile.TemporaryDirectory(dir=ROOT) as temp:
            path=Path(temp)/'engine.sock'
            with socketserver.UnixStreamServer(str(path),Handler) as server:
                thread=threading.Thread(target=server.serve_forever);thread.start()
                try:
                    s=path.stat();engine={'socketPath':str(path),'socketBinding':
                        [s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode&0o777]}
                    self.assertEqual(r.engine_get(engine,'1'*64),(200,{}))
                    with self.assertRaisesRegex(ValueError,'EXACT_CONTAINER_SELECTOR_REQUIRED'):
                        r.engine_get(engine,'anything?start=true')
                finally:server.shutdown();thread.join()
        self.assertEqual(calls,['GET /v1.44/containers/'+'1'*64+'/json HTTP/1.1'])
        self.assertEqual(r.GET_REQUESTS,1)
    def test_complete_bound_main_reports_owner_and_registry_history_without_writing(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temp:
            base=Path(temp);base.chmod(0o700);context=base/'context';context.mkdir(mode=0o700)
            owner=base/'owner';owner.mkdir(mode=0o700)
            registry_root=context/'registry';registry_root.mkdir(mode=0o700)
            paths={'root':str(registry_root)}
            for name in ('transition','evidence','before','retirementBefore','node','backup'):
                p=registry_root/name;p.mkdir(mode=0o700);paths[name]=str(p)
            request,new=sample();_,old=sample();old['Id']='2'*64
            _,pg=sample();pg['Id']='3'*64;pg['State'].update(Status='running',Running=True,Pid=3)
            pin=r.runtime_binding(old);pgpin=r.runtime_binding(pg)
            intents={phase:{} for phase in r.REGISTRY_PHASES}
            intents['QUIESCE_PRODUCERS']={'producerBindings':[pin]}
            intents['RELEASE_OLD_ENDPOINT']={'containerId':old['Id']}
            prepared={'engine':{},'registry':{'directoryPlan':paths,'intents':intents,
                'creationRequest':request,'postgresRuntimeBinding':pgpin},
                'cohortPlan':{'replacements':[{'module':'udp','oldRuntimeBinding':pin}]}}
            bundle={'prepared':prepared,'sources':{}}
            def put(p,value):
                p=Path(p);p.write_text(json.dumps(value,sort_keys=True,separators=(',',':')));p.chmod(0o600)
            put(context/'bundle.json',bundle)
            directories={}
            for name in ('authorization','containers','databases','gateway','gatewayRuntime'):
                p=context/name;p.mkdir(mode=0o700);directories[name]=str(p)
            process={'authorityDirectory':str(context),
                'unit':'ouf-file-cohort-b05102a00d9f20ec6a935e1de201d4a9.service',
                'bundle':{'path':str(context/'bundle.json'),'sha256':r.digest(bundle)},'directoryPlan':directories}
            scopes={'finiteActionProcess':process,'policyTokenLegacyRetirement':{'logicalOwnerScopeHash':'0'*64},
                'policyTokenFirstControlledGrant':{'credentialOperation':'1'*64,'sessionOperation':'2'*64},
                'policyTokenOutputCustody':{'path':str(owner/'token-output')},
                'policyTokenOwnerInstallation':{'journalPath':str(owner),'stageManifestHash':'3'*64}}
            authority=dict(scopes);auth=r.digest(authority);put(context/'authority.json',authority)
            review={'sourceClosure':{'declaration':{'sourceCommit':r.SOURCE}},'scopes':scopes,
                'privateInputHashes':{'preparedInputs':r.digest(prepared)}}
            put(context/'review.json',review)
            put(context/'delivery-status.json',{'authorityHash':auth,'phase':'PAUSED_REQUIRES_RECONCILIATION','reason':'CreationDenied'})
            row={'schema':'ouf.semantic-cutover-journal.v2','state':'IN_FLIGHT','version':9,'nextPhase':4,
                'transitionAuthorityEvidenceHash':auth,'creationRequestHash':r.digest(request),
                'predecessorHistoryHash':'4'*64,'predecessorIncidentRef':'5'*64,
                'deploymentProfile':'fixture','executionProfileHash':'6'*64,
                'effects':[{'phase':phase,'state':'APPLIED' if i<4 else 'IN_FLIGHT'}
                    for i,phase in enumerate(r.REGISTRY_PHASES[:5])],
                'databaseMayHaveChanged':False,'applicationWritesMayHaveOccurred':False}
            fields=('transitionAuthorityEvidenceHash','creationRequestHash','predecessorHistoryHash',
                'predecessorIncidentRef','deploymentProfile','executionProfileHash')
            row['contextHash']=r.digest({k:row[k] for k in fields})
            new['Name']='/ouf-semantic-cutover-'+row['contextHash']
            put(Path(paths['transition'])/'recovery.json',row)
            put(Path(directories['containers'])/'recovery.json',{'schema':'fixture','version':1,
                'effects':[],'nextStep':0,'createdAt':1.25})
            def get(engine,selector):
                if selector.startswith('ouf-semantic-cutover-'):return 200,copy.deepcopy(new)
                return 200,copy.deepcopy({old['Id']:old,pg['Id']:pg}[selector])
            before={str(p):p.read_bytes() for p in base.rglob('*') if p.is_file()}
            output=io.StringIO()
            with patch.object(r,'CONTEXT',context),patch.object(r,'PARENT',base),patch.object(r,'OWNER_ROOT',owner),\
                patch.object(r,'AUTHORITY',auth),patch.object(r,'REVIEW',r.digest(review)),\
                patch.object(r,'systemd'),patch.object(r,'journal'),patch.object(r,'source_stage'),\
                patch.object(r,'engine_get',side_effect=get),contextlib.redirect_stdout(output):r.main()
            after={str(p):p.read_bytes() for p in base.rglob('*') if p.is_file()}
            self.assertEqual(before,after);self.assertNotIn(PRIVATE,output.getvalue())
            rows=[json.loads(line) for line in output.getvalue().splitlines()]
            self.assertTrue(rows[-1]['complete'],rows[-1])
            self.assertTrue(any(x.get('nextPhaseName')=='CREATE_REPLACEMENT' for x in rows))
            self.assertTrue(any(x.get('hostConfigurationMismatchFields')==['OomKillDisable'] for x in rows))

if __name__=='__main__':unittest.main()
