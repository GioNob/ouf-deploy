"""Actual qualified archive reconciliation; only disposable CI files are changed."""
import importlib.util
import contextlib
import copy
import http.server
import io
import json
import os
from pathlib import Path
import tempfile
import signal
import socketserver
import threading
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
old=module('original_packet',ROOT/'scripts/prepare-ingestion-rollout-packet-20261020.py')
r=module('reconciler',ROOT/'scripts/reconcile-ingestion-frame-mac-20261020.py')
fixtures=module('packet_fixtures',ROOT/'tests/test_ingestion_rollout_packet.py')

class ActualRetainedArchive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.context=tempfile.TemporaryDirectory(dir=os.environ['OUF_TEST_ROOT']);cls.addClassCleanup(cls.context.cleanup)
        cls.root=Path(cls.context.name)
        with open(os.environ['OUF_CANDIDATE_ZIP'],'rb')as stream:cls.original=old.authenticate_candidate(stream,cls.root)

    def test_exact_ci_envelope_reconciles_without_recreation_or_archive_changes(self):
        before={p.name:r.metadata(p.stat())for p in self.root.iterdir()}
        with patch.object(r,'RETAINED',self.root):proof=r.native_header()
        self.assertEqual(proof['imageConfig'],self.original['nativeImageAudit']['imageConfig'])
        self.assertTrue(proof['exactJarAnd18SqlQualificationReused']);self.assertFalse(proof['archiveAuditReplayed'])
        self.assertEqual(before,{p.name:r.metadata(p.stat())for p in self.root.iterdir()})
        self.assertFalse(proof['archiveRecreated']);self.assertFalse(proof['packageDownloaded'])

    def test_one_changed_native_archive_byte_blocks_even_if_metadata_is_valid(self):
        path=self.root/'image.native-tagless.docker.tar'
        with path.open('r+b')as f:
            original=f.read(1);f.seek(0);f.write(bytes([original[0]^1]));f.flush();os.fsync(f.fileno())
        try:
            with patch.object(r,'RETAINED',self.root),self.assertRaisesRegex(r.Denied,'QUALIFIED_RETAINED_NATIVE_ARCHIVE_BYTES_REQUIRED'):
                r.native_header()
        finally:
            with path.open('r+b')as f:f.write(original);f.flush();os.fsync(f.fileno())

    def test_complete_reconciliation_real_unix_gets_and_root_owned_gateway_config(self):
        with tempfile.TemporaryDirectory(dir=os.environ['OUF_TEST_ROOT'])as scope:
            scope=Path(scope);owner_dir=scope/'owner';owner_dir.mkdir(mode=0o700)
            config=scope/'gateway.yaml';config.write_bytes(b'nginx_config:\n  envs:\n  - KEEP_EXISTING\n');config.chmod(0o600)
            original_config,binding=r.gateway.private_config(config)
            ingestion,draft,image=fixtures.fixture();gateway=copy.deepcopy(ingestion)
            ingestion['Config']=copy.deepcopy(self.original['nativeImageAudit']['imageConfig'])
            ingestion['Config']['Hostname']='a'*12
            ingestion['Config']['Env']=[*ingestion['Config'].get('Env',[]),'PRIVATE=ci-only-do-not-print']
            for actual in (ingestion,gateway):actual['State']={'Running':True,'Pid':2,'StartedAt':'ci-fixture'}
            gateway['Id']='d'*64;gateway['Name']='/gateway';gateway['Config']['User']='0'
            gateway['HostConfig']['Binds']=[str(config)+':'+r.frames.CONFIG_DESTINATION+':ro']
            gateway['Mounts']=[{'Type':'bind','Source':str(config),'Destination':r.frames.CONFIG_DESTINATION,'RW':False}]
            actual={'ingestion':ingestion,'gateway':gateway}
            for v in actual.values():v['Config']['MacAddress']=v['NetworkSettings']['Networks']['fixture_net']['MacAddress']
            pins={n:r.runtime(v)for n,v in actual.items()}
            info={'ServerVersion':'29.8.1','OSType':'linux','Architecture':'x86_64','Driver':'overlayfs',
                  'DriverStatus':[['driver-type','io.containerd.snapshotter.v1']]}
            calls=[]
            class Handler(http.server.BaseHTTPRequestHandler):
                def log_message(self,*_):pass
                def do_GET(self):
                    calls.append(self.path)
                    if self.path=='/v1.44/info':value=info
                    else:
                        selected=[v for v in actual.values()if self.path=='/v1.44/containers/'+v['Id']+'/json']
                        if len(selected)!=1:self.send_error(404);return
                        value=selected[0]
                    raw=r.encoded(value);self.send_response(200);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
            class Server(socketserver.UnixStreamServer):allow_reuse_address=False
            sock=scope/'engine.sock';server=Server(str(sock),Handler);sock.chmod(0o660)
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            try:
                s=sock.stat();engine={'socketPath':str(sock),'socketBinding':[s.st_dev,s.st_ino,s.st_uid,s.st_gid,0o660]}
                key=scope/'approved-key'
                owner={'engine':engine,'currentApplications':pins,'gateway':{'transport':{'configBinding':binding}},
                       'bindingPlan':{'candidatePayload':{'secrets':{'references':{'ingestionReadOwnerKey':str(key)}}}}}
                owner_hash=r.digest(owner);r.write_new(owner_dir/'execution-plan.json',owner)
                completed={'complete':True,'planHash':owner_hash};result_hash=r.digest(completed);r.write_new(owner_dir/'update-result.json',completed)
                draft.update(schema='ouf.ingestion-startup-bootstrap-draft.v1',runtimeAuthorityIssued=False,expectedRuntimeBindings=pins,
                             gateway={'environmentAddition':{r.frames.OWNER_ENV:{'path':str(key)}}},routeDraft={'fixture':'retained80'})
                draft['ingestion']['readOnlyBindAddition']['Source']=str(key)
                draft_path=scope/'draft.json';draft_hash=r.digest(draft);r.write_new(draft_path,draft)
                logical=r.digest({'bootstrap':draft_hash,'zip':r.package.ZIP_SHA,'preparation':'ouf.ingestion-rollout-packet.v1'})
                old_claim=scope/('ingestion-rollout-packet-'+logical+'.claim.json')
                r.write_new(old_claim,{'contextPath':str(self.root),'logicalRef':logical,'runtimeAuthorityIssued':False,'automaticReplayAllowed':False})
                old_pin=r.read(old_claim)
                staged=scope/'staged';staged.mkdir(mode=0o700);staged_path=staged/'apisix-config.proposed.yaml'
                staged_path.write_bytes(r.frames.expose_owner_environment(original_config));staged_path.chmod(0o600)
                staged_before=r.gateway.private_config(staged_path)
                prior_logical=r.digest({'predecessor':r.parsed(old_claim),'bootstrap':draft_hash,'reconciliation':'ouf.ingestion-rollout-packet-reconcile.v1'})
                prior_claim=scope/('ingestion-rollout-packet-reconcile-'+prior_logical+'.claim.json')
                r.write_new(prior_claim,{'contextPath':str(staged),'predecessorContextPath':str(self.root),'logicalRef':prior_logical,'runtimeAuthorityIssued':False,'automaticReplayAllowed':False})
                prior_pin=r.read(prior_claim)
                archive_pins={p.name:r.metadata(p.stat())for p in self.root.iterdir()}
                with patch.object(r,'STAGED_CONTEXT',staged),patch.object(r,'RETAINED',self.root),patch.object(r,'OWNER',owner_dir),patch.object(r,'OWNER_PLAN',owner_hash),\
                     patch.object(r,'OWNER_RESULT',result_hash),patch.object(r,'BOOTSTRAP',draft_path),patch.object(r,'BOOTSTRAP_SHA',draft_hash),\
                     patch.object(r.sys,'argv',['<fixture>']),contextlib.redirect_stdout(io.StringIO())as output:
                    r.main()
                report=json.loads(output.getvalue());self.assertTrue(report['complete']);self.assertEqual(len(calls),5)
                self.assertTrue(report['observedEndpointMacsAndAddressesPreserved']);self.assertEqual(set(report['legacyMacNormalizedModules']),{'ingestion','gateway'})
                self.assertFalse(report['completedGatewayConfigStagingReplayed']);self.assertEqual(r.gateway.private_config(staged_path),staged_before)
                self.assertEqual(r.read(prior_claim),prior_pin)
                self.assertEqual(report['dedicatedKeyMetadataState'],'MISSING_AT_EXISTING_CUSTODIED_PARENT')
                self.assertFalse(key.exists());self.assertFalse(report['runtimeAuthorityIssued'])
                self.assertEqual(r.read(old_claim),old_pin);self.assertEqual(r.gateway.private_config(config,binding)[0],original_config)
                self.assertEqual(archive_pins,{p.name:r.metadata(p.stat())for p in self.root.iterdir()})
                self.assertNotIn('ci-only-do-not-print',output.getvalue())
                plan_path=Path(report['contextPath'])/'packet-plan.json';plan=r.parsed(plan_path,report['packetPlanHash'])
                self.assertEqual(plan['retainedGatewayConfig']['metadata'][2:5],binding['metadata'][2:5])
                self.assertFalse(plan['frames']['ingestion']['targetApplyAuthorized'])
                self.assertTrue(plan['frames']['gateway']['resolveGatewaySecretAfterNativeAuthorityRequired'])
            finally:signal.alarm(0);server.shutdown();server.server_close();thread.join(timeout=2)

if __name__=='__main__':unittest.main()
