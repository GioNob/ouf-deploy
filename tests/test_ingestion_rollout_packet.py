"""Private preparation adversarial contracts; native effects remain unqualified."""
import ast
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT=Path(__file__).resolve().parents[1]
PATH=ROOT/'scripts/prepare-ingestion-rollout-packet-20261020.py'
spec=importlib.util.spec_from_file_location('rollout_packet',PATH)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
f=m.frames;p=m.package

def fixture():
    config={'User':'10002:10002','Entrypoint':['java','-jar','/app/app.jar'],'Cmd':[],
            'WorkingDir':'/app','Env':['PATH=/opt/java/bin:/usr/bin','PRIVATE=ci-only-value'],
            'Labels':{'retain':'yes'},'Image':'sha256:'+'b'*64,'Hostname':'a'*12}
    endpoint={'NetworkID':'c'*64,'IPAddress':'192.0.2.8','GlobalIPv6Address':'2001:db8::8',
              'MacAddress':'02:42:c0:00:02:08','Aliases':['ingestion','a'*12,'a'*64],
              'IPAMConfig':None,'Links':None,'DriverOpts':{'fixture':'one'},'GwPriority':0}
    actual={'Id':'a'*64,'Name':'/ingestion','Image':'sha256:'+'b'*64,'Config':config,
            'HostConfig':{'RestartPolicy':{'Name':'unless-stopped','MaximumRetryCount':0},'Binds':['/old:/old:ro'],
                          'OomKillDisable':None,'Memory':1234567,'CapDrop':['ALL'],'ReadonlyRootfs':True},
            'Mounts':[{'Destination':'/old','Source':'/old','Type':'bind','RW':False}],
            'NetworkSettings':{'Networks':{'fixture_net':endpoint}}}
    draft={'candidate':{'sourceCommit':p.SOURCE},'ingestion':{'bootstrapCmd':list(m.FLAGS)if hasattr(m,'FLAGS')else
            ['--spring.flyway.enabled=false','--ouf.ingestion.startup.schema-mode=VALIDATE_ONLY'],
            'ownerReadEnvironmentAdditions':{'OUF_ING_GATEWAY_READ_ENABLED':'true'},
            'startupEnvironmentAddition':{'SPRING_FLYWAY_ENABLED':'false'},
            'readOnlyBindAddition':{'Type':'bind','RW':False,'Source':'/approved/key','Destination':'/run/secrets/key'}}}
    image={'User':'10002:10002','Entrypoint':config['Entrypoint'],'WorkingDir':'/app','Env':['JAVA_HOME=/opt/java']}
    return actual,draft,image

class Frames(unittest.TestCase):
    def test_complete_ingestion_template_preserves_resources_network_and_other_environment(self):
        actual,draft,image=fixture();before=copy.deepcopy(actual)
        result=f.frame('ingestion',actual,'sha256:'+'e'*64,image,draft)
        self.assertEqual(actual,before);request=result['requestTemplate']
        self.assertEqual(request['HostConfig']['Memory'],1234567)
        self.assertEqual(request['HostConfig']['RestartPolicy'],f.NO_RESTART)
        self.assertEqual(result['restoreRestartPolicy']['Name'],'unless-stopped')
        self.assertIn('PRIVATE=ci-only-value',request['Env']);self.assertIn('SPRING_FLYWAY_ENABLED=false',request['Env'])
        self.assertEqual(request['Labels']['retain'],'yes');self.assertEqual(request['Hostname'],'')
        ep=request['NetworkingConfig']['EndpointsConfig']['fixture_net']
        self.assertEqual(ep['Aliases'],['ingestion']);self.assertEqual(ep['IPAMConfig']['IPv4Address'],'192.0.2.8')
        self.assertEqual(ep['IPAMConfig']['IPv6Address'],'2001:db8::8');self.assertEqual(ep['MacAddress'],'02:42:c0:00:02:08')
        self.assertFalse(result['targetApplyAuthorized']);self.assertFalse(result['nativeCreationRoundTripQualified'])

    def test_gateway_secret_is_unresolved_and_one_selected_mount_source_changes(self):
        actual,draft,image=fixture();actual['Config']['User']='636:636';actual['HostConfig']['Binds']=['/retained/config:'+f.CONFIG_DESTINATION+':ro']
        actual['Mounts']=[{'Destination':f.CONFIG_DESTINATION,'Source':'/retained/config','Type':'bind','RW':False}]
        result=f.frame('gateway',actual,actual['Image'],image,draft,'/new/private/config')
        self.assertIn(f.OWNER_ENV+'='+f.SECRET_SLOT,result['requestTemplate']['Env'])
        self.assertEqual(result['requestTemplate']['HostConfig']['Binds'],['/new/private/config:'+f.CONFIG_DESTINATION+':ro'])
        self.assertTrue(result['resolveGatewaySecretAfterNativeAuthorityRequired'])

    def test_identity_collision_dependent_runtime_and_network_drift_block(self):
        for change in ('uid','entrypoint','ipam','link','privileged','env','volume','path'):
            with self.subTest(change=change):
                actual,draft,image=fixture()
                if change=='uid':image['User']='0'
                if change=='entrypoint':image['Entrypoint']=['sh']
                if change=='ipam':actual['NetworkSettings']['Networks']['fixture_net']['IPAMConfig']={'IPv4Address':'192.0.2.9'}
                if change=='link':actual['HostConfig']['VolumesFrom']=['other']
                if change=='privileged':actual['HostConfig']['Privileged']=True
                if change=='env':actual['Config']['Env'].append('SPRING_FLYWAY_ENABLED=true')
                if change=='volume':image['Volumes']={'/unreviewed':{}}
                if change=='path':image['Env']=['JAVA_HOME=/elsewhere']
                with self.assertRaises(ValueError):f.frame('ingestion',actual,'sha256:'+'e'*64,image,draft)

    def test_nginx_allowlist_exact_single_addition_idempotence_and_ambiguity(self):
        old=b'apisix:\n  node_listen: 8080\nnginx_config:\n  envs:\n  - KEEP_ONE\n  - KEEP_TWO\n  http: {}\n'
        new=f.expose_owner_environment(old)
        self.assertEqual(new.replace(('  - '+f.OWNER_ENV+'\n').encode(),b''),old)
        self.assertEqual(f.expose_owner_environment(new),new)
        for bad in (old+old,old.replace(b'  - KEEP_TWO',b'  - KEEP_ONE'),old+b'# '+f.OWNER_ENV.encode()+b'\n',old.replace(b'  envs:',b'  envs: []')):
            with self.assertRaises(ValueError):f.expose_owner_environment(bad)

class Package(unittest.TestCase):
    def synthetic(self,extra=None):
        manifest={'sourceCommit':p.SOURCE,'imageId':p.IMAGE,'sourceLockSha256':p.LOCK_SHA,'module':'ingestion',
                  'repository':'GioNob/ouf-ingestion-runtime','scanGate':'PASS_HIGH_CRITICAL_UNKNOWN_INCLUDING_UNFIXED',
                  'runtimeAuthorityIssued':False,'targetApplyAuthorized':False}
        scan={'SchemaVersion':2,'Metadata':{'ImageID':p.IMAGE},'Results':[{'Class':'lang-pkgs','Type':'jar'},{'Class':'os-pkgs','Type':'debian'}]}
        files={'image.docker.tar':b'fixture-tar','application.jar':b'fixture-jar','candidate-manifest.json':json.dumps(manifest).encode(),
               'package-record.json':json.dumps({'sourceCommit':p.SOURCE,'imageId':p.IMAGE,'module':'ingestion'}).encode(),
               'trivy-image.json':json.dumps(scan).encode(),'source-inventory.json':b'{}'}
        if extra:files.update(extra)
        files['SHA256SUMS']=''.join(hashlib.sha256(v).hexdigest()+'  '+k+'\n'for k,v in files.items()).encode()
        raw=io.BytesIO()
        with zipfile.ZipFile(raw,'w')as z:
            for name,value in files.items():z.writestr(name,value)
        return raw.getvalue()

    def test_all_members_authenticated_without_extracting(self):
        raw=self.synthetic();proof=p.inventory(io.BytesIO(raw),p.sha(raw),len(raw))
        output=io.BytesIO();p.copy_member(io.BytesIO(raw),'application.jar',output,proof)
        self.assertEqual(output.getvalue(),b'fixture-jar');self.assertFalse(proof['targetApplyAuthorized'])
        with self.assertRaisesRegex(ValueError,'EXACT_SCANNED_ZIP_REQUIRED'):p.inventory(io.BytesIO(raw+b'x'),p.sha(raw),len(raw))

    def test_path_traversal_checksum_drift_and_scan_failure_block(self):
        raw=self.synthetic({'../foreign':b'bad'})
        with self.assertRaisesRegex(ValueError,'SAFE_UNIQUE_PACKAGE'):p.inventory(io.BytesIO(raw),p.sha(raw),len(raw))
        for member,value in [('application.jar',b'changed'),('trivy-image.json',b'{}')]:
            raw=self.synthetic({member:value})
            if member=='application.jar':
                out=io.BytesIO()
                with zipfile.ZipFile(io.BytesIO(raw))as original,zipfile.ZipFile(out,'w')as z:
                    for row in original.infolist():z.writestr(row,b'tampered'if row.filename==member else original.read(row))
                raw=out.getvalue()
            with self.assertRaises(ValueError):p.inventory(io.BytesIO(raw),p.sha(raw),len(raw))

    def test_exact18_resources_are_independent_of_jar_metadata(self):
        jar=io.BytesIO()
        with zipfile.ZipFile(jar,'w')as z:
            for r in m.SQL_MANIFEST['migrations']:z.writestr('BOOT-INF/classes/db/migration/'+r['script'],b'not-qualified-sql')
            z.writestr('BOOT-INF/classes/fixture/IngestionValidateOnlyStartup.class',b'fixture')
        with self.assertRaisesRegex(ValueError,'EXACT18_UNCHANGED_MIGRATION_BYTES'):p.jar_proof(jar.getvalue(),m.SQL_MANIFEST)

class Boundaries(unittest.TestCase):
    def test_only_closed_engine_get_no_runtime_oauth_sql_or_key_read(self):
        tree=ast.parse(PATH.read_text());requests=[n for n in ast.walk(tree)if isinstance(n,ast.Call)and ast.unparse(n.func)=='connection.request']
        self.assertEqual(len(requests),2)
        self.assertTrue(all(ast.literal_eval(n.args[0])=='GET'for n in requests))
        calls={ast.unparse(n.func)for n in ast.walk(tree)if isinstance(n,ast.Call)}
        self.assertFalse({'subprocess.run','os.execv','os.unlink','os.rename','os.replace'}&calls)
        secret=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='secret_metadata')
        opens=[n for n in ast.walk(secret)if isinstance(n,ast.Call)and ast.unparse(n.func)=='os.open']
        self.assertTrue(all('O_DIRECTORY'in ast.unparse(n.args[1])for n in opens))
        self.assertIn('PACKET_ALREADY_CLAIMED_RECONCILE_NO_REPLAY',PATH.read_text())

    def test_delivery_is_immutable_and_preserves_stop_context(self):
        launcher=(ROOT/'scripts/launch-ingestion-rollout-packet-20261020.sh').read_text();raw=PATH.read_bytes()
        self.assertIn(hashlib.sha256(raw).hexdigest(),launcher)
        self.assertIn(hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),launcher)
        self.assertLess(launcher.index('ouf-gh-2.102.0.PNoFbF'),launcher.index('command -v gh'))
        self.assertLess(launcher.index('sha256sum -c -'),launcher.index('sudo /usr/bin/python3'))
        self.assertIn(p.ZIP_SHA,launcher);self.assertIn('trap ouf_report_log EXIT',launcher)
        subprocess.run(['bash','-n',str(ROOT/'scripts/launch-ingestion-rollout-packet-20261020.sh')],check=True)

if 'OUF_TEST_ROOT'in os.environ:
    class RootCustody(unittest.TestCase):
        def test_missing_existing_symlink_key_metadata_without_opening_content(self):
            with tempfile.TemporaryDirectory(dir=os.environ['OUF_TEST_ROOT'])as root:
                key=Path(root)/'key';before=m.secret_metadata(key)
                self.assertEqual(before['state'],'MISSING_AT_EXISTING_CUSTODIED_PARENT')
                key.write_bytes(b'x'*64);key.chmod(0o400);os.chown(key,10002,10002)
                self.assertEqual(m.secret_metadata(key)['state'],'EXISTING_CONTENT_UNREAD')
                key.unlink();key.symlink_to('/unread')
                with self.assertRaises(m.Denied):m.secret_metadata(key)

        def test_private_stage_no_clobber_preserves_other_bytes_and_reader_identity(self):
            with tempfile.TemporaryDirectory(dir=os.environ['OUF_TEST_ROOT'])as root:
                path=Path(root)/'config';m.write_bytes(path,io.BytesIO(b'private fixture\n'),100)
                with self.assertRaises(FileExistsError):m.write_bytes(path,io.BytesIO(b'overwrite'),100)
                os.chown(path,636,636);path.chmod(0o400)
                m.gateway._EXISTING_CONFIG_CUSTODY[str(path)]={'parents':{},'file':(636,636,0o400)}
                raw,binding=m.gateway.private_config(path);self.assertEqual(raw,b'private fixture\n')
                path.write_bytes(b'changed fixture\n')
                with self.assertRaises(m.gateway.Denied):m.gateway.private_config(path,binding)

if __name__=='__main__':unittest.main()
