"""Run the exact scanned image in disposable CI containers, never on the VPS."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import unittest
import urllib.error
import urllib.request
import test_ingestion_db_preflight_native as native

IMAGE='sha256:5dfdf2239fa9eb3ae2ff8510521322cf91718bc787eee179db8e65c515a30e8b'
SOURCE='0fe0de60c6d980fe97610acf195d4bfd46d3777f'


class ScannedImage(native.NativeDatabase):
    @classmethod
    def setUpClass(cls):
        package=Path(os.environ['OUF_IMAGE_PACKAGE'])
        seen={}
        for line in (package/'SHA256SUMS').read_text().splitlines():
            expected,name=line.split('  ',1);p=Path(name)
            assert not p.is_absolute() and '..' not in p.parts and name not in seen
            path=package/p;assert path.is_file() and not path.is_symlink()
            h=hashlib.sha256()
            with path.open('rb')as f:
                for block in iter(lambda:f.read(1048576),b''):h.update(block)
            assert h.hexdigest()==expected
            seen[name]=expected
        manifest=json.loads((package/'candidate-manifest.json').read_text())
        assert manifest['sourceCommit']==SOURCE and manifest['imageId']==IMAGE
        assert manifest['scanGate']=='PASS_HIGH_CRITICAL_UNKNOWN_INCLUDING_UNFIXED'
        assert manifest['runtimeAuthorityIssued']is False and manifest['targetApplyAuthorized']is False
        native.command(['docker','load','-i',str(package/'image.docker.tar')],180)
        super().setUpClass()
        cls.running=[]
        cls.addClassCleanup(cls.stop_candidates)

    @classmethod
    def stop_candidates(cls):
        for cid in cls.running:
            subprocess.run(['docker','rm','-f',cid],capture_output=True,timeout=20)

    def launch(self,database=None,flyway='false'):
        args=['docker','run','-d','--network',self.network,'-p','127.0.0.1::8080',
            '-e','OUF_ING_DB_URL=jdbc:postgresql://'+self.pg+':5432/'+(database or self.db),
            '-e','OUF_ING_DB_USER='+self.user,'-e','OUF_ING_DB_PASSWORD=ci-only-runtime',
            '-e','SPRING_FLYWAY_ENABLED=false',IMAGE,
            '--spring.flyway.enabled='+flyway,'--ouf.ingestion.startup.schema-mode=VALIDATE_ONLY',
            '--spring.main.banner-mode=off','--logging.level.root=ERROR']
        cid=native.command(args).decode().strip();self.running.append(cid)
        return cid

    def ready(self,cid,expected=200):
        info=self.inspect(cid);port=info['NetworkSettings']['Ports']['8080/tcp'][0]['HostPort']
        url='http://127.0.0.1:'+port+'/actuator/health/readiness'
        status=None
        for attempt in range(40):
            try:
                with urllib.request.urlopen(url,timeout=3)as response:
                    status=response.status;body=json.loads(response.read(16385))
            except urllib.error.HTTPError as error:
                status=error.code;body=json.loads(error.read(16385))
            except (OSError,ValueError):status=None;body={}
            if status==expected:return body
            if not self.inspect(cid)['State']['Running']:break
            time.sleep(.5)
        self.fail('IMAGE_READINESS_EXPECTED_'+str(expected)+'_OBSERVED_'+str(status))

    def test_actual_scanned_image_bootstrap_and_readiness_detect_checksum_drift(self):
        before=self.facts();cid=self.launch()
        try:
            self.assertEqual(self.ready(cid)['status'],'UP')
            after=self.facts()
            self.assertEqual(before['history'],after['history'])
            self.assertEqual(before['catalog'],after['catalog'])
            self.admin("UPDATE ouf_ingestion.flyway_schema_history SET checksum=checksum+1 WHERE version='18'")
            try:self.assertEqual(self.ready(cid,503)['status'],'DOWN')
            finally:self.admin("UPDATE ouf_ingestion.flyway_schema_history SET checksum=checksum-1 WHERE version='18'")
            self.assertEqual(self.ready(cid)['status'],'UP')
        finally:native.command(['docker','stop','--time','10',cid],30)

    def test_actual_image_guard_blocks_before_creating_empty_schema(self):
        name=self.db+'_image_empty';self.admin('CREATE DATABASE '+name+' OWNER '+self.user)
        cid=self.launch(name,'true')
        try:
            for attempt in range(60):
                state=self.inspect(cid)['State']
                if not state['Running']:break
                time.sleep(.5)
            self.assertFalse(self.inspect(cid)['State']['Running'])
            self.assertNotEqual(self.inspect(cid)['State']['ExitCode'],0)
            logs=native.command(['docker','logs',cid])
            self.assertIn(b'ING_STARTUP_MIGRATE_FORBIDDEN',logs)
            rows=native.command(['docker','exec',self.pg,'psql','-X','-q','-A','-t','-U','postgres','-d',name,
                '-c',"SELECT count(*) FROM pg_namespace WHERE nspname='ouf_ingestion'"])
            self.assertEqual(rows.strip(),b'0')
        finally:
            subprocess.run(['docker','rm','-f',cid],capture_output=True,timeout=20)
            self.admin('DROP DATABASE '+name+' WITH (FORCE)')


if __name__=='__main__':unittest.main()
