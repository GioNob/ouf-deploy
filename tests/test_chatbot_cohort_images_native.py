"""Disposable real Engine/imports. Tiny fixture images never execute code."""
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tarfile
import unittest

import test_chatbot_cohort_containers as fixture
from tools.chatbot_file_cohort.images import prepare_imports, CohortImages, image_import_scope, IMAGE_MODULES
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_lease_recovery.recovery_journal import Journal
from engine_creation import Engine
from image_custody import runtime_image_id,FIELDS


@unittest.skipUnless(os.environ.get('OUF_NATIVE_POSTGRES') == '1', 'explicit disposable Docker CI only')
class NativeImages(unittest.TestCase):
    def test_five_tagless_imports_are_native_and_second_apply_never_reloads(self):
        self.assertEqual(os.geteuid(),0)
        f = fixture.crypto.SignedCutover(); f.setUp(); self.addCleanup(f.doCleanups)
        binary = Path(shutil.which('docker')).resolve()
        def docker(*args,data=None):
            return subprocess.run([str(binary),*args],input=data,check=True,stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,timeout=45).stdout
        path = '/var/run/docker.sock'; info = os.stat(path,follow_symlinks=False)
        engine = Engine(path,(info.st_dev,info.st_ino,info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode)))
        packages,output = f.root/'packages',f.root/'tagless'
        packages.mkdir(mode=0o700); output.mkdir(mode=0o700)
        records,journals = [],{}
        for module in IMAGE_MODULES:
            commit = hashlib.sha256((str(f.root)+module).encode()).hexdigest()[:40]
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream,mode='w') as archive:
                raw = ('disposable '+module).encode(); member = tarfile.TarInfo('fixture.txt')
                member.size = len(raw); member.mode = 0o444; archive.addfile(member,io.BytesIO(raw))
            tag = 'ouf-native-fixture:'+commit
            identity = docker('import','--change','LABEL org.opencontainers.image.revision='+commit,
                '--change','USER 65534:65534','--change','WORKDIR /',
                '--change','ENV PATH=/usr/bin:/bin','--change','ENTRYPOINT ["/fixture-never-run"]',
                '--change','CMD ["fixture"]','--change','STOPSIGNAL SIGTERM',
                '-',tag,data=stream.getvalue()).decode().strip()
            self.addCleanup(lambda image=identity: subprocess.run([str(binary),'image','rm','-f',image],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=20))
            directory = packages/module; directory.mkdir(mode=0o700)
            image = directory/'image.docker.tar'; docker('save','-o',str(image),identity)
            with tarfile.open(image) as saved:
                entry=json.load(saved.extractfile('manifest.json'))[0]
                config=saved.extractfile(entry['Config']).read()
            configuration_id='sha256:'+hashlib.sha256(config).hexdigest()
            records.append({'module':module,'artifactKind':'DOCKER_SAVE','imageId':configuration_id,'sourceCommit':commit,
                'scanGate':'PASS_HIGH_CRITICAL_UNKNOWN_INCLUDING_UNFIXED','files':{'image.docker.tar':hashlib.sha256(image.read_bytes()).hexdigest()}})
            # The fixture label above is test data; no scan/production acceptance is asserted.
            docker('image','rm','-f',identity)
            journal = f.root/('image-journal-'+module); journal.mkdir(mode=0o700); journals[module] = Journal(journal)
        records.append({'module':'gateway','artifactKind':'SOURCE_AND_ROUTE_PACKAGE','files':{}})
        manifest = {'schema':'ouf.chatbot-file-cohort-package.v1','modules':records}
        plan = prepare_imports(packages,manifest,output,engine=engine)
        for row in plan['images']:self.assertEqual(row['audit']['repositoryTags'],[])
        raw = json.loads(f.authority); raw['cohortImageImport'] = image_import_scope(plan)
        f.authority = fixture.crypto.encoded(raw); f.approval['executionAuthorityHash'] = fixture.crypto.sha(f.authority)
        f.write(f.mandate,fixture.crypto.encoded(f.approval)); f.approved = fixture.crypto.sha(f.mandate.read_bytes())
        for role in f.grant['roles']:f.sign(role)
        action = AggregateAction(f.gate(),f.authority,f.expected['sourceClosureHash'])
        owner = CohortImages(action,engine,plan,journals,{'path':str(binary),'sha256':hashlib.sha256(binary.read_bytes()).hexdigest()})
        owner.initialize()
        try:first = owner.apply()
        except Exception:
            for row in plan['images']:
                current=owner.inspect(runtime_image_id(row['audit']))
                if current is not None:
                    different=[key for key in FIELDS if current['Config'].get(key)!=row['audit']['imageConfig'].get(key)]
                    if different:print('NATIVE_FIXTURE_CONFIG_MISMATCH_FIELDS='+json.dumps({'module':row['module'],'fields':different}),flush=True)
            raise
        self.assertEqual(len(first['images']),5)
        history = {k:j.read() for k,j in journals.items()}
        self.assertTrue(all(r['effectAttemptCount'] == 1 and r['state'] == 'VERIFIED' for r in history.values()))
        self.assertEqual(owner.apply(),first)
        self.assertEqual({k:j.read() for k,j in journals.items()},history)
        for row in plan['images']:
            actual = owner.inspect(runtime_image_id(row['audit']))
            self.assertEqual(actual.get('RepoTags') or [],[])
        f.approval['state'] = 'REVOKED'; f.write(f.mandate,fixture.crypto.encoded(f.approval))
        with self.assertRaises(Exception):owner.apply()


if __name__ == '__main__':unittest.main()
