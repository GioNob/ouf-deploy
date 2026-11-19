"""Actual root file custody, archive byte verification and readonly SQL contracts."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import runpy
import sys
import subprocess
import tarfile
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('preparation', ROOT/'scripts/prepare-source-revision-inputs.py')
p = importlib.util.module_from_spec(spec); spec.loader.exec_module(p)
helper = runpy.run_path(str(ROOT/'tools/linked_property_rollout/preparation.py'))
custody = runpy.run_path(str(ROOT/'tools/linked_property_rollout/image_custody.py'))
import types
helper = types.SimpleNamespace(**helper); custody = types.SimpleNamespace(**custody)


class PrivatePreparation(unittest.TestCase):
    def fixture(self, root):
        package = root/'package'; package.mkdir(mode=0o700)
        reviewdir = root/'runner'; reviewdir.mkdir(mode=0o700)
        output = root/'private'; output.mkdir(mode=0o700)
        sources = {m:c*40 for m,c in [('onboarding','a'),('mcp','b'),('gateway','c')]}
        lock = {'modules':[{'module':m,'commit':s} for m,s in sources.items()],
                'targetApplyAuthorized':False,'runtimeAuthorityIssued':False}
        (package/'source-lock.json').write_bytes(p.encoded(lock))
        locksha = hashlib.sha256((package/'source-lock.json').read_bytes()).hexdigest()
        candidates = {}; images = {}
        for module in ('onboarding','mcp'):
            layer = io.BytesIO()
            with tarfile.open(fileobj=layer,mode='w'): pass
            rawlayer = layer.getvalue()
            config = p.encoded({'os':'linux','architecture':'amd64',
                'config':{'Labels':{'org.opencontainers.image.revision':sources[module]}},
                'rootfs':{'type':'layers','diff_ids':['sha256:'+hashlib.sha256(rawlayer).hexdigest()]}})
            image = 'sha256:'+hashlib.sha256(config).hexdigest(); images[module] = image
            path = reviewdir/(module+'.tagless.tar')
            with tarfile.open(path,'w') as archive:
                for name,raw in {'config.json':config,'layer.tar':rawlayer,
                    'manifest.json':p.encoded([{'Config':'config.json','RepoTags':None,'Layers':['layer.tar']}])}.items():
                    row = tarfile.TarInfo(name); row.size = len(raw); archive.addfile(row,io.BytesIO(raw))
            sha = hashlib.sha256(path.read_bytes()).hexdigest()
            with path.open('rb') as stream: audit = custody.archive(stream,sha,image,sources[module])
            candidates[module] = {'imageAudit':audit,'imageArchive':{'path':str(path),'sha256':sha},'nativeImageId':image}
            part = package/'parts'/('source-revision-part-'+module+'-1'); part.mkdir(parents=True)
            (part/'candidate-manifest.json').write_bytes(p.encoded({'sourceCommit':sources[module],
                'imageId':image,'sourceLockSha256':locksha,'scanGate':'PASS_HIGH_CRITICAL_UNKNOWN_INCLUDING_UNFIXED'}))
            if module == 'onboarding':
                with zipfile.ZipFile(part/'application.jar','w') as jar:
                    for version in range(1,35):
                        name = 'source_property_revision' if version == 34 else 'fixture'
                        jar.writestr('BOOT-INF/classes/db/migration/V'+str(version)+'__'+name+'.sql',
                                     '-- qualified migration '+str(version)+'\nSELECT 1;\n')
        gateway = package/'parts/source-revision-part-gateway-1'; gateway.mkdir(parents=True)
        (gateway/'source.tar').write_bytes(b'fixture-source-archive')
        sums = ''.join(hashlib.sha256(f.read_bytes()).hexdigest()+'  '+f.relative_to(package).as_posix()+'\n'
                       for f in sorted(package.rglob('*')) if f.is_file())
        (package/'SHA256SUMS').write_text(sums)
        (package/'SHA256SUMS.sigstore.json').write_bytes(b'{}')
        review = reviewdir/'image-review.json'
        review.write_bytes(p.encoded({'schema':'ouf.source-revision-image-custody-review.v1',
            'candidates':candidates,'containerd':False,'imagesImported':0}))
        profile = {'candidateSourceCommits':sources,'candidateNativeImageIds':images,
            'package':{'directory':str(package),'manifestSha256':hashlib.sha256(sums.encode()).hexdigest(),
                       'sourceLockSha256':locksha,'buildRunId':1},
            'runnerImageReview':{'path':str(review),'sha256':hashlib.sha256(review.read_bytes()).hexdigest()}}
        return profile, output

    def test_deep_copy_qualifies_both_images_and_all_jar_migrations_without_import(self):
        with tempfile.TemporaryDirectory(dir='/root') as temp:
            profile, output = self.fixture(Path(temp))
            candidates, containerd, gateway = p.stage(profile,output,helper,custody)
            self.assertFalse(containerd); self.assertEqual(set(candidates),{'onboarding','mcp'})
            self.assertEqual(len(candidates['onboarding']['migrations']),34)
            self.assertEqual(candidates['onboarding']['migrations'][-1]['script'],'V34__source_property_revision.sql')
            self.assertEqual(Path(gateway['path']).stat().st_mode & 0o777,0o600)
            for module,row in candidates.items():
                self.assertTrue(Path(row['imageArchive']['path']).is_relative_to(output))
                self.assertEqual(Path(row['imageArchive']['path']).stat().st_mode & 0o777,0o600)
            self.assertFalse((output/'authority.json').exists())

    def test_corrupted_image_blocks_before_a_private_plan_can_exist(self):
        with tempfile.TemporaryDirectory(dir='/root') as temp:
            profile, output = self.fixture(Path(temp))
            (Path(profile['runnerImageReview']['path']).parent/'onboarding.tagless.tar').write_bytes(b'changed')
            with self.assertRaises(ValueError): p.stage(profile,output,helper,custody)
            self.assertFalse((output/'prepared-plan.json').exists())

    def test_unlisted_file_and_source_drift_are_not_accepted_as_qualified_package(self):
        for changed in ('extra','source'):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory(dir='/root') as temp:
                profile, output = self.fixture(Path(temp))
                if changed == 'extra': (Path(profile['package']['directory'])/'unlisted').write_bytes(b'extra')
                else: profile['candidateSourceCommits']['onboarding'] = 'f'*40
                with self.assertRaises(ValueError): p.stage(profile,output,helper,custody)

    def test_existing_artifacts_and_symlinks_are_never_overwritten_or_followed(self):
        with tempfile.TemporaryDirectory(dir='/root') as temp:
            profile, output = self.fixture(Path(temp))
            (output/'onboarding.tagless.tar').write_bytes(b'retained')
            with self.assertRaises(FileExistsError): p.stage(profile,output,helper,custody)
            self.assertEqual((output/'onboarding.tagless.tar').read_bytes(),b'retained')
            link = Path(temp)/'link'; link.symlink_to(output/'onboarding.tagless.tar')
            with self.assertRaises(ValueError): p.read(link)

    def test_private_byte_and_metadata_drift_are_rejected(self):
        with tempfile.TemporaryDirectory(dir='/root') as temp:
            path = Path(temp)/'private'; path.write_bytes(b'original'); path.chmod(0o600)
            sha = hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(p.read(path,sha),b'original')
            path.write_bytes(b'changed')
            with self.assertRaises(ValueError): p.read(path,sha)
            path.chmod(0o666)
            with self.assertRaises(ValueError): p.read(path)

    def test_safe_manifest_rejects_duplicates_traversal_and_noncanonical_paths(self):
        for name in ('../escape','/absolute','a/../escape','a//b'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                p.manifest(('a'*64+'  '+name+'\n').encode())
        with self.assertRaises(ValueError): p.manifest((('a'*64+'  same\n')*2).encode())

    def test_database_selection_is_closed_and_statements_are_readonly(self):
        for module in ('onboarding','udp','mcp'):
            value = p.sql(module,{'schema':'ouf_'+module,'user':'ouf_'+module,'database':'ouf_'+module})
            self.assertTrue(value.startswith('BEGIN READ ONLY;'))
            self.assertTrue(value.endswith('ROLLBACK;'))
            self.assertIn("statement_timeout='10s'",value)
        for module in ('unknown',):
            with self.assertRaises(ValueError): p.sql(module,{'schema':'ouf','user':'ouf','database':'ouf'})
        with self.assertRaises(ValueError): p.sql('onboarding',{'schema':"bad';DROP SCHEMA public;--",'user':'ouf','database':'ouf'})

    @unittest.skipUnless(os.environ.get('OUF_PREPARATION_POSTGRES') == '1', 'real PostgreSQL qualification only')
    def test_all_three_read_queries_against_actual_postgres_catalogues(self):
        def query(statement):
            result = subprocess.run(['/usr/bin/psql','-h','127.0.0.1','-U','postgres','-d','postgres',
                '-X','-q','-A','-t','-v','ON_ERROR_STOP=1','-c',statement],
                stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
            self.assertEqual(result.returncode,0,result.stderr.decode())
            return result.stdout
        query('CREATE SCHEMA ouf_onboarding; CREATE SCHEMA ouf_udp; CREATE SCHEMA ouf_mcp; '
              'CREATE ROLE ouf_onboarding; GRANT USAGE,CREATE ON SCHEMA ouf_onboarding TO ouf_onboarding; '
              'CREATE TABLE ouf_onboarding.source(id integer); CREATE TABLE ouf_onboarding.onboarding_version(id integer); '
              'CREATE TABLE ouf_onboarding.managed_onboarding_review(id integer); '
              'CREATE TABLE ouf_onboarding.flyway_schema_history(installed_rank integer,version text,script text,checksum integer,success boolean); '
              'CREATE TABLE ouf_udp.flyway_schema_history(LIKE ouf_onboarding.flyway_schema_history); '
              'CREATE TABLE ouf_mcp.schema_migration(version integer,checksum text); '
              'CREATE FUNCTION ouf_onboarding.reject_audit_change() RETURNS trigger LANGUAGE plpgsql AS '
              "$$BEGIN RAISE EXCEPTION 'append only'; END$$; "
              'GRANT REFERENCES ON ouf_onboarding.source,ouf_onboarding.onboarding_version,ouf_onboarding.managed_onboarding_review TO ouf_onboarding; '
              'GRANT SELECT,INSERT ON ouf_onboarding.flyway_schema_history TO ouf_onboarding;')
        for module in ('onboarding','udp','mcp'):
            row = json.loads(query(p.sql(module,{'schema':'ouf_'+module,'user':
                'ouf_onboarding' if module == 'onboarding' else 'postgres','database':'postgres'})))
            self.assertTrue(row['transactionReadOnly']); self.assertEqual(row['preparedTransactions'],0)
            if module == 'onboarding':
                self.assertFalse(row['revisionTablePresent']); self.assertTrue(all(row['migrationRolePrivileges'].values()))


if __name__ == '__main__': unittest.main()
