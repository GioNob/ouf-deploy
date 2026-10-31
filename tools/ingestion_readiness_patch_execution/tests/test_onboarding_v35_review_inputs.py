"""Offline review preparation; histories/schema/runtime/package fixtures synthetic.

Actual root files, ZIP/tar extraction, hash checks and /proc pins are exercised.
No Docker, SQL, application calls or target/apply qualification is inferred.
"""
import copy,hashlib,importlib.util,io,json,os,socket,stat,subprocess,tarfile,tempfile,unittest,zipfile
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[3]if Path(__file__).parent.name=='tests'else Path(__file__).parent
def module(name,path):
    s=importlib.util.spec_from_file_location(name,path);v=importlib.util.module_from_spec(s);s.loader.exec_module(v);return v
def source(path,local):
    p=ROOT/path;return p if p.exists()else ROOT/local
p=module('v35_review_preparation',source('scripts/prepare-onboarding-v35-review-inputs-20261024.py','prepare-onboarding-v35-review-inputs-20261024.py'))
v=module('v35_zip_delivery',source('scripts/verify-onboarding-v35-artifact-20261024.py','verify-onboarding-v35-artifact-20261024.py'))
old=module('v35_reuse_metadata_definitions',source('tools/ingestion_readiness_patch_execution/tests/test_onboarding_engine_metadata.py','test_onboarding_engine_metadata.py'))
c,d,m,r=old.c,old.d,old.m,old.r
from tools.ingestion_readiness_patch_execution import database_read,runtime_bindings
def private(path,value):
    raw=value if type(value)is bytes else m.encoded(value);path.write_bytes(raw);path.chmod(0o400);return m.sha(raw)
def contract():
    rows=[]
    for i in range(1,36):
        raw=('SELECT '+str(i)+';\n').encode();rows.append({'version':str(i),'script':'V'+str(i)+'__fixture.sql','sha256':m.sha(raw),'flywayChecksum':p.crc(raw)})
    return {'migrations':rows}
def facts():
    expected=contract()['migrations'][:34]
    return {'history':[{'rank':i+1,'version':v['version'],'script':v['script'],'type':'SQL','checksum':v['flywayChecksum'],'success':True}for i,v in enumerate(expected)]}
class Guards(unittest.TestCase):
    def test_all34_checksums_not_only_v34_are_required(self):
        self.assertTrue(p.assess_history(facts(),contract())['all34SqlMigrationChecksumsMatchCandidate'])
        for kind in('checksum','script','missing','duplicate','failure'):
            f=facts()
            if kind=='checksum':f['history'][3]['checksum']+=1
            elif kind=='script':f['history'][3]['script']='V4__wrong.sql'
            elif kind=='missing':f['history'].pop()
            elif kind=='duplicate':f['history'].append(f['history'][0])
            else:f['history'][3]['success']=False
            self.assertFalse(p.assess_history(f,contract())['all34SqlMigrationChecksumsMatchCandidate'])
    def test_non_sql_metadata_is_separate_and_unknown_type_not_admitted(self):
        f=facts();f['history'].append({'type':'SCHEMA','version':None,'success':True})
        self.assertTrue(p.assess_history(f,contract())['nonSqlHistoryTypesRecognized'])
        f['history'][-1]['type']='UNREVIEWED';self.assertFalse(p.assess_history(f,contract())['nonSqlHistoryTypesRecognized'])
    def test_schema_flags_never_grant_admission(self):
        f={'relations':[{'name':name,'owner':'app_role','runtimeOwns':True}for name in('managed_onboarding_review','source_property_revision','flyway_schema_history')],
            'schema':{'runtimeCreate':True},'columns':[{'relation':'managed_onboarding_review','name':n}for n in('challenge_id','readiness_attempts','readiness_generation','readiness_started_at')],
            'constraints':[{'relation':'managed_onboarding_review','name':'managed_onboarding_review_readiness_attempts_check','validated':True,'definition':'CHECK (((readiness_attempts >= 0) AND (readiness_attempts <= 128)))'}]}
        result=p.assess_schema(f,{'runtimeRole':'app_role'});self.assertTrue(all(result.values()));self.assertNotIn('migrationAuthorized',result)
        f['relations'].append({'name':'managed_readiness_budget_session'});self.assertFalse(p.assess_schema(f,{'runtimeRole':'app_role'})['budgetTableAbsent'])
        f['relations'][0]['owner']='unreviewed';self.assertFalse(p.assess_schema(f,{'runtimeRole':'app_role'})['runtimeOwnsV35AffectedRelations'])
    def test_crc_matches_real_packaged_v34_and_v35(self):
        proofpath=source('releases/onboarding-v35-image-source-contract-20261024.json','onboarding-v35-image-source-contract.json')
        proof=json.loads(proofpath.read_bytes());rows={v['version']:v for v in proof['migrations']}
        self.assertEqual(rows['34']['flywayChecksum'],-1996496299);self.assertEqual(rows['35']['flywayChecksum'],1095739786)
        self.assertEqual(len(rows),35)
    def test_replay_precedes_any_metadata_read(self):
        with tempfile.TemporaryDirectory(dir=ROOT)as directory:
            root=Path(directory);(root/p.SCOPE).mkdir(mode=0o700)
            with patch.object(p,'PACKAGE',str(root)),patch.object(m.Facts,'json',side_effect=AssertionError('no reads')):
                with self.assertRaisesRegex(p.Stop,'ALREADY_CLAIMED'):p.prepare(None,None,c,d,m,r)
    def test_exact_zip_tar_and_jar_extraction_without_path_extraction(self):
        with tempfile.TemporaryDirectory(dir=ROOT)as directory:
            root=Path(directory);jar=b'only fixture jar';layer=io.BytesIO()
            with tarfile.open(fileobj=layer,mode='w')as t:
                info=tarfile.TarInfo('app/application.jar');info.size=len(jar);t.addfile(info,io.BytesIO(jar))
            image=io.BytesIO()
            with tarfile.open(fileobj=image,mode='w:gz')as t:
                info=tarfile.TarInfo(v.LAYER);data=layer.getvalue();info.size=len(data);t.addfile(info,io.BytesIO(data))
            image=image.getvalue();manifest=m.encoded({'reviewedSourceCommit':v.SOURCE,'testedCommit':v.TESTED,'archiveSha256':m.sha(image),
                'archiveBytes':len(image),'preservedAtomicInstallationOwner':True,'targetApplyAuthorized':False})
            with zipfile.ZipFile(root/'package.zip','w')as z:
                z.writestr('image.tar.gz',image);z.writestr('manifest.json',manifest);z.writestr('SHA256SUMS',b'fixture')
            pins={'ZIP_HASH':v.checksum(root/'package.zip'),'ZIP_BYTES':(root/'package.zip').stat().st_size,'MANIFEST_HASH':m.sha(manifest),
                'IMAGE_HASH':m.sha(image),'IMAGE_BYTES':len(image),'JAR_HASH':m.sha(jar),'JAR_BYTES':len(jar)}
            with patch.multiple(v,**pins):
                self.assertFalse(v.verify(root)['imageLoaded']);self.assertEqual((root/'application.jar').read_bytes(),jar)
                with self.assertRaises(FileExistsError):v.verify(root)
            with self.assertRaises(ValueError):v.verify(root)

@unittest.skipUnless(os.environ.get('OUF_NATIVE_V35_REVIEW')=='1','root-custodied filesystem/proc runner required')
class Native(unittest.TestCase):
    def test_protected_image_jar_and_all35_resources_verified_then_changed_archive_refused(self):
        with tempfile.TemporaryDirectory(dir=ROOT)as directory:
            root=Path(directory);root.chmod(0o700);row=contract();yaml=b'spring: fixture\n'
            jar=io.BytesIO()
            with zipfile.ZipFile(jar,'w')as z:
                z.writestr('BOOT-INF/classes/application.yml',yaml);z.writestr('BOOT-INF/lib/flyway-core-fixture.jar',b'fixture')
                for resource in row['migrations']:z.writestr('BOOT-INF/classes/db/migration/'+resource['script'],('SELECT '+resource['version']+';\n').encode())
            jar=jar.getvalue();image=b'pinned fixture image'
            manifest={'reviewedSourceCommit':p.SOURCE,'testedCommit':p.TESTED,'archiveSha256':m.sha(image),'archiveBytes':len(image),
                'imageId':'sha256:fixture','imageRevisionLabel':p.TESTED,'preservedDeploymentSourceCommit':'b0f5e3dacbe59ebf87e22dd6af2575e41249f51d',
                'preservedAtomicInstallationOwner':True,'sourceSchemaMigration':'V35__managed_readiness_budget_sessions.sql','targetApplyAuthorized':False,'humanBudgetGranted':False}
            mh=private(root/'manifest.json',manifest);private(root/'image.tar.gz',image);private(root/'application.jar',jar)
            row.update(schema='ouf.onboarding-v35-image-source-migration-contract.v1',sourceCommit=p.SOURCE,testedCommit=p.TESTED,
                sourceAndPackagedResourcesMatched=True,targetApplyAuthorized=False,manifestSha256=mh,imageId='sha256:fixture',
                archiveSha256=m.sha(image),archiveBytes=len(image),jarSha256=m.sha(jar),jarBytes=len(jar),applicationYamlSha256=m.sha(yaml))
            ch=private(root/'source-contract.json',row)
            with patch.multiple(p,PACKAGE=str(root),CONTRACT_HASH=ch):
                actual=p.packaged(m,m.Facts());self.assertEqual(len(actual[0]['migrations']),35)
                (root/'image.tar.gz').chmod(0o600);private(root/'image.tar.gz',b'changed fixture image')
                with self.assertRaises(Exception):p.packaged(m,m.Facts())
    def test_private_proposal_reuses_snapshot_with_zero_sql_engine_subprocess_and_no_overlay_content_read(self):
        with tempfile.TemporaryDirectory(dir=ROOT)as directory:
            root=Path(directory);root.chmod(0o700);package=root/'package';package.mkdir(mode=0o700)
            f=facts();f.update(database='onboarding_fixture',databaseOid=100,role='pgadmin',postgresPort=5432,transactionReadOnly=True,
                serverVersionNumber=170000,serverEncoding='UTF8',standby=False,capacity={'preparedTransactions':0,'currentConnections':2,'maximumConnections':100,'reservedForSuperusers':3},
                selectedReview=[{'configuration_hash':d.CONFIGURATION,'readiness_attempts':3,'readiness_generation':4,'readiness_phase':'PAUSED'}],
                activeReadinessLeases=0,roles=[{}],relations=[],columns=[],constraints=[],schema={})
            fp=root/'snapshot.json';fh=private(fp,f)
            owner=root/'owner';owner.mkdir(mode=0o700);overlay=root/'owner.yml';private(overlay,b'secret fixture never read');s=overlay.stat()
            native={'configurationSha256':'a'*64,'nativeFlywayEnabledByDefault':True,'sameDatasourceAsApplication':True,'higherPriorityMigrationOverridesAbsent':True,
                'ownerOverlays':[{'binding':{'path':str(overlay),'metadata':list(m.identity(s))},'target':'/fixture/owner.yml'}]}
            plan={'nativeFlywayConfiguration':native};op=owner/'execution-plan.json';oh=private(op,plan)
            actual={'Image':'sha256:'+'b'*64,'State':{'Pid':os.getpid(),'StartedAt':'fixture','Running':True,'Paused':False,'Restarting':False,'Dead':False,'OOMKilled':False,'Error':''},
                'Id':'a'*64,'Config':{'Env':['OUF_ONB_DB_URL=jdbc:postgresql://private-fixture:5432/onboarding_fixture','OUF_ONB_DB_USER=app_role'], 'WorkingDir':'/app'},
                'HostConfig':{},'NetworkSettings':{},'Mounts':[{'Destination':'/fixture/owner.yml','Source':str(overlay),'Type':'bind','RW':False}],'RestartCount':0}
            app=root/'observation.json';ah=private(app,actual);refs={n:{'path':str(app),'sha256':ah}for n in('onboarding','postgres')}
            inputs={'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'runtimeObservations':refs,
                'currentProcessIdentities':{n:m.process(actual)for n in refs},'currentBindings':{'onboarding':runtime_bindings.observed(actual,runtime_bindings.NATIVE)}}
            ip=root/'inputs.json';ih=private(ip,inputs)
            profile={'identity':{'database':'onboarding_fixture','databaseOid':100,'adminRole':'pgadmin','runtimeRole':'app_role','postgresPort':5432}}
            saved={'schema':'ouf.current-onboarding-database-private-snapshot.v1','inputHash':ih,'historicalNativeLifecycleLineageMatched':True,
                'targetApplyAuthorized':False,'historicalAuthorityReused':False,'automaticReplayAllowed':False,'budgetReset':False,
                'retainedFiles':[{'path':str(op),'sha256':oh}],'snapshotPath':str(fp),'snapshotSha256':fh,'profile':profile}
            sr=root/'completed-snapshot';sr.mkdir(mode=0o700);sp=sr/'snapshot-inputs.json';sh=private(sp,saved)
            private(sr/'complete.json',{'privateSnapshotInputsHash':sh,'status':'CURRENT_ONBOARDING_DATABASE_SNAPSHOT_OBSERVED','complete':True})
            contract_row=contract();contract_row.update(applicationYamlSha256='a'*64)
            image={'path':str(root/'image.bin'),'sha256':private(root/'image.bin',b'image'),'bytes':5,'metadata':list(m.identity((root/'image.bin').stat()))}
            jar={'path':str(root/'jar.bin'),'sha256':private(root/'jar.bin',b'jar'),'bytes':3,'metadata':list(m.identity((root/'jar.bin').stat()))}
            class Owner:OWNER=str(owner)
            before={x:x.read_bytes()for x in root.rglob('*')if x.is_file()}
            original_raw=m.raw
            def bounded_raw(path,*args,**kw):
                if Path(path)==overlay:raise AssertionError('NO_OWNER_OVERLAY_CONTENT_READ')
                return original_raw(path,*args,**kw)
            with patch.multiple(p,PACKAGE=str(package),SNAPSHOT=str(sp),SNAPSHOT_HASH=sh),patch.multiple(d,INPUT=str(ip),INPUT_HASH=ih),\
                 patch.object(p,'packaged',return_value=(contract_row,{},image,jar)),patch.object(m,'raw',bounded_raw),\
                 patch.object(m.Engine,'get',side_effect=AssertionError('NO_ENGINE')),patch.object(database_read,'bounded_read',side_effect=AssertionError('NO_SQL')),\
                 patch.object(d,'prepare',side_effect=AssertionError('NO_OLD_ENTRY')),patch.object(c,'prepare',side_effect=AssertionError('NO_OLD_ENTRY')),\
                 patch.object(subprocess,'Popen',side_effect=AssertionError('NO_SUBPROCESS')),patch.object(socket,'socket',side_effect=AssertionError('NO_CONNECTION')):
                result=p.prepare(Owner,None,c,d,m,r)
                self.assertEqual(result['engineGetAttempts'],0);self.assertEqual(result['sqlSessionAttempts'],0);self.assertFalse(result['targetApplyAuthorized'])
                self.assertFalse(result['allCurrentConfigurationPrecedenceResolved']);self.assertTrue(result['ownerOverlayMetadataMatchesRetained'])
                self.assertNotIn('private-fixture',json.dumps(result));self.assertNotIn('secret fixture',json.dumps(result))
                proposal=json.loads((package/p.SCOPE/'review-inputs.json').read_bytes());self.assertEqual(result['privateReviewInputsHash'],p.digest(proposal))
                with self.assertRaisesRegex(p.Stop,'ALREADY_CLAIMED'):p.prepare(Owner,None,c,d,m,r)
            self.assertEqual(before,{x:x.read_bytes()for x in before})
if __name__=='__main__':unittest.main()
