"""Real effects + abrupt process death; isolated fixture, never target authority.

Preceding phase receipts in this focused fixture are synthetic. We qualify only
the named Docker-create/PG-migration crash boundaries, not a complete installer.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import uuid
from test_semantic_transition_journal import m, j, H, module
engine = module('engine_creation', 'tools/semantic_application_cutover/engine_creation.py')


def call(*args, data=None):
    p = subprocess.run(args, input=data, capture_output=True, timeout=60)
    if p.returncode: raise RuntimeError('ISOLATED_NATIVE_COMMAND_FAILED')
    return p.stdout


def store(root, phase, creation_hash='b'*64):
    root.mkdir(mode=0o700)
    journal = j.Journal(str(root))
    initial = m.Transition.initial(m.digest({'fixtureScope':root.name}), creation_hash, 'c'*64, 'd'*64)
    journal.initialize(initial)
    t = m.Transition(journal, initial['contextHash'])
    with t.invocation():
        for previous in m.PHASES[:m.PHASES.index(phase)]:
            row = t.begin(previous, H, H, t.read()['version'])
            t.reconcile(previous, H, 'APPLIED', m.digest({'syntheticPrecedingPhase': previous}), row['version'])
    return t


def die_after_effect(t, phase, effect, managed=False):
    pid = os.fork()
    if pid == 0:
        try:
            with t.invocation():
                if not managed: t.begin(phase, H, H, t.read()['version'])
                effect()
                os._exit(91)  # No finally or successful journal receipt.
        except BaseException:
            os._exit(92)
    _, status = os.waitpid(pid, 0)
    assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 91
    assert t.read()['state'] == 'IN_FLIGHT'
    with t.invocation():
        try: t.begin(phase, H, 'e'*64, t.read()['version'])
        except ValueError as error: assert 'RECONCILIATION' in str(error)
        else: raise AssertionError('CRASH_REPLAY_ALLOWED')


def main():
    suffix = uuid.uuid4().hex[:12]
    app, db = 'ouf-cutover-create-'+suffix, 'ouf-cutover-pg-'+suffix
    partial_app = None
    with tempfile.TemporaryDirectory(prefix='ouf-cutover-crash-') as directory:
        root = Path(directory)
        try:
            call('docker', 'pull', 'alpine:3.22')
            image = json.loads(call('docker', 'image', 'inspect', 'alpine:3.22'))[0]['Id']
            request = {'Image':image,'User':'10001:10001','Cmd':['sleep','300'],
                       'HostConfig':{'NetworkMode':'none','ReadonlyRootfs':True,
                                     'CapDrop':['ALL'],'SecurityOpt':['no-new-privileges']}}
            t = store(root/'docker-journal', 'CREATE_REPLACEMENT', engine.digest(request))
            app = engine.Engine.name(t)
            socket_path = '/var/run/docker.sock'; s = os.stat(socket_path,follow_symlinks=False)
            adapter = engine.Engine(socket_path,(s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode & 0o777))
            # Only fixture checkpoint, not a target authenticator or grant.
            checkpoint = lambda phase: None
            die_after_effect(t, 'CREATE_REPLACEMENT', lambda: adapter.create_once(t,request,H,checkpoint),managed=True)
            actual = json.loads(call('docker', 'inspect', app))[0]
            assert actual['Image'] == image and actual['State']['Status'] == 'created'
            assert actual['Config']['User'] == '10001:10001' and actual['Config']['Cmd'] == ['sleep', '300']
            assert actual['HostConfig']['NetworkMode'] == 'none' and actual['HostConfig']['ReadonlyRootfs']
            assert actual['Mounts'] == [] and actual['HostConfig']['CapDrop'] == ['ALL']
            ids = call('docker', 'ps', '-a', '--filter', 'name=^/'+app+'$', '--format', '{{.ID}}').splitlines()
            assert len(ids) == 1
            with t.invocation():
                row = adapter.reconcile(t,request,checkpoint)
            assert row['nextPhase'] == m.PHASES.index('STAGE_PAUSED_REPLACEMENT')
            assert row['predecessorIncidentRef'] == 'd'*64 and row['predecessorHistoryHash'] == 'c'*64
            # Config drift and already-started generations cannot be reconciled
            # as the requested stopped creation, even with the exact same name.
            changed = dict(actual);changed['Image'] = 'sha256:'+'f'*64
            try: adapter.matching_created(t,request,changed)
            except engine.CreationDenied: pass
            else: raise AssertionError('FOREIGN_IMAGE_RECONCILED')
            changed = dict(actual);changed['State'] = dict(actual['State'],Status='running',Running=True,Pid=123)
            try: adapter.matching_created(t,request,changed)
            except engine.CreationDenied: pass
            else: raise AssertionError('CHANGED_GENERATION_RECONCILED')
            stage_intent = {'containerId':actual['Id'],'creationRequestHash':engine.digest(request),
                            'createdEvidenceHash':row['effects'][-1]['nativeEvidenceHash']}
            die_after_effect(t,'STAGE_PAUSED_REPLACEMENT',
                lambda: adapter.stage_paused_once(t,request,H,checkpoint),managed=True)
            paused = json.loads(call('docker','inspect',app))[0]
            assert paused['State']['Pid'] > 1 and paused['State']['Paused']
            with t.invocation():
                row = adapter.reconcile_paused(t,request,stage_intent,checkpoint)
            assert row['nextPhase'] == m.PHASES.index('ATTEST_NEW_OCI_PEER')
            assert row['applicationWritesMayHaveOccurred'] and not row['preMigrationRestoreAllowed']

            # A crash after start, before pause, is a partial effect: neither
            # restarting nor calling pause automatically is authorized.
            partial = store(root/'partial-pause-journal','CREATE_REPLACEMENT',engine.digest(request))
            partial_app = engine.Engine.name(partial)
            die_after_effect(partial,'CREATE_REPLACEMENT',
                lambda: adapter.create_once(partial,request,H,checkpoint),managed=True)
            with partial.invocation(): adapter.reconcile(partial,request,checkpoint)
            created = adapter.inspect(partial)
            partial_intent = {'containerId':created['Id'],'creationRequestHash':engine.digest(request),
                              'createdEvidenceHash':partial.read()['effects'][-1]['nativeEvidenceHash']}
            def interrupted_pause():
                original = adapter.request
                def interrupted(method,path,body=None):
                    if path.endswith('/pause'): os._exit(91)
                    return original(method,path,body)
                adapter.request = interrupted
                adapter.stage_paused_once(partial,request,H,checkpoint)
            die_after_effect(partial,'STAGE_PAUSED_REPLACEMENT',interrupted_pause,managed=True)
            running = adapter.inspect(partial)
            assert running['State']['Running'] and not running['State']['Paused']
            with partial.invocation():
                try: adapter.reconcile_paused(partial,request,partial_intent,checkpoint)
                except engine.CreationDenied: pass
                else: raise AssertionError('PARTIAL_STAGE_ACCEPTED')
            assert partial.read()['state'] == 'IN_FLIGHT'
            assert adapter.inspect(partial)['State']['Pid'] == running['State']['Pid']

            # Crash BEFORE the command does not make its consumed intent retryable.
            before = store(root/'before-journal', 'CREATE_REPLACEMENT')
            die_after_effect(before, 'CREATE_REPLACEMENT', lambda: None)
            with before.invocation():
                row = before.reconcile('CREATE_REPLACEMENT', H, 'NO_EFFECT',
                    m.digest({'fixtureEffectNotCalled': True}), before.read()['version'])
                assert row['state'] == 'NO_EFFECT_REQUIRES_NEW_DECISION'

            call('docker', 'run', '-d', '--name', db, '--network', 'none', '-e',
                 'POSTGRES_PASSWORD=isolated-fixture-only', 'postgres:17')
            for _ in range(40):
                # The image's init server accepts local sockets before it exits;
                # only the final server accepts this loopback TCP connection.
                p = subprocess.run(['docker','exec',db,'pg_isready','--host=127.0.0.1','-U','postgres'],capture_output=True,timeout=5)
                if p.returncode == 0: break
                time.sleep(.25)
            else: raise RuntimeError('FIXTURE_POSTGRES_NOT_READY')
            def sql(text):
                return call('docker','exec','-i',db,'psql','-X','-A','-t','-q','-U','postgres',
                            '-v','ON_ERROR_STOP=1',data=text.encode())
            sql('CREATE SCHEMA ouf_sem; CREATE TABLE ouf_sem.fixture(id int PRIMARY KEY); INSERT INTO ouf_sem.fixture VALUES(1),(2);')
            baseline = call('docker','exec',db,'pg_dump','-U','postgres','-Fc')
            pg = store(root/'migration-journal', 'ADMIT_MIGRATION')
            die_after_effect(pg, 'ADMIT_MIGRATION', lambda: sql('BEGIN; ALTER TABLE ouf_sem.fixture ADD COLUMN current_value text; INSERT INTO ouf_sem.fixture VALUES(3,\'post-migration\'); COMMIT;'))
            assert pg.read()['databaseMayHaveChanged'] and not pg.read()['preMigrationRestoreAllowed']
            current = sql('SELECT json_agg(t ORDER BY id) FROM ouf_sem.fixture t;').strip()
            rows = json.loads(current); assert [x['id'] for x in rows] == [1,2,3]
            assert rows[2]['current_value'] == 'post-migration'
            with pg.invocation():
                pg.reconcile('ADMIT_MIGRATION', H, 'APPLIED', hashlib.sha256(current).hexdigest(), pg.read()['version'])
                # Merely holding an older valid dump cannot authorize restore.
                assert baseline.startswith(b'PGDMP') and not pg.read()['preMigrationRestoreAllowed']
            assert sql('SELECT json_agg(t ORDER BY id) FROM ouf_sem.fixture t;').strip() == current
            print('OUF_CUTOVER_CRASH_NATIVE='+json.dumps({'status':'PASS','realDockerCreateCrashReconciledWithoutDuplicate':True,
                'crashBeforeEffectDoesNotReplayConsumedIntent':True,'realPostgresqlCommitCrashPreservesMigrationAndLateWrites':True,
                'preMigrationRestoreAllowed':False,'predecessorIncidentAndHistoryPreserved':True,
                'actualSealedEngineCreationAdapterExercised':True,'foreignImageAndStartedGenerationDenied':True,
                'realPausedNamespaceCrashReconciledWithoutRestart':True,
                'partialStartBeforePauseBlocksReplayAndAcceptance':True,
                'precedingPhaseAuthority':'SYNTHETIC_FIXTURE_ONLY','productionInstallerQualified':False,
                'targetActions':0,'notReleaseAcceptance':True}))
        finally:
            for name in (app, db, partial_app):
                if name: subprocess.run(['docker','rm','-f',name],capture_output=True,timeout=30)


if __name__ == '__main__': main()
