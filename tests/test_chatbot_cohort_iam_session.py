"""Disposable administrative-session fixture; no target credentials or calls."""
from contextlib import contextmanager
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tools/semantic_policy_token_owner'),
             str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from tools.chatbot_file_cohort import iam_session as module


class EngineFixture:
    path='/fixture-engine.sock'
    def __init__(self):
        self.row={'Id':'a'*64,'Name':'/ouf-keycloak','State':{
            'Running':True,'Pid':1234,'StartedAt':'2026-10-14T00:00:00Z'}}
        self.calls=[]
    def request(self,method,path):
        assert method=='GET'
        self.calls.append(path)
        return 200,copy.deepcopy(self.row)


@contextmanager
def fixture_terminal():
    # An inert FD models the operator terminal only for invocation assertions.
    fd=os.open('/dev/null',os.O_RDWR)
    try: yield fd
    finally: os.close(fd)


class AdminSessionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=ROOT);self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.root.chmod(0o700)
        self.stage=self.root/'stage';self.stage.mkdir(mode=0o700)
        self.client={'id':'11111111-1111-4111-8111-111111111111','clientId':'PRIVATE-FIXTURE-CLIENT',
            'enabled':True,'serviceAccountsEnabled':True,'publicClient':False,
            'clientAuthenticatorType':'client-secret','protocol':'openid-connect'}
        raw=module.evidence.encoded({'schema':'ouf.policy-token-existing-iam-metadata.v1','client':self.client})
        path=self.root/module.SNAPSHOT;path.write_bytes(raw);path.chmod(0o600)
        self.binary=self.root/'fixture-docker';self.binary.write_text('#!/bin/sh\nexit 0\n');self.binary.chmod(0o700)
        self.binding=module.governance.executable(str(self.binary))
        for p in (patch.object(module.evidence,'PARENT',self.root),patch.object(module,'SNAPSHOT_HASH',module.evidence.sha(raw)),
                  patch.object(module,'_terminal',fixture_terminal)):
            p.start();self.addCleanup(p.stop)
        self.engine=EngineFixture();self.events=[]
    def success(self):return 0,module.evidence.encoded(self.client),b''
    def run_session(self):return module.ensure_admin_session(self.engine,self.binding,self.stage,self.events.append)

    def test_available_session_does_not_login_or_create_claim(self):
        with patch.object(module,'_read',return_value=self.success()) as read,patch.object(module,'_interactive_login') as login:
            result=self.run_session()
        self.assertFalse(login.called);self.assertEqual(read.call_count,1)
        self.assertFalse(result['administrativeLoginAttempted']);self.assertEqual(list(self.stage.iterdir()),[])
        self.assertNotIn('PRIVATE-FIXTURE',json.dumps(result));self.assertNotIn('client-secret',read.call_args.args[0])
        self.assertIn('unix:///fixture-engine.sock',read.call_args.args[0]);self.assertIn('a'*64,read.call_args.args[0])

    def test_authentication_failure_prompts_once_then_exact_get_reconciles(self):
        with patch.object(module,'_read',side_effect=[(1,b'',b'PRIVATE-SECRET Session has expired'),self.success()]),\
             patch.object(module,'_interactive_login',return_value=0) as login:
            result=self.run_session()
        argv,env=login.call_args.args
        self.assertEqual(argv[-8:],['config','credentials','--server','http://localhost:8080','--realm','master','--user','oufadmin'])
        self.assertIn('-it',argv);self.assertNotIn('--password',argv)
        self.assertEqual(env['DOCKER_CONFIG'],str(self.stage));self.assertTrue((self.stage/module.CLAIM).is_file())
        self.assertTrue(result['administrativeLoginAttempted']);self.assertNotIn('PRIVATE-SECRET','\n'.join(self.events))
        with patch.object(module,'_read',return_value=self.success()),patch.object(module,'_interactive_login') as login:
            self.assertFalse(self.run_session()['administrativeLoginAttempted'])
            self.assertFalse(login.called)

    def test_unknown_login_completion_reads_once_and_never_replays_consumed_attempt(self):
        failed=(1,b'',b'Session has expired')
        with patch.object(module,'_read',side_effect=[failed,failed]),patch.object(module,'_interactive_login',return_value=None) as login:
            with self.assertRaisesRegex(module.evidence.CandidateDenied,'NOT_RECONCILED'):self.run_session()
            self.assertEqual(login.call_count,1)
        with patch.object(module,'_read',return_value=failed),patch.object(module,'_interactive_login') as login:
            with self.assertRaisesRegex(module.evidence.CandidateDenied,'ALREADY_CONSUMED'):self.run_session()
            self.assertFalse(login.called)

    def test_unknown_login_completion_can_be_reconciled_without_login_retry(self):
        with patch.object(module,'_read',side_effect=[(1,b'',b'not logged in'),self.success()]),\
             patch.object(module,'_interactive_login',return_value=None) as login:
            self.assertTrue(self.run_session()['administrativeLoginAttempted'])
            self.assertEqual(login.call_count,1)

    def test_permission_transport_and_unknown_errors_never_prompt_for_password(self):
        for message in (b'Forbidden HTTP403',b'connection refused',b'PRIVATE-SECRET arbitrary failure'):
            with self.subTest(message=message),patch.object(module,'_read',return_value=(1,b'',message)),\
                 patch.object(module,'_interactive_login') as login:
                with self.assertRaisesRegex(module.evidence.CandidateDenied,'NOT_PROVEN_AUTHENTICATION'):self.run_session()
                self.assertFalse(login.called);self.assertFalse((self.stage/module.CLAIM).exists())

    def test_container_restart_and_client_core_drift_block(self):
        def restarted(*_):
            self.engine.row['State']['Pid']+=1
            return self.success()
        with patch.object(module,'_read',side_effect=restarted):
            with self.assertRaisesRegex(module.evidence.CandidateDenied,'GENERATION_CHANGED'):self.run_session()
        changed={**self.client,'clientId':'ANOTHER'}
        with patch.object(module,'_read',return_value=(0,json.dumps(changed).encode(),b'')):
            with self.assertRaisesRegex(module.evidence.CandidateDenied,'CORE_DRIFT'):self.run_session()

    def test_actual_subprocess_diagnostic_is_bounded_and_no_stderr_printed(self):
        result=module._read([sys.executable,'-I','-B','-S','-c',
            "import sys;sys.stderr.write('private fixture session expired');sys.exit(1)"],{'PATH':'/usr/bin:/bin'})
        self.assertEqual(result[0],1);self.assertEqual(result[1],b'')
        self.assertTrue(module.AUTH_FAILURE.search(result[2]))
        with self.assertRaisesRegex(module.evidence.CandidateDenied,'UNBOUNDED'):
            module._read([sys.executable,'-I','-B','-S','-c',"import sys;sys.stderr.write('x'*70000)"],{'PATH':'/usr/bin:/bin'})

    def test_password_terminal_is_forwarded_without_python_capture(self):
        with patch.object(module.subprocess,'run',return_value=subprocess.CompletedProcess([],0)) as run:
            self.assertEqual(module._interactive_login(['fixture','-it'],{}),0)
        kwargs=run.call_args.kwargs
        self.assertEqual(kwargs['stdin'],kwargs['stdout']);self.assertEqual(kwargs['stdout'],kwargs['stderr'])
        self.assertNotIn('input',kwargs);self.assertEqual(kwargs['timeout'],300)


if __name__=='__main__':unittest.main()
