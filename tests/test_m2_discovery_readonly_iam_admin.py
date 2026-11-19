"""Real proc-root/file/namespace FDs; HTTP child is modeled in protocol tests.

The separate real Keycloak job exercises actual GETs, invalid bearer and expired
cache. No production credential, authentication or target effect is tested.
"""
import copy,hashlib,os,sys,tempfile,time,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import test_m2_discovery_current_cohort
from tools.m2_discovery_installation_profile import readonly_iam_admin as m
from tools.m2_discovery_installation_profile.node_owner import ObservationBudget


class ReadOnlyAdmin(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=ROOT,prefix='readonly-admin-');self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.root.chmod(0o700);self.cache=self.root/'kcadm.config'
        self.value={'serverUrl':'http://localhost:8080','realm':'master','endpoints':{'http://localhost:8080':{'master':{
            'token':'existing.disposable.bearer','expiresAt':int(time.time()*1000)+60000,
            'refreshToken':'MUST_NEVER_BE_FORWARDED','secret':'MUST_NEVER_BE_FORWARDED'}}}}
        self.cache.write_bytes(m.encoded(self.value));self.cache.chmod(0o600);self.pin=m.process_pin(os.getpid())
        p=Path(sys.executable).resolve();self.profile={'schema':m.SCHEMA,
            'python':{'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'maximumBytes':67108864},
            'sessionFile':{'containerPath':str(self.cache),'sha256':hashlib.sha256(self.cache.read_bytes()).hexdigest(),
                'metadataHash':m.digest(m.attrs(self.cache.stat())),'maximumBytes':262144},
            'sessionServer':'http://localhost:8080','adminRealm':'master','port':8080}

    def rebind(self):
        self.profile['sessionFile'].update(sha256=hashlib.sha256(self.cache.read_bytes()).hexdigest(),
            metadataHash=m.digest(m.attrs(self.cache.stat())))

    def test_actual_proc_file_is_minimized_without_forwarding_refresh_or_secret(self):
        before=self.cache.read_bytes();session=m.read_session(self.profile,self.pin,ObservationBudget(10))
        self.assertEqual(set(session),{'token','expiresAt','sessionFileHash'})
        self.assertNotIn(b'MUST_NEVER',m.encoded(session));self.assertEqual(self.cache.read_bytes(),before)

    def test_expired_session_stops_without_subprocess_or_cache_repair(self):
        self.value['endpoints']['http://localhost:8080']['master']['expiresAt']=1
        self.cache.write_bytes(m.encoded(self.value));self.rebind();before=self.cache.read_bytes()
        with patch.object(m.subprocess,'run') as command,self.assertRaisesRegex(ValueError,'BEARER_REQUIRED_NO_REFRESH'):
            m.read_session(self.profile,self.pin,ObservationBudget(10))
        command.assert_not_called();self.assertEqual(self.cache.read_bytes(),before)

    def test_changed_bytes_custody_and_symlink_are_rejected_without_following(self):
        self.cache.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'SESSION_CUSTODY_CHANGED|SESSION_BYTES_CHANGED'):
            m.read_session(self.profile,self.pin,ObservationBudget(10))
        self.cache.unlink();other=self.root/'private-original';other.write_bytes(m.encoded(self.value));other.chmod(0o600)
        self.cache.symlink_to(other);self.rebind()
        with self.assertRaises(OSError):m.read_session(self.profile,self.pin,ObservationBudget(10))
        self.assertTrue(self.cache.is_symlink());self.assertEqual(other.read_bytes(),m.encoded(self.value))

    def test_selected_endpoint_or_process_drift_precedes_http(self):
        self.value['realm']='another';self.cache.write_bytes(m.encoded(self.value));self.rebind()
        with self.assertRaisesRegex(ValueError,'SESSION_SELECTION'):
            m.read_session(self.profile,self.pin,ObservationBudget(10))
        pin=copy.deepcopy(self.pin);pin['startTicks']+=1
        with self.assertRaisesRegex(ValueError,'SESSION_PROCESS_CHANGED'):
            m.read_session(self.profile,pin,ObservationBudget(10))

    def test_child_receives_only_existing_bearer_over_stdin_and_fd_is_closed(self):
        session=m.read_session(self.profile,self.pin,ObservationBudget(10));before=self.cache.read_bytes()
        path='/admin/realms/ouf/clients/11111111-1111-4111-8111-111111111111';seen=[]
        def run(args,**kwargs):
            fd=kwargs['pass_fds'][0];seen.append(fd);self.assertTrue(os.fstat(fd))
            self.assertNotIn(session['token'],str(args)+str(kwargs['env']))
            value=m.decode(kwargs['input']);self.assertEqual(value,{'port':8080,'path':path,'query':{},'token':session['token']})
            self.assertNotIn(b'MUST_NEVER',kwargs['input']);self.assertEqual(args[-1],str(fd))
            return SimpleNamespace(returncode=0,stdout=b'{"nativeHttpLeafModeled":true}')
        with patch.object(m.subprocess,'run',side_effect=run):
            self.assertEqual(m.dispatch(self.profile,self.pin,session,path,{},ObservationBudget(10)),{'nativeHttpLeafModeled':True})
        with self.assertRaises(OSError):os.fstat(seen[0])
        self.assertEqual(self.cache.read_bytes(),before)

    def test_denied_child_has_one_attempt_no_fallback_and_closes_namespace(self):
        session=m.read_session(self.profile,self.pin,ObservationBudget(10));seen=[]
        def deny(args,**kwargs):seen.extend(kwargs['pass_fds']);return SimpleNamespace(returncode=2,stdout=b'')
        with patch.object(m.subprocess,'run',side_effect=deny) as get,self.assertRaisesRegex(ValueError,'GET_UNPROVEN_NO_REFRESH'):
            m.dispatch(self.profile,self.pin,session,'/admin/realms/ouf/clients/11111111-1111-4111-8111-111111111111',{},ObservationBudget(10))
        self.assertEqual(get.call_count,1)
        with self.assertRaises(OSError):os.fstat(seen[0])

    def test_login_refresh_and_unreviewed_url_cannot_enter_child(self):
        session=m.read_session(self.profile,self.pin,ObservationBudget(10))
        for path in ('/realms/master/protocol/openid-connect/token','http://elsewhere.invalid/admin/realms/ouf/clients/1',
            '/admin/realms/ouf/users','/admin/realms/ouf/clients/11111111-1111-4111-8111-111111111111/../../token'):
            with self.subTest(path=path),patch.object(m.subprocess,'run') as command,self.assertRaisesRegex(ValueError,'GET_ONLY_IAM_ADMIN_PATH'):
                m.dispatch(self.profile,self.pin,session,path,{},ObservationBudget(10))
            command.assert_not_called()


if __name__=='__main__':unittest.main()
