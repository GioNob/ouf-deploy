import importlib.util,json,unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('stage',Path('scripts/stage-semantic-workload-credential.py'))
stage=importlib.util.module_from_spec(spec);spec.loader.exec_module(stage)
class Custody(unittest.TestCase):
    def test_gateway_nonroot_worker_identity(self):
        raw=b'PID UID GID COMMAND\n100 0 0 nginx\n101 636 636 nginx\n102 636 636 nginx\n103 0 0 sh\n'
        identity=stage.worker_identity(raw);self.assertEqual((identity['uid'],identity['gid']),(636,636))
    def test_ambiguous_worker_identity_denied(self):
        for raw in (b'PID UID GID COMMAND\n',b'PID UID GID COMMAND\n1 100 100 nginx\n2 200 200 nginx\n',b'PID UID GID COMMAND\n1 secret secret nginx\n'):
            with self.assertRaises(ValueError):stage.worker_identity(raw)
    def test_openresty_process_name_has_same_identity_contract(self):
        raw=b'PID UID GID COMMAND\n100 0 0 openresty\n101 636 636 openresty\n'
        identity=stage.worker_identity(raw);self.assertEqual((identity['uid'],identity['gid']),(636,636))
    def test_custody_identity_does_not_copy_admin_or_gateway_secrets(self):
        v={'Id':'a'*64,'Image':'sha256:'+'b'*64,'Config':{'Env':['PASSWORD=DO_NOT_COPY']},'HostConfig':{},'Mounts':[],'NetworkSettings':{'Networks':{}},'State':{'Pid':123,'StartedAt':'time','Running':True}}
        result=stage.identity(v);self.assertNotIn('DO_NOT_COPY',json.dumps(result));self.assertNotIn('Config',result)
if __name__=='__main__':unittest.main()
