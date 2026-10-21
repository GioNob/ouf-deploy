"""Safe post-start state projection through the existing read-only reader."""
import contextlib
import io
import json
from pathlib import Path
import runpy
import types
import unittest
from unittest.mock import patch


class ProjectionTest(unittest.TestCase):
    def test_runtime_and_health_are_separate_and_private_inspect_fields_never_print(self):
        for running,health in ((True,None),(True,'healthy'),(False,'unhealthy')):
            calls=[]
            data={'Id':'a'*64,'Image':'sha256:'+'b'*64,'RestartCount':2,
                'Config':{'Image':'approved-image','Env':['SECRET=PRIVATE_VALUE']},
                'State':{'Running':running,'Status':'running' if running else 'exited','Pid':23 if running else 0,
                    'ExitCode':0 if running else 1,'OOMKilled':False,'StartedAt':'2026-10-09T19:11:00Z',
                    'Error':'PRIVATE_ERROR','Health':{'Status':health,'Log':[{'Output':'PRIVATE_LOG'}]}},
                'Mounts':[{'Destination':'/approved','Source':'/PRIVATE_SOURCE','Type':'bind','RW':False}]}
            def run(argv,**kwargs):
                calls.append(argv)
                if argv[1]=='version':out='29.8.1'
                elif argv[1]=='ps':out='running\touf-provider\n'
                else:
                    self.assertEqual(argv,['docker','inspect','ouf-provider']);out=json.dumps([data])
                return types.SimpleNamespace(returncode=0,stdout=out)
            output=io.StringIO()
            with patch('subprocess.run',side_effect=run),contextlib.redirect_stdout(output):
                runpy.run_path(str(Path(__file__).resolve().parents[1]/'scripts/read-release-readiness.py'))
            raw=output.getvalue();self.assertNotIn('PRIVATE_',raw)
            value=json.loads(raw.split('=',1)[1]);component=value['components'][0]
            self.assertEqual(component['containerId'],'a'*64)
            self.assertEqual(component['running'],running)
            self.assertEqual(component['healthStatus'],health)
            self.assertEqual(component['restartCount'],2)
            self.assertTrue(component['dockerStateErrorPresent'])
            self.assertEqual(value['containerLifecycleOperations'],0)
            self.assertTrue(all(cmd[1] in ('version','ps','inspect') for cmd in calls))


if __name__=='__main__':unittest.main()
