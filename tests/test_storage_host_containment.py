import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('host_driver',ROOT/'scripts/storage-host-containment-20261106.py')
d=importlib.util.module_from_spec(spec);spec.loader.exec_module(d)

class ReadRunner:
    def __init__(self,reply): self.reply=reply;self.calls=[]
    def run(self,binary,args,mutation=False):
        self.calls.append((binary,args,mutation))
        assert not mutation
        if args[0]=='call': return 'o "/org/freedesktop/systemd1/unit/ouf_2dtest_2eservice"\n'
        return self.reply

class TypedStopGuard(unittest.TestCase):
    def test_only_two_typed_empty_arrays_are_admitted(self):
        r=ReadRunner('a(sasbttttuii) 0\na(sasbttttuii) 0\n')
        d.empty_stop_hooks(r,'ouf-test.service')
        self.assertEqual(len(r.calls),2)

    def test_missing_nonempty_or_wrong_type_never_means_no_hooks(self):
        for value in ('','\n','a(sasbttttuii) 0\n','as 0\nas 0\n',
                      'a(sasbttttuii) 1 PRIVATE_COMMAND\na(sasbttttuii) 0\n'):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError,'TYPED_EMPTY_STOP_HOOKS_REQUIRED_ouf-test.service') as error:
                    d.empty_stop_hooks(ReadRunner(value),'ouf-test.service')
                self.assertNotIn('PRIVATE_COMMAND',str(error.exception))

    def test_command_boundary_rejects_start_restart_and_bus_mutation_before_spawn(self):
        with tempfile.TemporaryDirectory() as root:
            run=d.Runner({},Path(root))
            for binary,args,mut in [('systemctl',['start','ouf-test.service'],True),
                ('systemctl',['restart','ouf-test.service'],True),
                ('busctl',['call','org.freedesktop.systemd1','/org/freedesktop/systemd1',
                  'org.freedesktop.systemd1.Manager','StartUnit','s','ouf-test.service'],False),
                ('busctl',['set-property'],True)]:
                with self.subTest(args=args),self.assertRaises(ValueError):
                    run.run(binary,args,mutation=mut)
            self.assertEqual(run.calls,0)
            self.assertEqual(list(Path(root).iterdir()),[])

if __name__=='__main__':unittest.main()
