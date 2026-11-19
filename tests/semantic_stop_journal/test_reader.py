import importlib.util,json,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('stop_journal',ROOT/'scripts/read-semantic-stop-journal-20261022.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
def row(message,**values):
    return json.dumps({'MESSAGE':message,'_SYSTEMD_UNIT':'docker.service','__REALTIME_TIMESTAMP':'1792310990000000',
                       '_BOOT_ID':'a'*32,**values}).encode()+b'\n'
class Tests(unittest.TestCase):
    def test_shutdown_is_corroborated_but_actor_not_invented(self):
        result=m.classify(row("Processing signal 'terminated'")+row('Daemon shutdown complete'))
        self.assertEqual(result['finding'],'DOCKER_SHUTDOWN_CORROBORATED_IN_REGISTRY_STOP_WINDOW')
        self.assertFalse(result['rootCauseEstablished'])
    def test_secret_address_and_raw_messages_are_never_returned(self):
        result=m.classify(row("Processing signal 'terminated' SECRET 192.0.2.4 password=PRIVATE"))
        text=json.dumps(result)
        for value in ('SECRET','192.0.2.4','password','PRIVATE','Processing signal'):self.assertNotIn(value,text)
    def test_empty_journal_does_not_establish_healthy_or_cause(self):
        result=m.classify(b'');self.assertEqual(result['journalRowsRead'],0);self.assertFalse(result['rootCauseEstablished'])
        self.assertTrue(result['absenceOfMatchIsNotProofOfHealth'])
    def test_full_selection_stops_instead_of_claiming_complete_coverage(self):
        with self.assertRaisesRegex(m.Stop,'JOURNAL_SELECTION_LIMIT'):m.classify(row('other')*2000)
    def test_timestamp_outside_window_denied(self):
        with self.assertRaisesRegex(m.Stop,'OUTSIDE_SELECTED_WINDOW'):
            m.classify(row('Daemon shutdown complete',__REALTIME_TIMESTAMP='1792000000000000'))
    def test_registry_identity_is_only_an_explicit_mention(self):
        result=m.classify(row('event '+m.REGISTRY));self.assertTrue(result['exactRegistryIdMentionObserved'])
        self.assertNotIn(m.REGISTRY,json.dumps(result));self.assertFalse(result['rootCauseEstablished'])
if __name__=='__main__':unittest.main()
