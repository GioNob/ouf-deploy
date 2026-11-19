import copy,importlib.util,pathlib,tempfile,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
def module(n,p):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
m=module('resume',ROOT/'scripts/resume-ingestion-wide-20261108.py')
base=module('guards',ROOT/'tests/test_ingestion_wide_upgrade.py')
def database():
 d=base.db();d.pop('exactCandidateMigrationHistory');d['migrations']=[{'success':True,'version':str(i)} for i in range(19)]
 d['retainedRows']['ing_schedule']['rows']=2;d['scheduleStableFingerprint']='a'*32
 d['scheduleMetadata']=[dict(ordinal=i,state='DISABLED',triggerOnce=True,publicationEnabled=True,publicationPresent=True,currentPublicationConsumed=True,
  intervalSeconds=0,activationBlocked=False,activationFailures=0,leaseOwnerPresent=False,unexpiredLease=False,leaseUntil=None,
  lockVersion=123,discoveryVerifiedAt='2026-11-08T21:14:32.123456Z',nextRunAt='2026-09-01T00:00:00.000000Z',lastDispatchedAt='2026-09-01T00:00:00.000000Z') for i in (1,2)];return d
def polled(d):
 x=copy.deepcopy(d);x['retainedRows']['ing_schedule']['fingerprint']='b'*32
 for r in x['scheduleMetadata']:r.update(lockVersion=125,discoveryVerifiedAt='2026-11-08T22:00:00.123456Z')
 return x
class ResumeGuards(unittest.TestCase):
 def test_monotonic_poll_only_and_immutable_input(self):
  a=database();b=polled(a);saved=copy.deepcopy(a);self.assertTrue(m.compare_database(a,b,21554,True));self.assertEqual(a,saved)
  self.assertFalse(m.compare_database(a,copy.deepcopy(a),21554,True))
 def test_stopped_database_must_be_exact(self):
  a=database();m.compare_database(a,copy.deepcopy(a),21554)
  with self.assertRaisesRegex(RuntimeError,'STOPPED_DATABASE_STATE_CHANGED'):m.compare_database(a,polled(a),21554)
 def test_each_business_table_and_history_stays_exact(self):
  a=database()
  for t in m.TABLES:
   if t=='ing_schedule':continue
   b=polled(a);b['retainedRows'][t]['fingerprint']='c'*32
   with self.assertRaises(RuntimeError,msg=t):m.compare_database(a,b,21554,True)
  b=polled(a);b['migrations'][0]['success']=False
  with self.assertRaises(RuntimeError):m.compare_database(a,b,21554,True)
 def test_schedule_business_changes_cannot_hide_behind_polling(self):
  a=database()
  for key,v in [('state','ACTIVE'),('currentPublicationConsumed',False),('leaseOwnerPresent',True),('unexpiredLease',True),('activationFailures',1),('publicationEnabled',False),('triggerOnce',False),('nextRunAt','2026-11-09T00:00:00.000000Z'),('lastDispatchedAt','2026-11-09T00:00:00.000000Z')]:
   b=polled(a);b['scheduleMetadata'][0][key]=v
   with self.assertRaises(RuntimeError,msg=key):m.compare_database(a,b,21554,True)
  b=polled(a);b['scheduleStableFingerprint']='c'*32
  with self.assertRaises(RuntimeError):m.compare_database(a,b,21554,True)
 def test_poll_regressions_and_unexplained_fingerprint_rejected(self):
  a=database()
  for mode in ('counter','time','time_only','fingerprint_only','extra','missing'):
   b=polled(a)
   if mode=='counter':b['scheduleMetadata'][0]['lockVersion']=122
   if mode=='time':b['scheduleMetadata'][0]['discoveryVerifiedAt']='2026-11-08T20:00:00.000000Z'
   if mode=='time_only':b['scheduleMetadata'][0]['lockVersion']=123
   if mode=='fingerprint_only':b['scheduleMetadata']=copy.deepcopy(a['scheduleMetadata'])
   if mode=='extra':b['scheduleMetadata'][0]['newField']=1
   if mode=='missing':b['retainedRows'].pop('ing_run')
   with self.assertRaises(RuntimeError,msg=mode):m.compare_database(a,b,21554,True)
 def test_no_partial_replay_or_current_marker(self):
  with tempfile.TemporaryDirectory() as t:
   p=pathlib.Path(t);marker=p/'marker'
   for n in m.REQUIRED:(p/n).write_text('{}')
   m.journal_guard(p,marker)
   for n in m.ABSENT:
    (p/n).write_text('{}')
    with self.assertRaises(RuntimeError):m.journal_guard(p,marker)
    (p/n).unlink()
   marker.write_text('{}')
   with self.assertRaises(RuntimeError):m.journal_guard(p,marker)
 def test_stopped_exact_api_frame_cannot_be_normalized(self):
  o=base.old();a=copy.deepcopy(o);a['State'].update(Pid=0,Running=False,Restarting=False,Paused=False)
  h=type('H',(),{'frame':staticmethod(lambda x:x)})
  m.stopped_guard(o,a,a,a,h,base.r,base.mac)
  for mode in ('legacy','generation','endpoint','env','name'):
   b=copy.deepcopy(a)
   if mode=='legacy':b['Config'].pop('MacAddress')
   if mode=='generation':b['State']['StartedAt']='different'
   if mode=='endpoint':b['NetworkSettings']['Networks']={}
   if mode=='env':b['Config']['Env'].append('OTHER=1')
   if mode=='name':b['Name']='/other'
   with self.assertRaises(RuntimeError,msg=mode):m.stopped_guard(o,a,a,b,h,base.r,base.mac)
if __name__=='__main__':unittest.main(verbosity=2)
