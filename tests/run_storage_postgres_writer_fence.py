"""Native persistent publication-fence fixture; no runtime/SeaweedFS grant."""
from __future__ import annotations
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import threading

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT), str(ROOT/'tests')]
import run_storage_postgres_fixture_native as native

WRITER='ouf_fence_writer'
LIMITS={k:False for k in ('targetWriterFenceQualified','externalStorageWritesFenced',
 'simultaneousRecoveryCutQualified','pitrQualified','rpoMeasured','rtoMeasured',
 'releaseAdmitted','runtimeAuthorityIssued','productionCodeChanged')}
LIMITS.update(targetOperations=0,gatesClosed=0,acceptanceTestsPassed=0)


def require(ok,code):
 if not ok:raise RuntimeError(code)


def body_identity(body):
 require(isinstance(body,bytes) and len(body)<=4096,'FIXTURE_BODY_BUDGET')
 return hashlib.sha256(body).hexdigest(),len(body)


def call_sql(function,*args):
 signatures={'reserve':('op','epoch','hash','bytes'),'finish':('op','epoch','hash','bytes'),
 'begin_drain':('epoch','version'),'finish_drain':('version',),'reconcile':('op','version','hash','bytes')}
 require(function in signatures and len(args)==len(signatures[function]),'KNOWN_FIXTURE_CALL_REQUIRED')
 values=[]
 for kind,value in zip(signatures[function],args):
  if kind in ('epoch','version','bytes'):
   require(type(value) is int and 0<=value<=2**31 and (kind!='bytes' or value<=4096),'BOUNDED_INTEGER_REQUIRED');values.append(str(value))
  else:
   pattern=r'lab-[a-z0-9-]{1,48}' if kind=='op' else r'[0-9a-f]{64}'
   require(isinstance(value,str) and re.fullmatch(pattern,value) is not None,'FIXTURE_LITERAL_REQUIRED');values.append("'"+value+"'")
 return 'SELECT ouf_fence_lab.'+function+'('+','.join(values)+');'


def persist_body(path,body):
 body_identity(body)
 with path.open('xb') as stream:
  stream.write(body);stream.flush();os.fsync(stream.fileno())
 fd=os.open(path.parent,os.O_RDONLY)
 try:os.fsync(fd)
 finally:os.close(fd)


def reconciled_body_identity(path,expected_hash,expected_bytes):
 require(not path.is_symlink() and path.is_file(),'REGULAR_FIXTURE_BODY_REQUIRED')
 with path.open('rb') as stream:body=stream.read(4097)
 actual=body_identity(body)
 require(actual==(expected_hash,expected_bytes),'BODY_RECONCILIATION_REQUIRED')
 return actual


class Calls:
 def __init__(self,lab):self.lab=lab;self.number=0;self.lock=threading.Lock()
 def raw(self,sql,*,user='fixture_admin',expect=0):
  with self.lock:self.number+=1;number=self.number
  # Every subprocess is a distinct client/session; all waits are bounded.
  result=native.run(self.lab.argv("SET statement_timeout='3s'; SET lock_timeout='2s'; "+sql,user=user),timeout=6)
  stem=self.lab.output/('fence-%03d'%number)
  for suffix,value in (('.sql',sql.encode()),('.stdout',result.stdout),('.stderr',result.stderr)):
   stem.with_suffix(suffix).write_bytes(value)
  require(result.returncode==expect,'FIXTURE_SQL_RETURN_CODE')
  if expect==0:require(not result.stderr,'FIXTURE_SQL_UNEXPECTED_STDERR')
  else:require(b'42501' in result.stderr,'EXPECTED_INSUFFICIENT_PRIVILEGE_REQUIRED')
  return result.stdout.decode().strip()
 def call(self,function,*args,user='fixture_admin'):return self.raw(call_sql(function,*args),user=user)


def exercise(lab,output):
 lab.start(initialize_catalog=False)
 lab.sql((ROOT/'tests/fixtures/storage-recovery/writer-fence.sql').read_text())
 calls=Calls(lab);checks=[]
 def expect(actual,wanted,name):require(actual==wanted,name);checks.append(name)
 expect(calls.raw("SELECT ouf_fence_lab.begin_drain(NULL,0);"),'','null-control-input-does-not-transition')
 body=b'finite durable fixture write\x00\xff';digest,size=body_identity(body)
 sink=output/'synthetic-object';sink.mkdir()
 # Two real psql clients contend for the same idempotency key.
 with ThreadPoolExecutor(max_workers=2) as pool:
  futures=[pool.submit(calls.call,'reserve','lab-same',1,digest,size,user=WRITER) for _ in range(2)]
  expect(sorted(x.result() for x in futures),['EXISTING_PENDING','RESERVED'],'atomic-single-reservation')
 persist_body(sink/'same',body)
 expect(calls.call('finish','lab-same',1,digest,size,user=WRITER),'ACKED','durable-effect-before-ack')
 expect(calls.call('reserve','lab-same',1,digest,size,user=WRITER),'EXISTING_ACKED','stable-ack-replay-no-second-effect')
 expect(calls.call('reserve','lab-same',1,'0'*64,size,user=WRITER),'CONFLICT','same-key-different-intent-denied')
 expect(calls.call('reserve','lab-ambiguous',1,digest,size,user=WRITER),'RESERVED','persist-inflight-intent')
 # Simulate crash/ACK loss after external effect, before catalog publication.
 persist_body(sink/'ambiguous',body)
 with ThreadPoolExecutor(max_workers=2) as pool:
  futures=[pool.submit(calls.call,'begin_drain',1,0) for _ in range(2)]
  expect(sorted(x.result() for x in futures),['DRAINING','STALE'],'atomic-one-controller-transition')
 expect(calls.call('finish','lab-ambiguous',1,digest,size,user=WRITER),'FENCED','late-worker-publication-denied')
 expect(calls.call('reserve','lab-late',1,digest,size,user=WRITER),'FENCED','old-generation-new-claim-denied')
 expect(calls.call('reserve','lab-new-epoch',2,digest,size,user=WRITER),'FENCED','draining-new-generation-claim-denied')
 expect(calls.call('finish_drain',1),'RECONCILE_REQUIRED','pending-ambiguity-prevents-frozen')
 # Writer cannot mutate the ledger or call administrative fence/reconcile functions.
 for sql in ("UPDATE ouf_fence_lab.control SET phase='ACTIVE';",call_sql('begin_drain',1,0),call_sql('reconcile','lab-ambiguous',1,digest,size)):
  calls.raw(sql,user=WRITER,expect=1);checks.append('writer-privilege-denial')
 before=calls.raw("SELECT json_build_object('control',(SELECT row_to_json(c) FROM ouf_fence_lab.control c),'intents',(SELECT json_agg(i ORDER BY operation) FROM ouf_fence_lab.intents i),'events',(SELECT json_agg(e ORDER BY sequence) FROM ouf_fence_lab.events e));")
 result=native.run([str(lab.binary('pg_ctl')),'-D',str(lab.data),'-m','fast','-l',str(lab.output/'postgres.log'),'-w','-t','20','restart'],timeout=25)
 (lab.output/'restart.stdout').write_bytes(result.stdout);(lab.output/'restart.stderr').write_bytes(result.stderr)
 require(result.returncode==0,'POSTGRES_RESTART_FAILED')
 after=calls.raw("SELECT json_build_object('control',(SELECT row_to_json(c) FROM ouf_fence_lab.control c),'intents',(SELECT json_agg(i ORDER BY operation) FROM ouf_fence_lab.intents i),'events',(SELECT json_agg(e ORDER BY sequence) FROM ouf_fence_lab.events e));")
 expect(json.loads(before),json.loads(after),'restart-preserves-epoch-intents-and-history')
 expect(calls.call('finish','lab-ambiguous',1,digest,size,user=WRITER),'FENCED','restarted-stale-worker-denied')
 expect(calls.call('reserve','lab-ambiguous',1,digest,size,user=WRITER),'EXISTING_PENDING','ambiguous-retry-does-not-resend')
 expect(calls.call('reconcile','lab-ambiguous',1,'0'*64,size),'CONFLICT','wrong-reconciliation-digest-denied')
 # Read full fixture bytes before resolving the pending intent. No retry PUT occurs.
 observed_hash,observed_size=reconciled_body_identity(sink/'ambiguous',digest,size)
 expect(calls.call('reconcile','lab-ambiguous',1,observed_hash,observed_size),'RECONCILED','exact-body-reconciliation')
 expect(calls.call('reconcile','lab-ambiguous',1,observed_hash,observed_size),'EXISTING_RECONCILED','reconciliation-idempotent')
 expect(calls.call('finish_drain',0),'STALE','stale-controller-version-denied')
 expect(calls.call('finish_drain',1),'FROZEN','freeze-after-all-intents-terminal')
 expect(calls.call('reserve','lab-frozen',2,digest,size,user=WRITER),'FENCED','frozen-generation-no-new-write')
 final=json.loads(calls.raw("SELECT json_build_object('control',(SELECT row_to_json(c) FROM ouf_fence_lab.control c),'intents',(SELECT json_agg(i ORDER BY operation) FROM ouf_fence_lab.intents i),'events',(SELECT json_agg(e ORDER BY sequence) FROM ouf_fence_lab.events e));"))
 require(final['control']=={'singleton':True,'epoch':2,'version':2,'phase':'FROZEN'},'FINAL_CONTROL_REQUIRED')
 require(final['intents']==[
  {'operation':'lab-ambiguous','epoch':1,'body_hash':digest,'body_bytes':size,'state':'RECONCILED'},
  {'operation':'lab-same','epoch':1,'body_hash':digest,'body_bytes':size,'state':'ACKED'},
 ],'ORIGINAL_ACK_AND_RECONCILED_INTENT_REQUIRED')
 require([(e['sequence'],e['kind'],e['operation'],e['epoch'],e['version']) for e in final['events']]==[
  (1,'RESERVED','lab-same',1,0),(2,'ACKED','lab-same',1,0),
  (3,'RESERVED','lab-ambiguous',1,0),(4,'DRAINING',None,2,1),
  (5,'RECONCILED','lab-ambiguous',2,1),(6,'FROZEN',None,2,2),
 ],'EXACT_PRESERVED_EVENT_HISTORY_REQUIRED')
 require(sorted(p.name for p in sink.iterdir())==['ambiguous','same'] and
         all(reconciled_body_identity(p,digest,size)==(digest,size) for p in sink.iterdir()),
         'TWO_UNCHANGED_EXTERNAL_FIXTURE_EFFECTS_REQUIRED')
 (output/'final-ledger.json').write_text(json.dumps(final,sort_keys=True)+'\n')
 return {**LIMITS,'schema':'ouf.storage-postgres-publication-fence-fixture.v1','status':'NATIVE_SYNTHETIC_PUBLICATION_FENCE_PASS','postgresVersion':native.VERSION,'checksPassed':checks,'checkCount':len(checks),'realConcurrentClients':2,'durableObjectEffects':2,'publicationFenceEnforcedInFixture':True,'oneRestartPreservedState':True,'unresolvedIntentsBlockFreeze':True,'originalAckPreserved':True,'finalLedgerSha256':native.digest(output/'final-ledger.json'),'externalEffect':'two fsynced local synthetic files; no S3 writes','scope':'Disposable fixture role and schema only; not deployed OUF writer controls.'}


def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--pg-bin',required=True,type=Path);parser.add_argument('--output',required=True,type=Path);args=parser.parse_args()
 require(os.geteuid()!=0,'UNPRIVILEGED_LAB_USER_REQUIRED');require(not args.output.exists() and not args.output.is_symlink(),'FRESH_OUTPUT_REQUIRED')
 args.output.mkdir(parents=True,mode=0o700);lab=native.NativeLab(args.pg_bin,args.output/'postgres');receipt={**LIMITS,'status':'NATIVE_SYNTHETIC_PUBLICATION_FENCE_BLOCKED'};failure=None
 try:receipt=exercise(lab,args.output)
 except Exception as error:failure=type(error).__name__+': '+str(error);receipt['failure']=failure
 finally:
  try:lab.stop();receipt['cleanStop']=True
  except Exception as error:failure=type(error).__name__+': '+str(error);receipt.update(status='NATIVE_SYNTHETIC_PUBLICATION_FENCE_BLOCKED',cleanStop=False,cleanupFailure=failure)
 (args.output/'receipt.json').write_text(json.dumps(receipt,indent=2,sort_keys=True)+'\n')
 print(json.dumps(receipt));return 1 if failure else 0

if __name__=='__main__':raise SystemExit(main())
