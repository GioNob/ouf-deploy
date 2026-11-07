"""Offline observations, never admission, repair, a common cut or a writer fence."""
import argparse,re
from pathlib import Path
from .inventory_manifest import canonical,decode,require,sha
from .g0_database import parse_export,private_read,put_new,MAX_BYTES

WRITERS=('onboarding-human-upload','onboarding-delegated-upload','onboarding-profile-worker','ingestion-execution-replay','ingestion-outbox-ack-watermark','udp-store','udp-shadow','udp-purge-compaction','udp-maintenance','administrative-tools','external-consumers')
def census(doc,installation):
 require(type(doc) is dict and doc.get('schema')=='ouf.storage-g0-writer-census.v1' and doc.get('installationRef')==installation and type(doc.get('paths')) is list,'G0_WRITER_CENSUS_BINDING')
 records={}
 for r in doc['paths']:
  require(type(r) is dict and r.get('path') in WRITERS and r['path'] not in records and r.get('presence') in ('PRESENT','ABSENT','UNKNOWN') and r.get('provenance') in ('TECHNICAL_OBSERVATION','OPERATOR_DECLARATION','UNKNOWN'),'G0_WRITER_CENSUS_TYPED_PATH')
  require(r.get('presence')=='UNKNOWN' or type(r.get('evidenceSha256')) is str and re.fullmatch('[0-9a-f]{64}',r['evidenceSha256']) and type(r.get('capturedAt')) is str and bool(r['capturedAt']) and type(r.get('ownerRef')) is str and bool(r['ownerRef']) and r['provenance']!='UNKNOWN','G0_WRITER_EVIDENCE_REQUIRED')
  records[r['path']]=r
 missing=[p for p in WRITERS if p not in records or records[p]['presence']=='UNKNOWN']
 return {'reportedPaths':len(records),'missingOrUnknownPaths':missing,'operatorDeclaredPaths':sum(r['provenance']=='OPERATOR_DECLARATION' for r in records.values()),'technicalPaths':sum(r['provenance']=='TECHNICAL_OBSERVATION' for r in records.values()),'intakeComplete':not missing,'evidenceAuthenticityVerified':False,'writersQuiescentProven':False,'runtimeAuthorityIssued':False}
def reconcile(collection,exports,buckets,writer_census):
 require(type(collection) is dict and collection.get('schema')=='ouf.storage-g0-body-collection.v1' and collection.get('complete') is True and collection.get('sourceObservationsEqual') is True and collection.get('runtimeAuthorityIssued') is False,'G0_COMPLETE_BODY_OBSERVATION_REQUIRED')
 require(set(exports) in ({'onboarding','udp','ingestion'},{'onboarding-retained','udp','ingestion'}),'G0_THREE_OWNER_EXPORTS_REQUIRED')
 require(set(buckets)=={'onboarding','udp'} and all(type(v) is str and re.fullmatch('[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]',v) for v in buckets.values()),'G0_EXPLICIT_BUCKET_BINDINGS')
 objects={};used=set();findings=[];checks=0
 def issue(code,ref):findings.append({'code':code,'referenceSha256':sha(canonical(ref))})
 require(type(collection.get('objects')) is list and len(collection['objects'])<=256,'G0_BODY_SET_LIMIT')
 for p in collection['objects']:
  require(type(p) is dict and type(p.get('bucket')) is str and type(p.get('key')) is str and p.get('versionId') in (None,'','null') and type(p.get('bytes')) is int and p['bytes']>=0 and type(p.get('sha256')) is str and re.fullmatch('[0-9a-f]{64}',p['sha256']) and bool(p.get('etag')),'G0_TYPED_BODY_PROOF')
  k=(p['bucket'],p['key']);require(k not in objects,'G0_DUPLICATE_BODY_PROOF');objects[k]=p
 rows={}
 for profile,export in exports.items():
  require(export['header']['profile']==profile,'G0_EXPORT_PROFILE_BINDING')
  for table,section in export['sections'].items():rows[table]=section['rows']
 def rs(t):return rows.get(t,[])
 def index(t,key):
  out={}
  for r in rs(t):
   k=r.get(key);require(type(k) is str and k not in out,'G0_DB_DUPLICATE_OR_NULL_ID');out[k]=r
  return out
 def physical(bucket,key,digest=None,size=None):
  nonlocal checks
  checks+=1;k=(bucket,key)
  if type(key) is not str or not key or key.startswith('/') or '\x00' in key:issue('UNSUPPORTED_PHYSICAL_LOCATOR',k);return
  p=objects.get(k)
  if p is None:issue('MISSING_BODY',k);return
  used.add(k)
  if digest is not None and digest!='sha256:'+p['sha256']:issue('CONTENT_HASH_MISMATCH',k)
  if size is not None and (type(size) is not int or size!=p['bytes']):issue('CONTENT_SIZE_MISMATCH',k)
 def managed(ref,digest=None,size=None):
  if type(ref) is str and ref.startswith('object://managed-files/') and len(ref)>len('object://managed-files/'):
   physical(buckets['onboarding'],ref[len('object://'):],digest,size)
  else:issue('UNRESOLVED_MANAGED_REFERENCE',ref)
 def link(value,idx,label,optional=False):
  if value is None and optional:return None
  if value not in idx:issue('DANGLING_'+label,value);return None
  return idx[value]
 assets=index('ouf_onboarding.managed_file_asset','asset_id');profiles=index('ouf_onboarding.file_profile','profile_id');jobs=index('ouf_onboarding.file_profile_job','job_id')
 for a in assets.values():
  managed(a['staging_ref'],a['content_hash'],a['size_bytes'])
  if not a['tenant_id']:issue('ASSET_OWNER_UNRESOLVED',a['asset_id'])
 for r in rs('ouf_onboarding.managed_file_upload_intent'):
  managed(r['staging_ref'],r['content_hash'],r['size_bytes'])
  if r['state']!='ACKED':issue('UPLOAD_INTENT_UNRESOLVED',r['intent_id'])
  else:
   a=link(r['asset_id'],assets,'UPLOAD_ASSET')
   if a and any(a[k]!=r[k] for k in ['staging_ref','content_hash','size_bytes','tenant_id']):issue('UPLOAD_ASSET_BINDING_MISMATCH',r['intent_id'])
 for table in ['ouf_onboarding.managed_file_upload_attempt','ouf_onboarding.managed_file_onboarding_attempt','ouf_onboarding.managed_file_owner_reconciliation','ouf_onboarding.file_profile_job','ouf_onboarding.file_profile','ouf_onboarding_legacy.managed_file_ingestion']:
  for r in rs(table):
   a=link(r['asset_id'],assets,'ASSET')
   if a and any(r[k]!=a[k] for k in ['content_hash','size_bytes'] if k in r):issue('ASSET_REFERENCE_BINDING_MISMATCH',[table,r['asset_id']])
   if r.get('profile_id'):link(r['profile_id'],profiles,'PROFILE')
   if table.endswith('owner_reconciliation'):link(r['job_id'],jobs,'PROFILE_JOB')
   for field in ['sample_ref','output_ref']:
    if r.get(field):issue('ADDITIONAL_REFERENCE_REQUIRES_CLASSIFICATION',[table,field,r[field]])
 lakes=index('ouf_udp.lake_object','lake_object_id');manifests=index('ouf_udp.compaction_manifest','manifest_id');plans=index('ouf_udp.lake_shadow_rebuild_plan','plan_id');handoffs=index('ouf_udp.handoff_intake','handoff_id')
 for r in lakes.values():
  loc=r['locator']
  if r['state']=='DELETED':
   if (buckets['udp'],loc) in objects:issue('DELETED_CATALOG_BODY_PRESENT',r['lake_object_id'])
  elif type(loc) is str and loc.startswith('manifest://'):
   link(loc[len('manifest://'):],manifests,'MANIFEST');issue('COMPACTED_SLICE_VERIFICATION_REQUIRED',r['lake_object_id'])
  elif type(loc) is str and loc.startswith('lake/'):
   physical(buckets['udp'],loc,r['content_hash'],r['logical_size_bytes'])
  else:issue('UNRESOLVED_LAKE_LOCATOR',r['lake_object_id'])
  if r['previous_locator']:issue('PREVIOUS_LOCATOR_REQUIRES_LIFECYCLE_CLASSIFICATION',r['lake_object_id'])
 for r in manifests.values():
  out=link(r['output_lake_object_id'],lakes,'MANIFEST_OUTPUT')
  if out and out['content_hash']!=r['output_content_hash']:issue('MANIFEST_OUTPUT_HASH_MISMATCH',r['manifest_id'])
 for r in rs('ouf_udp.compaction_manifest_entry'):
  link(r['manifest_id'],manifests,'MANIFEST');link(r['input_lake_object_id'],lakes,'MANIFEST_INPUT');issue('MANIFEST_RANGE_VALIDATION_REQUIRED',[r['manifest_id'],r['input_lake_object_id']])
 for r in rs('ouf_udp.lake_shadow_rebuild_entry'):
  link(r['plan_id'],plans,'SHADOW_PLAN');link(r['lake_object_id'],lakes,'SHADOW_OBJECT')
  if r['shadow_locator']:physical(buckets['udp'],r['shadow_locator'],r['source_hash'],r['source_size_bytes'])
  issue('SHADOW_LIFECYCLE_RECONCILIATION_REQUIRED',[r['plan_id'],r['lake_object_id']])
 for r in handoffs.values():
  link(r['raw_lake_object_id'],lakes,'RAW_ENVELOPE',optional=True)
  link(r['source_raw_lake_object_id'],lakes,'SOURCE_RAW',optional=True)
 for r in rs('ouf_udp.materialization_job'):link(r['handoff_id'],handoffs,'HANDOFF')
 for r in rs('ouf_udp.replay_plan'):
  link(r['raw_lake_object_id'],lakes,'REPLAY_RAW');link(r['source_handoff_id'],handoffs,'REPLAY_SOURCE');link(r['replay_handoff_id'],handoffs,'REPLAY_RESULT',optional=True)
 runs=index('ouf_ingestion.ing_run','run_id');attempts=index('ouf_ingestion.processing_attempt','attempt_id');lineages=index('ouf_ingestion.ing_lineage','lineage_id');outbox=index('ouf_ingestion.handoff_outbox','handoff_id');quarantines=index('ouf_ingestion.ing_quarantine','quarantine_id')
 for table in ['ouf_ingestion.ing_partition','ouf_ingestion.processing_attempt','ouf_ingestion.ing_lineage','ouf_ingestion.handoff_outbox','ouf_ingestion.checkpoint_history','ouf_ingestion.runtime_configuration_snapshot','ouf_ingestion.ing_quarantine']:
  for r in rs(table):
   link(r['run_id'],runs,'RUN')
   if 'attempt_id' in r:link(r['attempt_id'],attempts,'ATTEMPT',optional=table.endswith('ing_quarantine'))
 for r in outbox.values():
  l=link(r['lineage_id'],lineages,'LINEAGE')
  if l and l['run_id']!=r['run_id']:issue('LINEAGE_RUN_MISMATCH',r['handoff_id'])
  if r['raw_object_ref']:
   # RAW references are catalog identifiers, never guessed physical object keys.
   ref=r['raw_object_ref'];lake=link(ref[7:] if ref.startswith('lake://') else ref,lakes,'OUTBOX_RAW')
   if not l or l['raw_object_ref']!=ref or not l['raw_hash']:issue('RAW_LINEAGE_BINDING_UNPROVEN',r['handoff_id'])
   elif lake and lake['content_hash']!=l['raw_hash']:issue('OUTBOX_RAW_HASH_MISMATCH',r['handoff_id'])
  if l and l['output_hash']!=r['payload_content_hash']:issue('LINEAGE_OUTPUT_HASH_MISMATCH',r['handoff_id'])
  if r['state']=='ACKED':
   h=link(r['handoff_id'],handoffs,'ACK_RECEIPT')
   if not r['acked_at'] or not r['downstream_receipt_ref'] or h and (h['receipt_ref']!=r['downstream_receipt_ref'] or h['ingestion_run_id']!=r['run_id'] or h['content_hash']!=r['payload_content_hash']):issue('ACK_RECEIPT_BINDING_MISMATCH',r['handoff_id'])
   if h and r['raw_object_ref'] and h['source_raw_lake_object_id']!=(r['raw_object_ref'][7:] if r['raw_object_ref'].startswith('lake://') else r['raw_object_ref']):issue('ACK_SOURCE_RAW_BINDING_MISMATCH',r['handoff_id'])
 for r in rs('ouf_ingestion.ing_watermark'):
  o=link(r['committed_handoff_id'],outbox,'WATERMARK_HANDOFF')
  if not o:continue
  run=runs.get(o['run_id'])
  if o['state']!='ACKED' or o['partition_key']!=r['partition_key'] or not run or run['source_id']!=r['source_id'] or o['candidate_watermark_sha256']!=r['watermark_sha256']:issue('WATERMARK_ACK_BINDING_MISMATCH',r['committed_handoff_id'])
  if any(p['run_id']==o['run_id'] and p['partition_key']==o['partition_key'] and p['sequence_no']<o['sequence_no'] and p['state']!='ACKED' for p in outbox.values()):issue('WATERMARK_OVERTAKES_UNACKED',r['committed_handoff_id'])
 for r in rs('ouf_ingestion.runtime_configuration_snapshot'):
  run=runs.get(r['run_id'])
  if run and any(run[k]!=r[k] for k in ['bundle_id','bundle_version','bundle_checksum']):issue('CONFIGURATION_BUNDLE_MISMATCH',r['snapshot_id'])
  if r['staging_ref']:managed(r['staging_ref'])
  if r['asset_id_ref']:link(r['asset_id_ref'],assets,'CONFIGURATION_ASSET')
  if r['binding_ref']:issue('BINDING_REFERENCE_REQUIRES_CLASSIFICATION',r['snapshot_id'])
 for r in quarantines.values():
  for f in ['payload_ref','evidence_ref']:
   if r[f]:issue('QUARANTINE_REFERENCE_REQUIRES_CLASSIFICATION',[r['quarantine_id'],f])
 for r in rs('ouf_ingestion.replay_request'):link(r['quarantine_id'],quarantines,'REPLAY_QUARANTINE')
 for k in objects.keys()-used:issue('UNCLASSIFIED_BODY',k)
 writer=census(writer_census,collection['installationRef'])
 return {'schema':'ouf.storage-g0-reconciliation.v1','status':'OBSERVATIONS_CONSISTENT_NOT_G0_ACCEPTANCE' if not findings else 'HELD_FINDINGS_REQUIRE_REVIEW','observationFindings':findings,'findingsCount':len(findings),'bodyObjects':len(objects),'bodyReferencesChecked':checks,'classifiedBodies':len(used),'exportRows':sum(len(x) for x in rows.values()),'exportBindings':{k:{'rawSha256':v['rawSha256'],'sqlSha256':v['sqlSha256'],'sourceSchemaCommit':v['header']['sourceSchemaCommit']} for k,v in exports.items()},'bodyCollectionSha256':sha(canonical(collection)),'writerCensus':writer,'pointInTimeCommonCutProven':False,'runtimeInstalledCommitsProven':False,'g0Complete':False,'targetWrites':0,'runtimeAuthorityIssued':False,'acceptanceCreditAdded':0}

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('input',type=Path);p.add_argument('output',type=Path);a=p.parse_args()
 c=decode(private_read(a.input,16384));require(type(c) is dict and set(c)=={'collectionFile','exports','buckets','writerCensusFile'},'G0_RECONCILIATION_EXACT_INPUT')
 exports={profile:parse_export(private_read(Path(path),MAX_BYTES),profile) for profile,path in c['exports'].items()}
 report=reconcile(decode(private_read(Path(c['collectionFile']),MAX_BYTES)),exports,c['buckets'],decode(private_read(Path(c['writerCensusFile']),65536)))
 put_new(a.output.parent,a.output.name,canonical(report));print(report['status']);raise SystemExit(0 if not report['findingsCount'] else 1)
