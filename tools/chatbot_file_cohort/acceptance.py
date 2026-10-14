"""Bounded read-only owner evidence for two HUMAN-approved managed-file sources.

The authority selects an existing asset/profile and an eight-object baseline.
No source, run, approval, resolution or token is created here. ACK is not commit;
only actual UDP observations plus new-source provenance prove materialization.
A fresh authenticated chatbot search remains a separate acceptance observation.
"""
import copy
import json
import re
import uuid
from database_gate import Psql, literal
from engine_creation import Engine
from tools.chatbot_file_cohort.plan import digest, require
from tools.chatbot_file_cohort.databases import CohortDatabases
from tools.chatbot_file_cohort.containers import CohortContainers

PROFILE = 'ouf.chatbot-file-owner-acceptance.v1'
BEGIN_READ = "BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY; SET LOCAL statement_timeout='8s'; SET LOCAL lock_timeout='1s';"


def compile_acceptance_plan(*, asset_id, profile_id, profile_version, tenant, subject,
                            canonical_type, ontology_semantic_id, baseline, asset_observation):
    for value in (asset_id, profile_id, subject):
        require(str(uuid.UUID(value)) == value, 'EXACT_ACCEPTANCE_IDENTIFIER_REQUIRED')
    require(type(profile_version) is int and profile_version > 0 and tenant
            and canonical_type.startswith('https://') and ontology_semantic_id.startswith('https://'),
            'EXACT_EXISTING_ACCEPTANCE_SELECTORS_REQUIRED')
    require(type(asset_observation) is dict and asset_observation.get('assetId')==asset_id
            and asset_observation.get('profileId')==profile_id and asset_observation.get('profileVersion')==profile_version
            and asset_observation.get('ownerMatched') is True and asset_observation.get('rows')==13
            and asset_observation.get('columns')==20 and asset_observation.get('mediaType')=='text/csv'
            and all(re.fullmatch(r'sha256:[0-9a-f]{64}',str(asset_observation.get(k,''))) for k in ('contentHash','profileContractHash')),
            'CURRENT_OWNED_THIRTEEN_ROW_TWENTY_COLUMN_CSV_REQUIRED')
    require('boundSourceId' in asset_observation and asset_observation['boundSourceId'] is None,
            'ORIGINAL_ASSET_ALREADY_BOUND_TO_SOURCE_REQUIRES_EXISTING_SOURCE_SELECTION')
    require(baseline.get('schema') == 'ouf.chatbot-existing-object-baseline.v1'
            and baseline.get('count') == 8 and baseline.get('nextCursor') is None
            and baseline.get('partial') is False and len(baseline['objects']) == 8,
            'COMPLETE_EIGHT_OBJECT_BASELINE_REQUIRED')
    objects = []
    for row in baseline['objects']:
        key = row.get('urbanObjectId', row.get('id'))
        require(str(uuid.UUID(key)) == key and row['status'] == 'ACTIVE'
                and type(row['revision']) is int and row['revision'] > 0,
                'EXACT_BASELINE_OBJECT_REQUIRED')
        objects.append({'urbanObjectId':key,'status':row['status'],'revision':row['revision'],
                        'propertyIris':sorted(row['propertyIris'])})
    require(len({r['urbanObjectId'] for r in objects}) == 8, 'UNIQUE_BASELINE_OBJECTS_REQUIRED')
    return {'schema':'ouf.chatbot-file-owner-acceptance-plan.v1','profile':PROFILE,
            'assetId':asset_id,'profileId':profile_id,'profileVersion':profile_version,
            'tenant':tenant,'subject':subject,'canonicalType':canonical_type,
            'ontologySemanticId':ontology_semantic_id,'createdAfter':'SIGNED_ACTION_ISSUED_AT',
            'requiredSourceCount':2,'maximumSourceCount':2,'expectedRowsPerSource':13,
            'originalAssetObservation':copy.deepcopy(asset_observation),
            'secondSourceInput':'NEW_UPLOAD_SAME_BYTES_SAME_OWNER_SAME_PROFILE_AFTER_ACTION',
            'baseline':{'canonicalType':baseline['canonicalType'],'objects':sorted(objects,key=lambda r:r['urbanObjectId'])},
            'baselineEvidenceHash':digest(baseline),'automaticOwnerWritesAllowed':False,
            'freshChatbotSearchRequired':True,'notReleaseAcceptance':True}


def profile_hash(alias):
    return "'sha256:'||encode(sha256(convert_to(jsonb_build_object('format',"+alias+".format,'metadata',"+alias+".metadata,'headers',"+\
        "(SELECT jsonb_agg(c->>'name' ORDER BY ordinal) FROM jsonb_array_elements("+alias+".inferred_schema) WITH ORDINALITY h(c,ordinal)))::text,'UTF8')),'hex')"


def asset_query(asset_id,profile_id,subject):
    return f"""SELECT json_build_object('assetId',a.asset_id,'profileId',f.profile_id,'profileVersion',f.version,
      'contentHash',a.content_hash,'mediaType',a.media_type,'boundSourceId',a.source_id,'ownerMatched',a.uploaded_by={literal(subject)},
      'rows',(f.metadata->>'rows')::integer,'columns',(f.metadata->>'columns')::integer,
      'profileContractHash',{profile_hash('f')}) FROM ouf_onboarding.managed_file_asset a
      JOIN ouf_onboarding.file_profile f ON f.asset_id=a.asset_id
      WHERE a.asset_id={literal(asset_id)}::uuid AND f.profile_id={literal(profile_id)}::uuid"""


def observe_acceptance_input(engine,postgres_runtime_binding,onboarding_binding,*,asset_id,profile_id,subject):
    """Prepare-only metadata read of existing input; no future asset ID is invented."""
    require(type(engine) is Engine,'REAL_ENGINE_REQUIRED_FOR_INPUT_OBSERVATION')
    def guard():
        engine.check_socket()
        code,actual=engine.request('GET','/v1.44/containers/'+postgres_runtime_binding['containerId']+'/json')
        require(code==200 and Engine.runtime_binding(actual)==postgres_runtime_binding,'ACCEPTANCE_POSTGRES_PROCESS_DRIFT')
    guard()
    channel=Psql(postgres_runtime_binding['containerId'],onboarding_binding['user'],onboarding_binding['database'],
                 'ouf-cutover-acceptance-input')
    try:
        identity=channel.query("SELECT json_build_object('name',current_database(),'oid',oid::bigint) FROM pg_database WHERE datname=current_database()",
                               statement=BEGIN_READ,timeout=10)
        require(identity=={'name':onboarding_binding['database'],'oid':onboarding_binding['databaseOid']},'ACCEPTANCE_DATABASE_IDENTITY_DRIFT')
        result=channel.query(asset_query(asset_id,profile_id,subject),timeout=10)
        guard()
        return result
    finally:channel.close()


def rows_sql(rows, columns):
    return 'jsonb_to_recordset('+literal(json.dumps(rows,separators=(',',':')))+'::jsonb) AS x('+columns+')'


def source_query(plan, issued_at):
    """Read only attempts for the signed asset, subject, and post-action window."""
    a,p,s,t,c,o = (literal(plan[k]) for k in ('assetId','profileId','subject','tenant','canonicalType','ontologySemanticId'))
    original=plan['originalAssetObservation']; content=literal(original['contentHash']); ph=literal(original['profileContractHash'])
    return f"""WITH candidates AS (
 SELECT a.source_id,a.onboarding_version_id,a.asset_id,a.created_at AS attempt_at
 FROM ouf_onboarding.managed_file_onboarding_attempt a
 JOIN ouf_onboarding.managed_file_asset af ON af.asset_id=a.asset_id
 WHERE a.subject_id={s} AND a.created_at>=to_timestamp({issued_at})
   AND af.uploaded_by={s} AND af.content_hash={content} AND af.media_type='text/csv'
   AND (af.asset_id={a}::uuid OR af.created_at>=to_timestamp({issued_at}))
 ORDER BY a.created_at,a.idempotency_key LIMIT 3
), observed AS (
 SELECT json_build_object(
 'sourceId',x.source_id,'versionId',x.onboarding_version_id,'state',v.state,
 'assetId',x.asset_id,'profileId',f.profile_id,
 'configurationHash',v.configuration_hash,'publicationId',p.publication_id,
 'bundleId',p.bundle->>'bundleId','bundleVersion',p.bundle->>'bundleVersion',
 'bundleChecksum',p.checksum,
 'semanticPublicationSetRef',p.bundle#>>'{{extractionProfile,runtime,execution,semanticPublicationSetRef}}',
 'propertyIris',COALESCE((SELECT json_agg(q->>'propertyIri' ORDER BY q->>'propertyIri')
   FROM jsonb_array_elements(p.bundle#>'{{extractionProfile,runtime,udp,materialization,properties}}') q),'[]'::json),
 'scopeMatched',COALESCE(s.created_at>=to_timestamp({issued_at}) AND s.source_kind='INTERNAL_MANAGED'
   AND s.acquisition_mode='MANAGED' AND s.metadata->>'managedFileAssetId'=x.asset_id::text
   AND s.metadata->>'fileProfileId'=f.profile_id::text AND f.asset_id=x.asset_id AND af.source_id=x.source_id
   AND ((x.asset_id={a}::uuid AND f.profile_id={p}::uuid AND f.version={plan['profileVersion']})
        OR (x.asset_id<>{a}::uuid AND f.version=1 AND f.created_at>=to_timestamp({issued_at})))
   AND ({profile_hash('f')})={ph} AND af.content_hash={content}
   AND f.metadata->>'rows'={literal(str(plan['expectedRowsPerSource']))} AND af.uploaded_by={s}
   AND v.source_id=x.source_id AND v.configuration#>>'{{extractionProfile,selection,assetId}}'=x.asset_id::text
   AND v.configuration#>>'{{extractionProfile,selection,fileProfileId}}'=f.profile_id::text
   AND v.configuration#>>'{{extractionProfile,runtime,assetId}}'=x.asset_id::text
   AND v.configuration#>>'{{extractionProfile,runtime,fileProfileId}}'=f.profile_id::text,false),
 'approvedPublicationMatched',COALESCE(v.state='ACTIVE' AND p.active AND p.source_id=x.source_id
   AND r.tenant_id={t} AND r.subject_id={s} AND r.source_id=x.source_id
   AND r.configuration_hash=v.configuration_hash AND ch.configuration_hash=v.configuration_hash
   AND ch.status='CONFIRMED' AND d.decision='APPROVE' AND d.actor_subject={s}
   AND d.target_hash=v.configuration_hash AND d.onboarding_version_id=x.onboarding_version_id
   AND length(d.authentication_context_ref)>0 AND d.decided_at>=to_timestamp({issued_at})
   AND p.bundle->>'configurationHash'=v.configuration_hash AND p.bundle->>'checksum'=p.checksum
   AND p.bundle->>'createdFromOnboardingVersion'=x.onboarding_version_id::text
   AND p.bundle#>>'{{source,sourceId}}'=x.source_id
   AND p.bundle#>>'{{extractionProfile,runtime,udp,resolution,governedIdentity,tenantId}}'={t}
   AND p.bundle#>>'{{extractionProfile,runtime,udp,resolution,governedIdentity,canonicalClass}}'={c}
   AND p.bundle#>>'{{extractionProfile,runtime,udp,resolution,governedIdentity,sourceId}}'=x.source_id
   AND EXISTS (SELECT 1 FROM jsonb_array_elements(p.bundle->'semanticReferenceBindings') b
     WHERE b->>'semanticId'={o} AND b->>'semanticVersion'<>''
       AND b->>'revisionId' ~ '^[0-9a-f-]{{36}}$'
       AND b->>'publicationSetId'=p.bundle#>>'{{extractionProfile,runtime,execution,semanticPublicationSetRef}}'),false)
 ) AS row,x.attempt_at,x.source_id
 FROM candidates x LEFT JOIN ouf_onboarding.source s ON s.source_id=x.source_id
 LEFT JOIN ouf_onboarding.onboarding_version v ON v.onboarding_version_id=x.onboarding_version_id
 LEFT JOIN ouf_onboarding.managed_file_asset af ON af.asset_id=x.asset_id
 LEFT JOIN ouf_onboarding.file_profile f ON f.profile_id::text=s.metadata->>'fileProfileId'
 LEFT JOIN ouf_onboarding.managed_onboarding_review r ON r.onboarding_version_id=x.onboarding_version_id
 LEFT JOIN ouf_onboarding.approval_challenge ch ON ch.challenge_id=r.challenge_id
 LEFT JOIN ouf_onboarding.approval_decision d ON d.challenge_id=ch.challenge_id
 LEFT JOIN ouf_onboarding.published_configuration p ON p.onboarding_version_id=x.onboarding_version_id
) SELECT COALESCE(json_agg(row ORDER BY attempt_at,source_id),'[]'::json) FROM observed"""


def ingestion_query(source, plan, issued_at):
    sid,tenant,bid,bv,bh = (literal(v) for v in (source['sourceId'],plan['tenant'],source['bundleId'],source['bundleVersion'],source['bundleChecksum']))
    bref=literal(source['bundleId']+':'+source['bundleVersion']+':'+source['bundleChecksum'])
    sem=literal(source['semanticPublicationSetRef'])
    return f"""WITH runs AS (
 SELECT r.* FROM ouf_ingestion.ing_run r WHERE r.source_id={sid} AND r.tenant_id={tenant}
 AND r.bundle_id={bid} AND r.bundle_version={bv} AND r.bundle_checksum={bh}
 AND r.created_at>=to_timestamp({issued_at}) ORDER BY r.created_at,r.run_id LIMIT 2
), observed AS (
 SELECT json_build_object('runId',r.run_id,'state',r.state,
 'handoffs',COALESCE((SELECT json_agg(h.row ORDER BY h.handoff_id) FROM (
  SELECT o.handoff_id,json_build_object('handoffId',o.handoff_id,'runId',r.run_id,'sourceId',r.source_id,
   'lineageId',o.lineage_id,'sourceObjectHash',encode(sha256(convert_to(l.source_object_id,'UTF8')),'hex'),
   'contentHash',o.payload_json->>'contentHash','receiptRef',o.downstream_receipt_ref,
   'bundleRef',{bref},'semanticPublicationSetRef',{sem},
   'acked',o.state='ACKED' AND o.acked_at IS NOT NULL AND o.downstream_receipt_ref='udp://handoffs/'||o.handoff_id::text,
   'lineageMatched',COALESCE(l.run_id=r.run_id AND a.run_id=r.run_id AND a.state='SUCCEEDED'
     AND a.source_object_id=l.source_object_id AND l.bundle_ref={bref}
     AND o.payload_json->>'handoffId'=o.handoff_id::text
     AND o.payload_json->>'ingestionRunId'=r.run_id::text
     AND o.payload_json->>'lineageId'=l.lineage_id::text
     AND o.payload_json#>>'{{sourceIdentity,sourceId}}'={sid}
     AND o.payload_json#>>'{{sourceIdentity,typeCode}}'='FILE'
     AND o.payload_json#>>'{{sourceIdentity,sourceObjectId}}'=l.source_object_id
     AND o.payload_json#>>'{{contractRefs,bundleRef}}'={bref}
     AND o.payload_json#>>'{{contractRefs,semanticPublicationSetRef}}'={sem},false)) AS row
  FROM ouf_ingestion.handoff_outbox o LEFT JOIN ouf_ingestion.ing_lineage l ON l.lineage_id=o.lineage_id
  LEFT JOIN ouf_ingestion.processing_attempt a ON a.attempt_id=l.attempt_id
  WHERE o.run_id=r.run_id ORDER BY o.handoff_id LIMIT {plan['expectedRowsPerSource']+1}
 ) h),'[]'::json)) AS row,r.created_at FROM runs r
) SELECT COALESCE(json_agg(row ORDER BY created_at),'[]'::json) FROM observed"""


def udp_query(handoffs, source, plan):
    records=rows_sql(handoffs,'"handoffId" text,"runId" text,"sourceId" text,"lineageId" text,"sourceObjectHash" text,"contentHash" text,"receiptRef" text,"bundleRef" text,"semanticPublicationSetRef" text')
    tenant,kind,subject=(literal(plan[k]) for k in ('tenant','canonicalType','subject'))
    properties=literal(json.dumps(source['propertyIris'],separators=(',',':')))
    return f"""WITH observed AS (
 SELECT json_build_object('handoffId',x."handoffId",'urbanObjectId',b.urban_object_id,
 'revisionId',m.revision_id,'materialChange',m.material_change,'jobState',j.state,
 'resolution',CASE WHEN d.outcome='REVIEW_REQUIRED' AND z.state='RESOLVED' THEN 'HUMAN_'||hd.action ELSE d.outcome END,
 'openResolutionIssue',COALESCE(z.state='OPEN',false),
 'intakeMatched',COALESCE(i.ingestion_run_id=x."runId" AND i.source_id=x."sourceId" AND i.type_code='FILE'
  AND encode(sha256(convert_to(i.source_object_id,'UTF8')),'hex')=x."sourceObjectHash"
  AND i.content_hash=x."contentHash" AND i.receipt_ref=x."receiptRef"
  AND i.payload_json->>'lineageId'=x."lineageId"
  AND i.payload_json#>>'{{contractRefs,bundleRef}}'=x."bundleRef"
  AND i.payload_json#>>'{{contractRefs,semanticPublicationSetRef}}'=x."semanticPublicationSetRef",false),
 'commitMatched',COALESCE(j.state='SUCCEEDED' AND b.state='ACTIVE' AND b.first_handoff_id=i.handoff_id
  AND m.urban_object_id=b.urban_object_id AND r.urban_object_id=b.urban_object_id
  AND m.canonical_hash=r.canonical_hash AND u.status='ACTIVE' AND u.tenant_id={tenant} AND u.canonical_type={kind}
  AND cs.revision_id=u.current_revision_id AND cs.urban_object_id=b.urban_object_id
  AND (NOT m.material_change OR r.source_handoff_id=i.handoff_id)
  AND ((d.outcome='MATCH' AND d.target_urban_object_id=b.urban_object_id) OR d.outcome='NEW_OBJECT'
    OR (d.outcome='REVIEW_REQUIRED' AND z.state='RESOLVED' AND hd.action IN ('APPROVE_MATCH','CREATE_NEW')
        AND hd.target_urban_object_id=b.urban_object_id AND hd.actor_subject={subject}
        AND length(hd.authorization_decision_ref)>0)),false),
 'newSourceProvenanceMatched',COALESCE((SELECT jsonb_agg(c.property_iri ORDER BY c.property_iri)={properties}::jsonb
    AND bool_and(COALESCE(c.source_id=i.source_id AND c.urban_object_id=b.urban_object_id
      AND c.provenance_json->>'handoffRef'='handoff://'||i.handoff_id
      AND c.provenance_json->>'ingestionRunId'=x."runId" AND c.provenance_json->>'lineageRef'=x."lineageId"
      AND c.provenance_json#>>'{{sourceIdentity,sourceId}}'=i.source_id
      AND c.provenance_json#>>'{{sourceIdentity,sourceObjectId}}'=i.source_object_id
      AND c.provenance_json#>>'{{contractRefs,bundleRef}}'=x."bundleRef"
      AND c.provenance_json#>>'{{contractRefs,semanticPublicationSetRef}}'=x."semanticPublicationSetRef",false))
    FROM ouf_udp.property_contribution c WHERE c.handoff_id=x."handoffId"),false)) AS row,x."handoffId" AS id
 FROM {records}
 LEFT JOIN ouf_udp.handoff_intake i ON i.handoff_id=x."handoffId"
 LEFT JOIN ouf_udp.materialization_job j ON j.handoff_id=i.handoff_id
 LEFT JOIN ouf_udp.source_binding b ON b.source_id=i.source_id AND b.type_code=i.type_code AND b.source_object_id=i.source_object_id
 LEFT JOIN ouf_udp.materialization_observation m ON m.handoff_id=i.handoff_id
 LEFT JOIN ouf_udp.object_revision r ON r.revision_id=m.revision_id
 LEFT JOIN ouf_udp.urban_object u ON u.urban_object_id=b.urban_object_id
 LEFT JOIN ouf_udp.urban_object_current_state cs ON cs.urban_object_id=u.urban_object_id
 LEFT JOIN ouf_udp.resolution_decision d ON d.handoff_id=i.handoff_id
 LEFT JOIN ouf_udp.resolution_issue z ON z.resolution_decision_id=d.resolution_decision_id
 LEFT JOIN ouf_udp.human_resolution_decision hd ON hd.issue_id=z.issue_id
) SELECT COALESCE(json_agg(row ORDER BY id),'[]'::json) FROM observed"""


def baseline_query(plan):
    records=rows_sql(plan['baseline']['objects'],'"urbanObjectId" uuid,status text,revision bigint,"propertyIris" jsonb')
    return f"""SELECT json_build_object('count',count(*),'preserved',COALESCE(bool_and(COALESCE(
      u.urban_object_id IS NOT NULL AND u.tenant_id={literal(plan['tenant'])}
      AND u.canonical_type={literal(plan['baseline']['canonicalType'])} AND u.status=x.status AND u.revision=x.revision
      AND (SELECT jsonb_agg(k ORDER BY k) FROM jsonb_object_keys(cs.canonical_payload) k)=x."propertyIris",false)),false))
      FROM {records} LEFT JOIN ouf_udp.urban_object u ON u.urban_object_id=x."urbanObjectId"
      LEFT JOIN ouf_udp.urban_object_current_state cs ON cs.urban_object_id=u.urban_object_id"""


def summarize(plan, sources, runs, committed, baseline):
    """Metadata-only receipt; never collapse ACK, commit, reuse, or chatbot search."""
    require(len(sources)<=2 and len({s['sourceId'] for s in sources if s['sourceId']})==len(sources),
            'ACCEPTANCE_SOURCE_SELECTION_AMBIGUOUS')
    complete=[]
    for source, run, udp in zip(sources,runs,committed):
        count=plan['expectedRowsPerSource']
        handoffs=run[0]['handoffs'] if len(run)==1 else []
        good=(source['scopeMatched'] is True and source['approvedPublicationMatched'] is True
              and len(run)==1 and run[0]['state']=='SUCCEEDED' and len(handoffs)==count
              and len({h['sourceObjectHash'] for h in handoffs})==count
              and all(h['acked'] is True and h['lineageMatched'] is True for h in handoffs)
              and len(udp)==count and all(r['urbanObjectId'] is not None for r in udp)
              and all(r['intakeMatched'] is True and r['commitMatched'] is True
                      and r['newSourceProvenanceMatched'] is True for r in udp))
        complete.append(bool(good))
    preserved=baseline=={'count':8,'preserved':True}
    same_records=False
    if len(complete)==2 and all(complete):
        bindings=[]
        for run,udp in zip(runs,committed):
            objects={r['handoffId']:r['urbanObjectId'] for r in udp}
            bindings.append(sorted((h['contentHash'],objects[h['handoffId']]) for h in run[0]['handoffs']))
        same_records=(bindings[0]==bindings[1] and sources[0]['propertyIris']==sources[1]['propertyIris'])
    distinct_assets=(len(sources)==2 and sources[0]['assetId']==plan['assetId'] and sources[0]['profileId']==plan['profileId']
                     and sources[1]['assetId']!=sources[0]['assetId'] and sources[1]['profileId']!=sources[0]['profileId'])
    reused=(len(complete)==2 and all(complete) and distinct_assets
            and {r['urbanObjectId'] for r in committed[0]}=={r['urbanObjectId'] for r in committed[1]}
            and same_records
            and all(r['resolution'] in ('MATCH','HUMAN_APPROVE_MATCH') for r in committed[1]))
    phase=('TWO_SOURCE_COMMIT_AND_REUSE_PROVEN' if reused and preserved else
           'SOURCE_COMMIT_PROVEN' if any(complete) and preserved else 'NOT_PROVEN')
    return {'schema':'ouf.chatbot-file-owner-acceptance-receipt.v1','profile':PROFILE,'phase':phase,
            'status':'OWNER_EVIDENCE_OBSERVED_NOT_CHATBOT_ACCEPTED','planHash':digest(plan),
            'observedSourceCount':len(sources),'committedSourceCount':sum(complete),
            'requiredSourceCount':2,'expectedRowsPerSource':plan['expectedRowsPerSource'],
            'observedAckCount':sum(sum(h['acked'] is True for h in run[0]['handoffs']) for run in runs if len(run)==1),
            'openResolutionIssueCount':sum(r['openResolutionIssue'] is True for rows in committed for r in rows),
            'canonicalNoOpCount':sum(r['commitMatched'] is True and r['materialChange'] is False for rows in committed for r in rows),
            'eightBaselineObjectsPreserved':preserved,'secondSourceReusesSameObjectIds':reused,
            'sameCanonicalRecordHashesPreserved':same_records,
            'distinctUrbanObjectCount':len({r['urbanObjectId'] for rows in committed for r in rows if r['commitMatched'] is True}),
            'ownerEvidenceHash':digest({'sources':sources,'runs':runs,'udp':committed,'baseline':baseline}),
            'freshChatbotSearchProven':False,'recordValuesReadOrPrinted':False,'ownerWrites':0,
            'runtimeAuthorityIssued':False,'budgetReset':False,'notReleaseAcceptance':True}


class AcceptanceObserver:
    def __init__(self, databases, containers, plan):
        require(type(databases) is CohortDatabases and type(containers) is CohortContainers,
                'REAL_COHORT_OWNERS_REQUIRED_FOR_ACCEPTANCE')
        require(databases.action is containers.action and databases.installation_plan==containers.plan
                and containers.plan.get('acceptancePlanHash')==digest(plan)
                and plan.get('schema')=='ouf.chatbot-file-owner-acceptance-plan.v1'
                and plan.get('requiredSourceCount')==plan.get('maximumSourceCount')==2,
                'SIGNED_EXACT_TWO_SOURCE_ACCEPTANCE_PLAN_REQUIRED')
        self.databases,self.containers,self.plan=databases,containers,copy.deepcopy(plan)
        self.plan_hash=digest(plan)

    def _query(self,module,expression):
        binding=next(r for r in self.databases.plan['modules'] if r['module']==module)
        channel=Psql(self.databases.plan['postgresRuntimeBinding']['containerId'],binding['user'],binding['database'],
                     'ouf-cutover-acceptance')
        try:
            actual=channel.query("SELECT json_build_object('name',current_database(),'oid',oid::bigint) FROM pg_database WHERE datname=current_database()",
                                 statement=BEGIN_READ,timeout=10)
            require(actual=={'name':binding['database'],'oid':binding['databaseOid']},'ACCEPTANCE_DATABASE_IDENTITY_DRIFT')
            return channel.query(expression,timeout=10)
        finally:
            channel.close()  # Read-only transaction rolls back when psql exits.

    def observe(self):
        require(digest(self.plan)==self.plan_hash,'ACCEPTANCE_PLAN_DRIFT')
        self.databases.guard(); self.containers.guard()
        state=self.containers.record()
        require(state['nextStep']==len(self.containers.steps)
                and all(e['state']=='APPLIED' for e in state['effects']), 'COHORT_READY_REQUIRED_BEFORE_ACCEPTANCE')
        issued=json.loads(self.databases.action.raw)['issuedAt']
        require(type(issued) is int and issued>0,'SIGNED_ACTION_TIME_REQUIRED')
        sources=self._query('onboarding',source_query(self.plan,issued))
        require(type(sources) is list and len(sources)<=2,'ACCEPTANCE_SOURCE_SELECTION_AMBIGUOUS')
        runs=[]; udp_reads=[]
        for source in sources:
            if source['scopeMatched'] is not True or source['approvedPublicationMatched'] is not True:
                runs.append([]); udp_reads.append("'[]'::json"); continue
            require(1<=len(source['propertyIris'])<=32 and len(set(source['propertyIris']))==len(source['propertyIris']),
                    'EXACT_PUBLISHED_PROPERTY_SET_REQUIRED')
            rows=self._query('ingestion',ingestion_query(source,self.plan,issued))
            require(type(rows) is list and len(rows)<=1,'ACCEPTANCE_RUN_SELECTION_AMBIGUOUS')
            runs.append(rows)
            hands=rows[0]['handoffs'] if rows else []
            require(len(hands)<=self.plan['expectedRowsPerSource'],'ACCEPTANCE_HANDOFF_ROW_BOUND_EXCEEDED')
            udp_reads.append('('+udp_query(hands,source,self.plan)+')' if hands else "'[]'::json")
        # Both source bindings, their current objects, and the retained Cinema
        # baseline share one actual PostgreSQL snapshot.
        downstream=self._query('udp',"SELECT json_build_object('committed',json_build_array("+
            ','.join(udp_reads)+"),'baseline',("+baseline_query(self.plan)+'))')
        committed,baseline=downstream['committed'],downstream['baseline']
        # Source configuration remains immutable and ACTIVE across the downstream reads.
        require(self._query('onboarding',source_query(self.plan,issued))==sources,'ACCEPTANCE_SOURCE_CHANGED_DURING_READ')
        self.databases.guard(); self.containers.guard()
        return summarize(self.plan,sources,runs,committed,baseline)
