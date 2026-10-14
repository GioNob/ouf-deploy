"""Actual PostgreSQL owner-schema joins, using disposable fixture data only.

Set OUF_CHATBOT_ACCEPTANCE_PG_DSN to a local disposable superuser database.
The test creates/drops its own random database and loads real owner migrations;
it never uses target credentials, service endpoints or production databases.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
import urllib.parse
import uuid

ROOT=Path(__file__).resolve().parents[1]
OWNER=Path(os.environ.get('OUF_CHATBOT_DEPLOY_ROOT',str(ROOT)))
sys.path[:0]=[str(ROOT),str(OWNER),str(OWNER/'tools/semantic_database_cutover'),
             str(OWNER/'tools/semantic_policy_token_owner'),str(OWNER/'tools/semantic_application_cutover'),
             str(OWNER/'tools/semantic_cohort_admission/cohort-draft')]
from tools.chatbot_file_cohort.acceptance import (compile_acceptance_plan,source_query,ingestion_query,
    udp_query,baseline_query,summarize,BEGIN_READ,asset_query)
from database_gate import literal


def ident(): return str(uuid.uuid4())
def sqlval(v):
    if v is None:return 'NULL'
    if isinstance(v,bool):return 'true' if v else 'false'
    if isinstance(v,(int,float)):return str(v)
    return literal(json.dumps(v,separators=(',',':')) if isinstance(v,(dict,list)) else v)


@unittest.skipUnless(os.environ.get('OUF_CHATBOT_ACCEPTANCE_PG_DSN'),'actual PostgreSQL fixture DSN required')
class PostgreSqlAcceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base=os.environ['OUF_CHATBOT_ACCEPTANCE_PG_DSN']
        url=urllib.parse.urlsplit(cls.base)
        assert url.scheme in ('postgresql','postgres') and url.hostname in ('localhost','127.0.0.1','::1')
        assert shutil.which('psql'), 'psql required for actual owner joins'
        cls.db='ouf_acceptance_fixture_'+uuid.uuid4().hex
        cls.sql('CREATE DATABASE '+cls.db+';',base=True)
        cls.dsn=urllib.parse.urlunsplit(url._replace(path='/'+cls.db))
        onb=Path(os.environ['OUF_CHATBOT_ONBOARDING_ROOT'])/'src/main/resources/db/migration'
        ing=Path(os.environ['OUF_CHATBOT_INGESTION_ROOT'])
        udp=Path(os.environ['OUF_CHATBOT_UDP_ROOT'])
        groups=[(onb,[1,5,30,32]),(ing/'src/main/resources/db/migration',[1,4]),
                (udp/'src/main/resources/db/migration',[1,2,3,5,7,17])]
        for directory,versions in groups:
            for version in versions:
                paths=list(directory.glob('V'+str(version)+'__*.sql'))
                assert len(paths)==1,(directory,version)
                cls.sql(paths[0].read_text())

    @classmethod
    def tearDownClass(cls): cls.sql('DROP DATABASE '+cls.db+' WITH (FORCE);',base=True)

    @classmethod
    def sql(cls,text,base=False):
        result=subprocess.run(['psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1',cls.base if base else cls.dsn],
            input=text,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
        if result.returncode: raise AssertionError('PostgreSQL fixture statement failed: '+result.stderr)
        return result.stdout.strip()

    def query(self,expression):
        return json.loads(self.sql(BEGIN_READ+'\nSELECT ('+expression+');\nROLLBACK;'))

    def insert(self,table,**values):
        self.sql('INSERT INTO '+table+'('+','.join(values)+') VALUES('+','.join(sqlval(v) for v in values.values())+');')

    def test_two_sources_ack_is_not_commit_and_canonical_noop_preserves_lineage(self):
        issued=1577836800
        asset,profile,subject=ident(),ident(),ident()
        tenant='fixture-tenant'; kind='https://schema.org/PerformingArtsTheater'; ontology='https://fixture.invalid/teatri#Ontology'
        properties=['https://schema.org/name','https://schema.org/postalCode']
        baseline={'schema':'ouf.chatbot-existing-object-baseline.v1','count':8,'nextCursor':None,'partial':False,
          'canonicalType':'https://fixture.invalid/cinema#Cinema','objects':[
             {'urbanObjectId':ident(),'revision':1,'status':'ACTIVE','propertyIris':['https://schema.org/name']} for _ in range(8)]}
        profile_metadata={'rows':13,'columns':20,'delimiter':';','encoding':'UTF-8','headerRow':1}
        headers=[{'name':'field'+str(n)} for n in range(20)]
        self.insert('ouf_onboarding.managed_file_asset',asset_id=asset,staging_ref='object://fixture/csv',
           content_hash='sha256:'+'1'*64,media_type='text/csv',size_bytes=100,uploaded_by=subject,retention_ref='fixture')
        self.insert('ouf_onboarding.file_profile',profile_id=profile,asset_id=asset,version=1,format='CSV',
           metadata=profile_metadata,inferred_schema=headers,candidate_keys=[],sample_ref='fixture')
        original_input=self.query(asset_query(asset,profile,subject))
        plan=compile_acceptance_plan(asset_id=asset,profile_id=profile,profile_version=1,tenant=tenant,subject=subject,
              canonical_type=kind,ontology_semantic_id=ontology,baseline=baseline,asset_observation=original_input)
        # Baseline immutable revisions have independent historical handoffs.
        for n,row in enumerate(baseline['objects']):
            hand=ident();rev=ident();obj=row['urbanObjectId']; hashv='sha256:'+str(n)*64
            self.insert('ouf_udp.handoff_intake',handoff_id=hand,ingestion_run_id=ident(),ingestion_id='fixture',
                source_id='cinema-existing',type_code='FILE',source_object_id=str(n),content_hash=hashv,
                payload_json={},receipt_ref='udp://handoffs/'+hand)
            self.insert('ouf_udp.urban_object',urban_object_id=obj,canonical_type=baseline['canonicalType'],tenant_id=tenant)
            self.insert('ouf_udp.object_revision',revision_id=rev,urban_object_id=obj,revision_no=1,canonical_hash=hashv,
                authority_hash=hashv,authority_state={},canonical_payload={'https://schema.org/name':'fixture'},
                access_labels={},source_handoff_id=hand,bundle_ref='old',semantic_publication_ref='old')
            self.insert('ouf_udp.urban_object_current_state',urban_object_id=obj,revision_id=rev,canonical_hash=hashv,
                authority_hash=hashv,authority_state={},canonical_payload={'https://schema.org/name':'fixture'},access_labels={})
            self.sql('UPDATE ouf_udp.urban_object SET current_revision_id='+literal(rev)+' WHERE urban_object_id='+literal(obj))
        self.assertEqual(self.query(source_query(plan,issued)),[])
        self.assertEqual(self.query(baseline_query(plan)),{'count':8,'preserved':True})
        sources=[]; runrows=[]; udprows=[]; objects=[ident() for _ in range(13)]; revisions=[]
        for source_no in (1,2):
            if source_no==2:
                asset,profile=ident(),ident()
                self.insert('ouf_onboarding.managed_file_asset',asset_id=asset,staging_ref='object://fixture/csv-second-upload',
                   content_hash='sha256:'+'1'*64,media_type='text/csv',size_bytes=100,uploaded_by=subject,retention_ref='fixture')
                self.insert('ouf_onboarding.file_profile',profile_id=profile,asset_id=asset,version=1,format='CSV',
                   metadata=profile_metadata,inferred_schema=headers,candidate_keys=[],sample_ref='fixture')
            sid='fixture-source-'+str(source_no);vid=ident();pid=ident();challenge=ident();run=ident();pubset=ident()
            h='sha256:'+str(source_no+2)*64; bundleid='bundle-'+sid; bref=bundleid+':1.0.0:'+h
            runtime={'assetId':asset,'fileProfileId':profile,'execution':{'semanticPublicationSetRef':pubset},
              'udp':{'resolution':{'governedIdentity':{'tenantId':tenant,'canonicalClass':kind,'sourceId':sid}},
                     'materialization':{'properties':[{'propertyIri':v} for v in properties]}}}
            config={'extractionProfile':{'selection':{'assetId':asset,'fileProfileId':profile},'runtime':runtime}}
            bundle={'bundleId':bundleid,'bundleVersion':'1.0.0','source':{'sourceId':sid},'configurationHash':h,'checksum':h,
             'createdFromOnboardingVersion':vid,'extractionProfile':config['extractionProfile'],
             'semanticReferenceBindings':[{'semanticId':ontology,'semanticVersion':'1.0.0','revisionId':ident(),'publicationSetId':pubset}]}
            self.insert('ouf_onboarding.source',source_id=sid,name=sid,source_kind='INTERNAL_MANAGED',acquisition_mode='MANAGED',
                        owner_ref=subject,metadata={'managedFileAssetId':asset,'fileProfileId':profile})
            self.sql('UPDATE ouf_onboarding.managed_file_asset SET source_id='+literal(sid)+' WHERE asset_id='+literal(asset))
            self.insert('ouf_onboarding.onboarding_version',onboarding_version_id=vid,source_id=sid,version=1,state='ACTIVE',
                        configuration=config,configuration_hash=h,frozen_at='2026-01-01T00:00:00Z')
            self.insert('ouf_onboarding.managed_file_onboarding_attempt',asset_id=asset,subject_id=subject,idempotency_key='fixture-'+sid,
                        request_hash=h,source_id=sid,onboarding_version_id=vid)
            self.insert('ouf_onboarding.approval_challenge',challenge_id=challenge,onboarding_version_id=vid,source_id=sid,
                        configuration_hash=h,status='CONFIRMED',expires_at='2030-01-01',confirmed_at='2026-01-01')
            self.insert('ouf_onboarding.approval_decision',decision_id=ident(),challenge_id=challenge,onboarding_version_id=vid,
                        actor_subject=subject,decision='APPROVE',target_hash=h,authentication_context_ref='fixture-human')
            self.insert('ouf_onboarding.managed_onboarding_review',tenant_id=tenant,subject_id=subject,command_key='review-'+sid,
                        request_hash=h,source_id=sid,onboarding_version_id=vid,challenge_id=challenge,configuration_hash=h)
            self.insert('ouf_onboarding.published_configuration',publication_id=pid,source_id=sid,onboarding_version_id=vid,
                        bundle_version=1,bundle=bundle,checksum=h,active=True,effective_from='2026-01-01')
            selected=self.query(source_query(plan,issued));source=selected[-1]
            self.assertTrue(source['scopeMatched']);self.assertTrue(source['approvedPublicationMatched'])
            self.insert('ouf_ingestion.ing_run',run_id=run,source_id=sid,bundle_id=bundleid,bundle_version='1.0.0',
                        bundle_checksum=h,mode='MANAGED_ONCE',state='SUCCEEDED',correlation_id='fixture',tenant_id=tenant)
            for n,obj in enumerate(objects):
                hand=ident();lineage=ident();attempt=ident();key='fixture-record-'+str(n)
                refs={'bundleRef':bref,'semanticPublicationSetRef':pubset};identity={'sourceId':sid,'typeCode':'FILE','sourceObjectId':key}
                record_hash='sha256:'+hashlib.sha256(('fixture-record-'+str(n)).encode()).hexdigest()
                envelope={'handoffId':hand,'ingestionRunId':run,'lineageId':lineage,'contentHash':record_hash,
                          'sourceIdentity':identity,'contractRefs':refs}
                self.insert('ouf_ingestion.processing_attempt',attempt_id=attempt,run_id=run,source_object_id=key,attempt_no=1,
                            adapter_id='fixture',bundle_version='1.0.0',state='SUCCEEDED')
                self.insert('ouf_ingestion.ing_lineage',lineage_id=lineage,run_id=run,attempt_id=attempt,source_object_id=key,
                            bundle_ref=bref,adapter_ref='fixture',evidence_json={})
                self.insert('ouf_ingestion.handoff_outbox',handoff_id=hand,run_id=run,lineage_id=lineage,idempotency_key=hand,
                            payload_json=envelope,state='ACKED',downstream_receipt_ref='udp://handoffs/'+hand,acked_at='2026-01-01')
                self.insert('ouf_udp.handoff_intake',handoff_id=hand,ingestion_run_id=run,ingestion_id='fixture',source_id=sid,
                            type_code='FILE',source_object_id=key,content_hash=record_hash,payload_json=envelope,receipt_ref='udp://handoffs/'+hand)
                self.insert('ouf_udp.materialization_job',job_id=ident(),handoff_id=hand,state='READY')
                if source_no==1:
                    rev=ident();revisions.append(rev)
                    self.insert('ouf_udp.urban_object',urban_object_id=obj,canonical_type=kind,tenant_id=tenant)
                    self.insert('ouf_udp.object_revision',revision_id=rev,urban_object_id=obj,revision_no=1,canonical_hash=h,
                        authority_hash=h,authority_state={},canonical_payload={v:'fixture' for v in properties},access_labels={},
                        source_handoff_id=hand,bundle_ref=bref,semantic_publication_ref=pubset)
                    self.insert('ouf_udp.urban_object_current_state',urban_object_id=obj,revision_id=rev,canonical_hash=h,
                        authority_hash=h,authority_state={},canonical_payload={v:'fixture' for v in properties},access_labels={})
                    self.sql('UPDATE ouf_udp.urban_object SET current_revision_id='+literal(rev)+' WHERE urban_object_id='+literal(obj))
                self.insert('ouf_udp.source_binding',source_id=sid,type_code='FILE',source_object_id=key,urban_object_id=obj,first_handoff_id=hand)
                self.insert('ouf_udp.resolution_decision',resolution_decision_id=ident(),handoff_id=hand,candidate_ref='fixture',
                    outcome='NEW_OBJECT' if source_no==1 else 'MATCH',target_urban_object_id=None if source_no==1 else obj,
                    strategy_id='fixture',strategy_version='1',evidence_refs=[],decided_by='fixture-owner',policy_ref='fixture')
                self.insert('ouf_udp.materialization_observation',observation_id=ident(),handoff_id=hand,urban_object_id=obj,
                    revision_id=revisions[n],material_change=source_no==1,canonical_hash='sha256:'+'3'*64)
                for prop in properties:
                    self.insert('ouf_udp.property_contribution',contribution_id=ident(),urban_object_id=obj,handoff_id=hand,
                        property_iri=prop,value_json='"fixture"',value_hash=h,access_label='OPEN',source_id=sid,authority_rank=0,
                        provenance_json={'handoffRef':'handoff://'+hand,'ingestionRunId':run,'lineageRef':lineage,'sourceIdentity':identity,'contractRefs':refs})
            owner_run=self.query(ingestion_query(source,plan,issued))
            self.assertEqual(len(owner_run[0]['handoffs']),13)
            self.assertTrue(all(r['acked'] and r['lineageMatched'] for r in owner_run[0]['handoffs']))
            before=self.query(udp_query(owner_run[0]['handoffs'],source,plan))
            self.assertTrue(all(r['intakeMatched'] and r['newSourceProvenanceMatched'] for r in before))
            self.assertFalse(any(r['commitMatched'] for r in before),'ACK plus revision is insufficient before materialization success')
            self.sql('UPDATE ouf_udp.materialization_job SET state=\'SUCCEEDED\' WHERE handoff_id IN (SELECT handoff_id FROM ouf_udp.handoff_intake WHERE source_id='+literal(sid)+')')
            after=self.query(udp_query(owner_run[0]['handoffs'],source,plan))
            self.assertTrue(all(r['commitMatched'] for r in after))
            sources.append(source);runrows.append(owner_run);udprows.append(after)
            report=summarize(plan,sources,runrows,udprows,self.query(baseline_query(plan)))
            self.assertEqual(report['phase'],'SOURCE_COMMIT_PROVEN' if source_no==1 else 'TWO_SOURCE_COMMIT_AND_REUSE_PROVEN')
            self.assertFalse(report['freshChatbotSearchProven'])
        self.assertEqual(report['canonicalNoOpCount'],13)
        self.assertEqual(report['committedUrbanObjectIds'],sorted(objects))
        self.assertEqual(report['distinctUrbanObjectCount'],len(report['committedUrbanObjectIds']))
        self.assertTrue(report['sameCanonicalRecordHashesPreserved'])
        # A historical bound asset remains the immutable byte/profile baseline;
        # it does not block deployment or get reassigned to another source.
        bound_input=self.query(asset_query(plan['assetId'],plan['profileId'],subject))
        bound_plan=compile_acceptance_plan(asset_id=plan['assetId'],profile_id=plan['profileId'],profile_version=1,
             tenant=tenant,subject=subject,canonical_type=kind,ontology_semantic_id=ontology,baseline=baseline,
             asset_observation=bound_input)
        self.assertFalse(bound_plan['existingAssetReusable'])
        remaining=self.query(source_query(bound_plan,issued))
        self.assertEqual([s['sourceId'] for s in remaining],['fixture-source-2'])
        self.assertEqual(summarize(bound_plan,remaining,[runrows[1]],[udprows[1]],self.query(baseline_query(plan)))['requiredAdditionalUploadCount'],2)
        swapped=copy.deepcopy(udprows)
        swapped[1][0]['urbanObjectId'],swapped[1][1]['urbanObjectId']=swapped[1][1]['urbanObjectId'],swapped[1][0]['urbanObjectId']
        self.assertFalse(summarize(plan,sources,runrows,swapped,self.query(baseline_query(plan)))['secondSourceReusesSameObjectIds'])
        # The second source's original revision is legitimate; provenance still is mandatory.
        second_handoff=runrows[1][0]['handoffs'][0]['handoffId']
        broken_source=copy.deepcopy(sources[1]);broken_source['propertyIris'].append('https://fixture.invalid/missing')
        missing=self.query(udp_query(runrows[1][0]['handoffs'],broken_source,plan))
        self.assertFalse(any(r['newSourceProvenanceMatched'] for r in missing))
        bad_plan=copy.deepcopy(plan);bad_plan['tenant']='other-tenant'
        self.assertFalse(any(r['commitMatched'] for r in self.query(udp_query(runrows[1][0]['handoffs'],sources[1],bad_plan))))
        self.assertFalse(self.query(source_query(bad_plan,issued))[0]['approvedPublicationMatched'])
        self.sql('UPDATE ouf_udp.urban_object SET revision=2 WHERE urban_object_id='+literal(baseline['objects'][0]['urbanObjectId']))
        self.assertFalse(self.query(baseline_query(plan))['preserved'])
        self.assertEqual(summarize(plan,sources,runrows,udprows,self.query(baseline_query(plan)))['phase'],'NOT_PROVEN')
        # Runtime evidence query runs in a PostgreSQL READ ONLY transaction.
        with self.assertRaisesRegex(AssertionError,'read-only'):
            self.sql(BEGIN_READ+"\nUPDATE ouf_udp.urban_object SET status='DELETED';")
