-- Synthetic relational fixture, applied only to the disposable CI PostgreSQL.
INSERT INTO ouf_onboarding.managed_file_asset(asset_id,tenant_id,staging_ref,content_hash,media_type,size_bytes,uploaded_by,retention_ref)
VALUES('11111111-1111-1111-1111-111111111111','tenant','object://managed-files/11111111-1111-1111-1111-111111111111','sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad','text/csv',3,'fixture','retention-fixture');
INSERT INTO ouf_onboarding.managed_file_upload_intent(intent_id,upload_kind,tenant_id,subject_id,idempotency_key,file_id,content_hash,size_bytes,staging_ref,epoch,state,asset_id,acknowledged_at)
VALUES('11111111-1111-1111-1111-111111111111','DIRECT','tenant','fixture','fixture','file_fixture','sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',3,'object://managed-files/11111111-1111-1111-1111-111111111111',1,'ACKED','11111111-1111-1111-1111-111111111111',now());
INSERT INTO ouf_udp.lake_object(lake_object_id,tenant_id,source_id,type_code,tier,content_hash,media_type,logical_size_bytes,locator,state,retention_class,access_label,retention_until)
VALUES('22222222-2222-2222-2222-222222222222','tenant','source','TYPE','RAW','sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad','text/plain',3,'lake/tenant/raw/ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad','VERIFIED','AUDIT','private',now()+interval '1 day');
INSERT INTO ouf_ingestion.ing_run(run_id,source_id,tenant_id,bundle_id,bundle_version,bundle_checksum,mode,state,correlation_id)
VALUES('33333333-3333-3333-3333-333333333333','source','tenant','bundle','1','fixture','MANAGED_ONCE','SUCCEEDED','fixture');
INSERT INTO ouf_ingestion.ing_partition(run_id,partition_key,state) VALUES('33333333-3333-3333-3333-333333333333','default','SUCCEEDED');
INSERT INTO ouf_ingestion.processing_attempt(attempt_id,run_id,source_object_id,attempt_no,adapter_id,bundle_version,state)
VALUES('44444444-4444-4444-4444-444444444444','33333333-3333-3333-3333-333333333333','source-object',1,'adapter','1','SUCCEEDED');
INSERT INTO ouf_ingestion.ing_lineage(lineage_id,run_id,attempt_id,source_object_id,bundle_ref,adapter_ref,evidence_json)
VALUES('55555555-5555-5555-5555-555555555555','33333333-3333-3333-3333-333333333333','44444444-4444-4444-4444-444444444444','source-object','bundle','adapter','{"data":{"rawObjectRef":"lake://22222222-2222-2222-2222-222222222222","rawHash":"sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","outputHash":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}}');
-- Canonical output hash deliberately differs from raw bytes. They must not be equated.
INSERT INTO ouf_ingestion.handoff_outbox(handoff_id,run_id,lineage_id,idempotency_key,payload_json,state,downstream_receipt_ref,acked_at,sequence_no,candidate_watermark_json)
VALUES('66666666-6666-6666-6666-666666666666','33333333-3333-3333-3333-333333333333','55555555-5555-5555-5555-555555555555','fixture','{"rawObjectRef":"lake://22222222-2222-2222-2222-222222222222","contentHash":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}','ACKED','udp://handoffs/66666666-6666-6666-6666-666666666666',now(),1,'{"cursor":1}');
INSERT INTO ouf_ingestion.ing_watermark(source_id,partition_key,watermark_json,committed_handoff_id)
VALUES('source','default','{"cursor":1}','66666666-6666-6666-6666-666666666666');
INSERT INTO ouf_udp.handoff_intake(handoff_id,ingestion_run_id,ingestion_id,source_id,type_code,source_object_id,content_hash,payload_json,receipt_ref,source_raw_lake_object_id)
VALUES('66666666-6666-6666-6666-666666666666','33333333-3333-3333-3333-333333333333','fixture','source','TYPE','source-object','sha256:0000000000000000000000000000000000000000000000000000000000000000','{}','udp://handoffs/66666666-6666-6666-6666-666666666666','22222222-2222-2222-2222-222222222222');
