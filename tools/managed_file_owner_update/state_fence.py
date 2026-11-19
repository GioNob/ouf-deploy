"""Closed36→38 preservation fence. No ownership adoption or budget mutation."""
import copy

def bind(base):
    extra=('managed_file_upload_attempt','managed_profile_budget_session','managed_profile_event')
    def fingerprint(table):
        return "'%s',(SELECT jsonb_build_object('rows',count(*),'sha256',encode(sha256(convert_to(coalesce(string_agg(encode(sha256(convert_to(t.payload::text,'UTF8')),'hex'),E'\\n' ORDER BY encode(sha256(convert_to(t.payload::text,'UTF8')),'hex')),''),'UTF8')),'hex')) FROM (SELECT to_jsonb(x) AS payload FROM ouf_onboarding.%s x LIMIT 10001) t)"%(table,table)
    class Fence:
        TABLES=(*base.TABLES,*extra);JOB=base.JOB;ASSET=base.ASSET
        def query(self,after=False):
            base.require(type(after)is bool,'EXACT_OWNER_SCHEMA_QUERY_SELECTOR')
            q=base.query(True)
            q=q.replace("to_jsonb(x)-ARRAY['generation','lock_version','input_binding_hash','recovery_session_id','budget_profile','failure_class']","to_jsonb(x)")
            # A NULL tenant addition is the only allowed row representation delta.
            q=q.replace('to_jsonb(x) AS payload FROM ouf_onboarding.managed_file_asset',"to_jsonb(x)-'tenant_id' AS payload FROM ouf_onboarding.managed_file_asset")
            marker="), 'migrationAddition'";base.require(marker in q,'SEALED_V36_QUERY_SHAPE_REQUIRED')
            q=q.replace(marker,','+','.join(fingerprint(t)for t in extra)+marker,1)
            control=""", 'retainedAsset',(SELECT jsonb_build_object('uploaderMatchesExpected',uploaded_by='b93d8cf6-cd14-4ee6-91d7-84cd76c4f500','hashMatchesExpected',content_hash='sha256:f670059bb524832aa9cd78fbe5e907be053244248ff1ef4d7962b14fcd72c311','sizeMatchesExpected',size_bytes=13903) FROM ouf_onboarding.managed_file_asset WHERE asset_id='"""+base.ASSET+"""'::uuid), 'jobControl',(SELECT jsonb_build_object('generation',generation,'version',lock_version,'hasRecoverySession',recovery_session_id IS NOT NULL) FROM ouf_onboarding.file_profile_job WHERE job_id='"""+base.JOB+"""'::uuid AND asset_id='"""+base.ASSET+"""'::uuid)"""
            if after:
                addition=""", 'ownershipSchema',jsonb_build_object(
'tenantColumn',(SELECT count(*) FROM information_schema.columns WHERE table_schema='ouf_onboarding' AND table_name='managed_file_asset' AND column_name='tenant_id' AND data_type='text' AND is_nullable='YES'),
'nonNullLegacyTenants',(SELECT count(*) FROM ouf_onboarding.managed_file_asset WHERE tenant_id IS NOT NULL),
'ownerReceipts',(SELECT count(*) FROM ouf_onboarding.managed_file_owner_reconciliation),
'enabledGuards',(SELECT count(*) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='ouf_onboarding' AND t.tgname IN ('managed_file_owner_immutable','managed_file_owner_reconciliation_immutable') AND t.tgenabled='O'))"""
            else:
                addition=""", 'ownershipSchema',jsonb_build_object('deltaAbsent',NOT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema='ouf_onboarding' AND table_name='managed_file_asset' AND column_name='tenant_id') AND to_regclass('ouf_onboarding.managed_file_owner_reconciliation') IS NULL AND NOT EXISTS(SELECT 1 FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='ouf_onboarding' AND t.tgname IN ('managed_file_owner_immutable','managed_file_owner_reconciliation_immutable')))"""
            base.require(q.endswith(');\nROLLBACK;'),'CLOSED_OPERATIONAL_QUERY_END_REQUIRED')
            return q[:-len(');\nROLLBACK;')]+control+addition+');\nROLLBACK;'
        def validate(self,facts,profile,migrations,baseline=None,after=False):
            base.require(len(migrations)==38 and [r['version']for r in migrations]==[str(i)for i in range(1,39)],'ALL38_PACKAGED_MIGRATIONS_REQUIRED')
            sql=[r for r in facts['history']if r['type']=='SQL'];wanted=migrations if after else migrations[:36]
            base.require(len(sql)==len(wanted)and len({r['version']for r in sql})==len(wanted),'EXACT36_BEFORE38_AFTER_SQL_HISTORY_REQUIRED')
            by={r['version']:r for r in wanted}
            for row in sql:
                expected=by.get(row['version']);base.require(expected is not None and row['script']==expected['script']and row['checksum']==expected['flywayChecksum']and row['success']is True,'EXACT_REVIEWED_MIGRATION_HISTORY_REQUIRED')
            base.require(facts['retainedAsset']=={'uploaderMatchesExpected':True,'hashMatchesExpected':True,'sizeMatchesExpected':True},'EXACT_RETAINED_FARMACIE_INPUT_REQUIRED')
            base.require(facts['jobControl']=={'generation':0,'version':0,'hasRecoverySession':False},'SAME_FAILED5_CONTROL_STATE_REQUIRED')
            base.require(set(facts['states'])==set(self.TABLES),'ALL12_OPERATIONAL_FINGERPRINTS_REQUIRED')
            for table in extra:
                r=facts['states'][table];base.require(set(r)=={'rows','sha256'}and type(r['rows'])is int and 0<=r['rows']<=10000 and type(r['sha256'])is str and base.re.fullmatch('[a-f0-9]{64}',r['sha256']),'BOUNDED_EXTRA_OPERATIONAL_FINGERPRINT_REQUIRED')
            base.require(all(facts['states'][t]['rows']==0 for t in('managed_profile_budget_session','managed_profile_event')),'NO_RECOVERY_BUDGET_OR_EVENT_ALLOWED')
            schema={'tenantColumn':1,'nonNullLegacyTenants':0,'ownerReceipts':0,'enabledGuards':2}if after else{'deltaAbsent':True}
            base.require(facts['ownershipSchema']==schema,'ONLY_EMPTY_ADDITIVE_V37_V38_OWNER_SCHEMA_ALLOWED')
            legacy=copy.deepcopy(facts);legacy.pop('ownershipSchema');legacy.pop('jobControl');legacy.pop('retainedAsset')
            legacy['history']=[r for r in legacy['history']if r['type']!='SQL'or r['version']in{str(i)for i in range(1,37)}]
            legacy['states']={t:legacy['states'][t]for t in base.TABLES};base.validate(legacy,profile,migrations[:36],after=True)
            normalized=copy.deepcopy(facts);normalized.pop('ownershipSchema')
            normalized['history']=[r for r in normalized['history']if r['type']!='SQL'or r['version']not in('37','38')]
            if baseline is not None:
                before=copy.deepcopy(baseline);before.pop('ownershipSchema');base.require(normalized==before,'OPERATIONAL_ROWS_COUNTERS_OR_HISTORY_CHANGED')
            return {'operationalStateHash':base.digest(normalized),'installedSchemaVersion':38 if after else 36,
                'migrationHistoryExact':True,'retainedFailedJobUnchanged':True,'noPendingProfileOrReadinessWork':True,
                'all12OperationalFingerprintsUnchanged':baseline is not None,'zeroBudgetsAndEventsProven':True,
                'legacyTenantNotBackfilled':after,'newOwnerReceiptTableEmpty':after,'newOwnerGuardsEnabled':after,
                'databaseMigrationsPerformed':2 if after else 0}
        def arguments(self,profile,empty_config,sql):
            base.require(sql in(self.query(False),self.query(True)),'ONLY_CLOSED36_TO38_READ_ONLY_QUERY_ALLOWED')
            args=base.arguments(profile,empty_config,base.query(True));args[-1]=sql;return args
    return Fence()
