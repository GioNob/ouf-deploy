"""Current single-owner admission for an exact same-image request-only plan."""
import ast,copy,hashlib,json,os,re,stat,types,zipfile
from pathlib import Path
from urllib.parse import quote,urlsplit

TARGET={
    'preparedRoot':'/etc/ouf/deploy-snapshots/managed-profile-ths-native-plan-d0dbbd61-20261028-v1',
    'executionRoot':'/etc/ouf/deploy-snapshots/managed-profile-ths-request-update-e22a443d-20261028-v1',
    'executionInputsHash':'e22a443d2617bf4db06b90ca272fd80e87fe3a05a9b4b6386b15cce51fea11e4',
    'conditionalPlanHash':'9c961982f1e521ca67e25de6d9437cbfc670821c874625d77b9a092da33b6900',
    'configurationProfileHash':'d0dbbd61b5a6486124e229e646ce63a96165dfc2433ae200f7fec92383d5140c',
    'iamResultHash':'c82b1b1025086faf4acf0899485643209f8929c4fa8ce6ca045fc2bfbdd7d027',
    'sources':{'onboarding':'9890b31868641e5be43c949a56f4ef69dd23bdfd'},
    'testedSources':{'onboarding':'de65795d07ede9ebca1bdea02ef250860d87f433'},
    'nativeImageIds':{'onboarding':'sha256:c512c24787304dc0ee40d2b5b1559d458ddf1d5a65a068775ef173c47ba849a3'},
    'archives':{'onboarding':'8571d101da6c06c87d3659c67f4c359f285a9e14a340baa30cbbcc54e147d554'},
    'retainedImageInputsPath':'/etc/ouf/deploy-snapshots/managed-csv-control-image-plan-14a96f782827c894-v1/execution-inputs.json',
    'retainedImageInputsHash':'900b09c6d29a20fda5dfff1f1333df167363c96e865cc2c13a7b58791f4e0c51',
    'ownerOverlayPath':'/opt/ouf/secrets/onboarding-ths.yaml',
    'preparationCounts':{'bytes':750536,'engineGets':27,'privateMetadataReads':5},
    'transportHashes':{'retainedEngineBindingHash':'8e3adb93d5874ee423092e7171e501a2fcef3386c44fbe48ee40c7c92ef8bb01',
        'capturedEngineBindingHash':'c17569848d56b8efb49ded7ab94b9e4e307ecb0b80eead2fed42aa34d1ed5718',
        'peerCredentialsHash':'7ff52993d5d3cb149089942de7fc7a6511db2671cf2125976c081ad6fff89772'}}

def bind(base):
    class Context(base.Context):
        def __init__(self,parts,auth,sign,journal,closure,*,case=TARGET,public_authority=None,runtime=None):
            self.core,self.p,self.images,self.mac,self.http,self.ports_module,self.watch,self.engine_helpers,self.terminal=[
                parts[k]for k in('authority','plan_helper','image_custody','retained_mac','transport','ports','quarantine','engine_creation','terminal')]
            c=self.core;self.auth,self.sign,self.journal_module=auth,sign,journal
            self.closure=copy.deepcopy(closure);self.case=copy.deepcopy(case);self.root=Path(case['executionRoot']);self.runtime=runtime
            self.serial=0;self.execution=None;self.responses=0;self.receiptBytes=0;self.issueStarted=False
            self.counts={k:0 for k in c.LIMITS};self.p.ancestry(self.root.parent)
            c.require(not os.path.lexists(self.root),'THS_REQUEST_UPDATE_SCOPE_CONSUMED_NO_REPLAY')
            self.root.mkdir(mode=0o700);self.root.chmod(0o700);self.sync(self.root.parent)
            self.write(self.root,'preparation-claim.json',{'schema':'ouf.ths-owner-request-update-preflight-claim.v1',
                'executionInputsHash':case['executionInputsHash'],'maximums':c.LIMITS,
                'runtimeEffectsDispatched':0,'automaticReplayAllowed':False,'budgetReset':False})
            prepared=Path(case['preparedRoot']);retained={}
            for name,checksum in [('execution-inputs.json',case['executionInputsHash']),
                ('execution-plan.json',case['conditionalPlanHash']),('result.json',None)]:
                self.reserve('ownerConfigurationReads');retained[name]=self.read(prepared/name,checksum)
            native,plan,result=(retained[n]for n in('execution-inputs.json','execution-plan.json','result.json'))
            c.require(native['schema']=='ouf.ths-owner-request-private-native-inputs.v1'
                and native['conditionalNativePlanHash']==case['conditionalPlanHash']
                and native['configurationProfileHash']==case['configurationProfileHash']
                and c.digest(native['retainedIamResult'])==case['iamResultHash']
                and all(native[k]is False for k in('executionEntryQualified','runtimeAuthorityIssued',
                    'targetApplyAuthorized','automaticReplayAllowed','budgetReset')),
                'EXACT_PREPARED_SINGLE_OWNER_PRIVATE_INPUTS_REQUIRED')
            c.require(result['schema']=='ouf.ths-owner-request-native-plan-result.v1'
                and result['status']=='THS_OWNER_REQUEST_CONDITIONAL_NATIVE_PLAN_PREPARED_NOT_AUTHORIZED'
                and result['complete']is True and result['executionInputsHash']==case['executionInputsHash']
                and result['conditionalNativePlanHash']==case['conditionalPlanHash']
                and result['configurationProfileHash']==case['configurationProfileHash']
                and result['counts']==case['preparationCounts'] and result['targetRoles']==['onboarding']
                and result['cohortSize']==13 and result['unchangedPeers']==12
                and result['scopePatchApplied']is False and result['runtimeAuthorityIssued']is False,
                'EXACT_SUCCESSFUL_CONSUMED_NATIVE_PLAN_REQUIRED')
            capture=native['currentCapture'];self.prepared_inputs=copy.deepcopy(native)
            self.inputs=copy.deepcopy(capture);self.proposal=copy.deepcopy(plan)
            c.require(plan['schema']=='ouf.ths-owner-request-conditional-native-plan.v1'
                and plan['kind']=='FROZEN_CONDITIONAL_PROPOSAL_NOT_EXECUTABLE'
                and c.digest(plan)==case['conditionalPlanHash']
                and plan['configurationProfileHash']==case['configurationProfileHash']
                and plan['iamResultHash']==case['iamResultHash']
                and plan['targetRoles']==['onboarding']and set(plan['replacements'])=={'onboarding'}
                and len(plan['existingApplications'])==13 and len(plan['unchangedApplications'])==12
                and plan['databaseMigration']=={'from':36,'to':36,'newMigrations':0}
                and all(plan[k]is False for k in('executionEntryQualified','databaseAdmissionProven',
                    'currentJobOrBudgetStateObserved','runtimeAuthorityIssued','targetApplyAuthorized',
                    'iamConfigurationMutationAuthorized','imageImportAuthorized','humanBudgetsOrResumeAuthorized',
                    'sourceActivationAuthorized','automaticRollbackAllowed','automaticReplayAllowed','budgetReset')),
                'EXACT_UNEXECUTED_SINGLE_OWNER_NO_IMPORT_PLAN_REQUIRED')
            self.proposal['readReplacements']=self.proposal['replacements']
            row=self.proposal['readReplacements']['onboarding'];actual=capture['currentObservations']['onboarding']
            c.require(row['oldBinding']==self.p.stable_binding(actual)
                and row['request']['Image']==actual['Image']==case['nativeImageIds']['onboarding']
                and row['sameNativeImageRequired']is True and row['nativeImageImportAuthorized']is False,
                'EXACT_SAME_INSTALLED_IMAGE_AND_OWNER_REQUIRED')
            self.proposal['onboardingReplacement']=row;self.proposal['nativeIdentityProfile']='CONFIG_AND_NATIVE_MANIFEST'
            self.application_facts=copy.deepcopy(plan['candidateApplicationFacts']);self.migrations=self.application_facts['migrations']
            c.require(len(self.migrations)==36,'ALL_36_RETAINED_MIGRATION_FACTS_REQUIRED')
            self.database_profile=copy.deepcopy(plan['boundDatabaseProfile'])
            self.database,self.fence,self.backup=parts['database'],parts['state_fence'],parts['backup']
            self.transport_compatibility=self.database.retained_transport(c,self.database_profile,capture['engineBinding'],case['transportHashes'])
            self.proposal['operationalSqlHash']=c.sha(self.fence.query(True).encode())
            self.proposal['operationalSqlAfterHash']=self.proposal['operationalSqlHash']
            self.reserve('ownerConfigurationReads');original=self.read(case['retainedImageInputsPath'],case['retainedImageInputsHash'])
            audit=original['imageAudits']['onboarding'];archive=original['nativeArchives']['onboarding']
            c.require(audit==row['imageAudit']and audit['sourceCommit']==case['testedSources']['onboarding']
                and audit['nativeIdentity']['nativeImageId']==case['nativeImageIds']['onboarding']
                and self.images.runtime_image_id(audit)==actual['Image']
                and archive['sha256']==case['archives']['onboarding']
                and Path(archive['path']).parent==Path(case['retainedImageInputsPath']).parent,
                'EXACT_RETAINED_ARCHIVE_READ_ONLY_NO_IMPORT_REQUIRED')
            self.archives={'onboarding':copy.deepcopy(archive)};self.archive=self.archives['onboarding']
            self.facts={'onboarding':{'audit':copy.deepcopy(audit),'archive':copy.deepcopy(archive),
                'identity':{'nativeImageId':actual['Image'],'configurationImageId':audit['imageId']}}}
            self.native={'imageAudit':copy.deepcopy(audit),'currentOnboarding':copy.deepcopy(actual)}
            overlays=plan['nativeFlywayConfiguration']['ownerOverlays']
            c.require(len(overlays)==1 and overlays[0]['binding']['path']==case['ownerOverlayPath'],'ONE_RETAINED_OWNER_OVERLAY_REQUIRED')
            self.reserve('ownerConfigurationContentReads')
            self.owner_overlay_raw,self.owner_overlay_binding=self.p.private_config(case['ownerOverlayPath'],overlays[0]['binding'])
            self.configuration_raw=parts['configuration_raw'];self.onb_context=parts['onb_context']
            self.engine=self.http.Engine(self.p,capture['engineBinding']);self.engine.before=self.before_dispatch;self.engine.retained=self.retained
            self.public_authority=public_authority or parts['base_context'].public_authority
            self.authority_metadata=self.refresh_authority();self.profile=self.authority_metadata['profile'];self.openssl=self.executable()
            paths=[prepared/name for name in retained]+[Path(case['retainedImageInputsPath'])]
            self.input_seals={str(path):list(self.p.frame(path.lstat()))for path in paths}
            self.source_seals={path:list(self.p.frame(Path(path).lstat()))for path in closure}
            self.verify_archive();self.application_jar=self.extract_application()
            if runtime is not None:self.runtime_binding=self.runtime_snapshot()
            self.check_sources()

        def classify_configuration(self,postgres):
            c=self.core;actual=copy.deepcopy(self.native['currentOnboarding'])
            actual['Config']['Env']=copy.deepcopy(self.proposal['onboardingReplacement']['request']['Env'])
            def private_file(path,checksum,maximum):
                c.require(path==self.application_jar['path']and checksum==self.application_jar['sha256']
                    and maximum==268435456,'ONLY_RETAINED_EXACT_APPLICATION_JAR')
                c.require(hashlib.sha256(Path(path).read_bytes()).hexdigest()==checksum,'APPLICATION_JAR_CHANGED')
            def owner(path):
                c.require(path==self.case['ownerOverlayPath'],'ONLY_ONE_NAMED_OWNER_CONFIGURATION')
                return self.owner_overlay_raw,self.owner_overlay_binding
            namespace={'hashlib':hashlib,'json':json,'os':os,'Path':Path,'re':re,'urlsplit':urlsplit,
                'zipfile':zipfile,'require':c.require,'env':lambda rows:self.p.env({'Env':rows}),
                'private_file':private_file,'private_config':owner}
            names=('application_json_metadata','owner_json_overlay','overlay_text','additional_location','verify')
            nodes=[n for n in ast.parse(self.configuration_raw).body if isinstance(n,ast.FunctionDef)and n.name in names]
            c.require(len(nodes)==len(names),'EXACT_SEALED_NATIVE_VERIFIER_REQUIRED')
            exec(compile(ast.Module(body=nodes,type_ignores=[]),'<sealed-configuration>','exec'),namespace)
            identity=self.database_profile['identity']
            observed=namespace['verify'](actual,{'jar':self.application_jar},postgres,
                {'user':identity['runtimeRole'],'database':identity['database'],'schema':identity['schema']},
                identity['postgresPort'],self.application_facts['applicationYamlSha256'])
            expected=copy.deepcopy(self.proposal['nativeFlywayConfiguration'])
            expected['configurationSha256']=self.application_facts['applicationYamlSha256']
            before=expected['applicationJson'];delta=self.proposal['scopeRequestDelta']
            original_json=self.p.env(self.native['currentOnboarding']['Config'])['SPRING_APPLICATION_JSON']
            c.require(type(before)is dict and before['rawSha256']==hashlib.sha256(original_json.encode()).hexdigest()
                and c.digest(self.p.decode(original_json))==delta['requestBeforeHash']
                and type(observed['applicationJson'])is dict
                and observed['applicationJson']['rawSha256']==delta['conditionalRequestAfterHash'],
                'ONLY_REVIEWED_ADDITIVE_JSON_HASH_TRANSITION_REQUIRED')
            expected['applicationJson']['rawSha256']=delta['conditionalRequestAfterHash']
            c.require(observed==expected,'EXACT_OWNER_OVERLAY_AND_ONLY_REQUEST_DELTA_REQUIRED')
            self.proposal['nativeFlywayConfiguration']=observed;self.configuration_classified=True
            del self.owner_overlay_raw

        def current(self):
            c=self.core;self.check_sources()
            print('Verifico13generazioni,12peer,immagine gia installata e rete;solo Onboarding e nessuna SQL prima di APPROVO.',flush=True)
            for role,binding in self.proposal['existingApplications'].items():
                status,actual=self.preflight_get('/v1.44/containers/'+binding['containerId']+'/json')
                c.require(status==200 and actual['State']['Running']is True and actual['State']['Paused']is False
                    and actual['State']['Restarting']is False and self.p.stable_binding(actual)==binding
                    and self.p.process_pin(actual['State']['Pid'])==self.inputs['currentProcessPins'][role],
                    'ALL_13_CURRENT_GENERATIONS_REQUIRED')
                if actual['Id']==self.database_profile['postgresRuntimeBinding']['containerId']:
                    self.database.check_postgres(self,actual)
                    if not getattr(self,'configuration_classified',False):self.classify_configuration(actual)
            c.require(getattr(self,'configuration_classified',False),'OWNER_CONFIGURATION_PRECEDENCE_REQUIRED')
            row=self.proposal['onboardingReplacement'];status,_=self.preflight_get('/v1.44/containers/'+row['retiredName']+'/json')
            c.require(status==404,'RETAINED_OWNER_NAME_ALREADY_EXISTS')
            status,info=self.preflight_get('/v1.44/info')
            c.require(status==200 and info['ServerVersion']=='29.8.1'
                and ['driver-type','io.containerd.snapshotter.v1']in(info.get('DriverStatus')or[]),'EXACT_NATIVE_ENGINE_PROFILE_REQUIRED')
            status,image=self.preflight_get('/v1.44/images/'+quote(self.case['nativeImageIds']['onboarding'],safe='')+'/json')
            c.require(status==200,'SAME_NATIVE_IMAGE_MUST_ALREADY_EXIST_NO_IMPORT')
            self.images.loaded(self.facts['onboarding']['audit'],image)
            net=row['network'];status,value=self.preflight_get('/v1.44/networks/'+net['id'])
            c.require(status==200 and value['Id']==net['id']and value['Name']==net['name']
                and value['Driver']=='bridge'and value['Scope']=='local','EXACT_CURRENT_OWNER_NETWORK_REQUIRED')
            members=value.get('Containers')or{}
            expected={v['Id']for v in self.inputs['currentObservations'].values()
                if any(endpoint.get('NetworkID')==net['id']for endpoint in v['NetworkSettings']['Networks'].values())}
            wanted=row['request']['NetworkingConfig']['EndpointsConfig'][net['name']]['MacAddress'].lower()
            c.require(set(members)==expected and [cid for cid,ep in members.items()
                if str(ep.get('MacAddress','')).lower()==wanted]==[row['oldBinding']['containerId']],
                'EXACT_COMPLETE_NETWORK_AND_SOLE_OWNER_MAC_REQUIRED')
            baseline={net['id']:copy.deepcopy(members)}
            if hasattr(self,'network_baseline'):c.require(baseline==self.network_baseline,'NETWORK_CHANGED_DURING_HUMAN_REVIEW')
            self.network_baseline=baseline;self.admission()

        def import_claim(self,*args):
            self.core.require(False,'IMAGE_IMPORT_FORBIDDEN_SAME_IMAGE_REQUEST_UPDATE')

        def owner_health(self,role,pin):
            self.core.require(role=='onboarding','ONLY_ONBOARDING_READINESS')
            return self.http.health(self.p,pin,self.proposal['onboardingReplacement']['readiness'])
    return Context
