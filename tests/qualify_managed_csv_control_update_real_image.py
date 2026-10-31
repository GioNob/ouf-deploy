"""Exact control-candidate JAR/configuration under disposable root custody; no Engine/SQL/OAuth."""
import copy,importlib.util,json,os,pathlib,subprocess,types
ROOT=pathlib.Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
assert os.geteuid()==os.getegid()==0
subprocess.run(['/usr/bin/python3','-I','-S','-B',str(ROOT/'tests/qualify_managed_csv_control_image_plan.py')],check=True)
prepared=pathlib.Path('/root/ouf-managed-csv-control-plan-ci/image-plan');native=json.loads((prepared/'execution-inputs.json').read_bytes())
case=json.loads((ROOT/'releases/managed-profile-control-onboarding-image-custody-20261027.json').read_bytes())
context=load('qualified_profile_context',ROOT/'tools/onboarding_profile_recovery_update/context.py');p=load('qualified_profile_pure_plan',ROOT/'tools/acquisition_read_native/plan_helper.py')
adapter=load('new_control_context',ROOT/'tools/managed_csv_control_update/context.py');base=load('retained_control_context',ROOT/'tools/acquisition_redaction_update/context.py');Control=adapter.bind(base);ctx=Control.__new__(Control);ctx.onb_context=context;ctx.root=pathlib.Path('/root/ouf-profile-recovery-real-image');ctx.root.mkdir(mode=0o700)
ctx.native={'imageAudit':native['imageAudits']['onboarding'],'currentOnboarding':native['currentCapture']['currentObservations']['onboarding']};ctx.p=p;ctx.archive=native['nativeArchives']['onboarding'];ctx.application_facts=case['application'];ctx.application_jar=ctx.extract_application()
assert ctx.application_jar['sha256']==case['application']['jarSha256']
raw=b'{"ouf":{"authorization":{"ths":{"enabled":true}}}}';owner=ctx.root/'owner.yaml';ctx.write(ctx.root,owner.name,raw)
_,binding=p.private_config(str(owner));ctx.case={'ownerOverlayPath':str(owner)};ctx.owner_overlay_binding=binding;ctx.owner_overlay_raw=raw
ctx.configuration_raw=(ROOT/'tools/source_revision_update/configuration.py').read_bytes()
overlay={'format':'STRICT_JSON','ownerThsOAuthAndSessionOnly':True,'retainedSessionSecurityValidated':False,'migrationOverridePresent':False,
    'propertyCount':1,'bytes':len(raw),'sha256':context.sha(raw),'configurationValuesPrinted':False}
ctx.proposal={'nativeFlywayConfiguration':{'configurationSha256':'a'*64,'nativeFlywayEnabledByDefault':True,'sameDatasourceAsApplication':True,
    'databaseMatches':True,'roleMatches':True,'higherPriorityMigrationOverridesAbsent':True,'ownerOverlays':[{'binding':binding,'metadata':overlay,'target':'/owner.yaml'}],
    'applicationJson':None,'externalUnreviewedConfigurationAbsent':True,'configurationValuesPrinted':False}}
ctx.database_profile={'identity':{'runtimeRole':'ouf_onboarding','database':'onboarding','schema':'ouf_onboarding','postgresPort':5432}}
actual=copy.deepcopy(ctx.native['currentOnboarding']);actual['State']['Pid']=2147483647
actual['Config'].update(Env=['OUF_ONB_DB_USER=ouf_onboarding','OUF_ONB_DB_PASSWORD=CI_SYNTHETIC_ONLY','OUF_ONB_DB_URL=jdbc:postgresql://ci-postgres:5432/onboarding','SPRING_CONFIG_ADDITIONAL_LOCATION=file:/owner.yaml'],Entrypoint=['java','-jar','/app/application.jar'],Cmd=None,WorkingDir='/app')
actual['Mounts']=[{'Type':'bind','Destination':'/owner.yaml','Source':str(owner),'RW':False}];ctx.native['currentOnboarding']=actual
postgres={'Name':'/ci-postgres','Config':{'Hostname':'ci-postgres'},'NetworkSettings':{'Networks':{}}}
ctx.classify_configuration(postgres);assert ctx.configuration_classified and ctx.proposal['nativeFlywayConfiguration']['configurationSha256']==case['application']['applicationYamlSha256']
ctx.owner_overlay_raw=raw;actual['Config']['Env'].append('SPRING_FLYWAY_ENABLED=false')
try:ctx.classify_configuration(postgres);raise AssertionError('migration override admitted')
except context.Stop as error:assert str(error)=='UNREVIEWED_SPRING_OVERRIDE_CHANNEL'
actual['Config']['Env'].pop();actual['Config']['Cmd']=['--spring.flyway.enabled=false']
try:ctx.classify_configuration(postgres);raise AssertionError('launch override admitted')
except context.Stop as error:assert str(error)=='UNREVIEWED_JAVA_ARGUMENT_OVERRIDE'
print(json.dumps({'status':'EXACT_CONTROL_APPLICATION_EXTRACTION_AND_CONFIGURATION_QUALIFIED','jarSha256':ctx.application_jar['sha256'],
    'applicationYamlSha256':case['application']['applicationYamlSha256'],'unreviewedMigrationChannelsRejected':True,
    'configurationFixtureNotTargetAdmission':True,'engineRequests':0,'sqlSessions':0,'oauthRequests':0,'runtimeAuthorityIssued':False,'applicationE2EProven':False},sort_keys=True))
