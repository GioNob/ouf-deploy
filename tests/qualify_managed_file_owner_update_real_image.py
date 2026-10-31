"""Exact immutable control JAR and real native verifier, no application startup."""
import ast,copy,hashlib,importlib.util,json,os,pathlib,subprocess,types
ROOT=pathlib.Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
assert os.geteuid()==os.getegid()==0
subprocess.run(['/usr/bin/python3','-I','-S','-B',str(ROOT/'tests/qualify_managed_file_owner_image_plan.py')],check=True)
prepared=pathlib.Path('/var/lib/ouf-owner-image-plan-ci/plan')
native=json.loads((prepared/'execution-inputs.json').read_bytes())
custody=json.loads((ROOT/'releases/managed-file-owner-v38-image-custody-20261028.json').read_bytes())
p=load('retained_plan_helpers',ROOT/'tools/acquisition_read_native/plan_helper.py')
onb=load('retained_onb_context',ROOT/'tools/onboarding_profile_recovery_update/context.py')
base=load('retained_read_context',ROOT/'tools/acquisition_redaction_update/context.py')
control=load('retained_control_context',ROOT/'tools/managed_csv_control_update/context.py');control.Context=control.bind(base)
adapter=load('new_ths_context',ROOT/'tools/managed_file_owner_update/context.py');Context=adapter.bind(control)
ctx=Context.__new__(Context);ctx.core=types.SimpleNamespace(require=onb.require,digest=p.digest)
ctx.onb_context=onb;ctx.p=p;ctx.root=pathlib.Path('/var/lib/ouf-owner-v38-real-image');ctx.root.mkdir(mode=0o700)
ctx.native={'imageAudit':native['imageAudits']['onboarding'],'currentOnboarding':copy.deepcopy(native['currentCapture']['currentObservations']['onboarding'])}
ctx.archive=native['nativeArchives']['onboarding'];ctx.application_facts=custody['application'];ctx.application_jar=ctx.extract_application()
assert ctx.application_jar['sha256']==custody['application']['jarSha256']
raw=b'{"ouf":{"authorization":{"ths":{"enabled":true}}}}'
owner=ctx.root/'owner.yaml';ctx.write(ctx.root,owner.name,raw);_,binding=p.private_config(str(owner))
ctx.case={'ownerOverlayPath':str(owner)};ctx.owner_overlay_binding=binding;ctx.owner_overlay_raw=raw
ctx.configuration_raw=(ROOT/'tools/source_revision_update/configuration.py').read_bytes()
actual=ctx.native['currentOnboarding'];actual['State']['Pid']=2147483647
before={'spring.security.oauth2.client.registration.ouf-ths.scope':['openid','authorization.policy.admin','ouf.managed-source.file.upload','resolution.issue.read','resolution.match.approve'],
    'ouf.authorization.ths.enabled':True}
after=copy.deepcopy(before);after['spring.security.oauth2.client.registration.ouf-ths.scope']+=['ouf.managed-source.preview','ouf.managed-source.file.profile','ouf.onboarding.quarantine.release']
raw_before=json.dumps(before,indent=2) # raw and canonical hashes deliberately differ
raw_after=json.dumps(after,sort_keys=True,separators=(',',':'))
actual['Config'].update(Env=['OUF_ONB_DB_USER=ouf_onboarding','OUF_ONB_DB_PASSWORD=CI_SYNTHETIC_ONLY',
    'OUF_ONB_DB_URL=jdbc:postgresql://ci-postgres:5432/onboarding','SPRING_CONFIG_ADDITIONAL_LOCATION=file:/owner.yaml',
    'SPRING_APPLICATION_JSON='+raw_before],Entrypoint=['java','-jar','/app/application.jar'],Cmd=None,WorkingDir='/app')
actual['Mounts']=[{'Type':'bind','Destination':'/owner.yaml','Source':str(owner),'RW':False}]
projected=[*actual['Config']['Env'][:-1],'SPRING_APPLICATION_JSON='+raw_after]
actual['Config']['Env'][-1]='SPRING_APPLICATION_JSON='+raw_after
namespace={'hashlib':hashlib,'json':json,'re':__import__('re'),'require':onb.require}
node=next(n for n in ast.parse(ctx.configuration_raw).body if isinstance(n,ast.FunctionDef)and n.name=='application_json_metadata')
exec(compile(ast.Module(body=[node],type_ignores=[]),'<retained-native-metadata>','exec'),namespace)
metadata=namespace['application_json_metadata'](raw_after)
overlay={'format':'STRICT_JSON','ownerThsOAuthAndSessionOnly':True,'retainedSessionSecurityValidated':False,
    'migrationOverridePresent':False,'propertyCount':1,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'configurationValuesPrinted':False}
ctx.proposal={'onboardingReplacement':{'request':{'Env':projected}},'scopeRequestDelta':{
    'requestBeforeHash':p.digest(before),'conditionalRequestAfterHash':p.digest(after)},
    'nativeFlywayConfiguration':{'configurationSha256':custody['application']['applicationYamlSha256'],
        'nativeFlywayEnabledByDefault':True,'sameDatasourceAsApplication':True,'databaseMatches':True,'roleMatches':True,
        'higherPriorityMigrationOverridesAbsent':True,'ownerOverlays':[{'binding':binding,'metadata':overlay,'target':'/owner.yaml'}],
        'applicationJson':metadata,'externalUnreviewedConfigurationAbsent':True,'configurationValuesPrinted':False}}
ctx.database_profile={'identity':{'runtimeRole':'ouf_onboarding','database':'onboarding','schema':'ouf_onboarding','postgresPort':5432}}
postgres={'Name':'/ci-postgres','Config':{'Hostname':'ci-postgres'},'NetworkSettings':{'Networks':{}}}
original=copy.deepcopy(actual);ctx.classify_configuration(postgres)
assert actual==original and ctx.configuration_classified
assert ctx.proposal['nativeFlywayConfiguration']['applicationJson']['rawSha256']==p.digest(after)
ctx.owner_overlay_raw=raw;actual['Config']['Env'][-1]='SPRING_APPLICATION_JSON='+raw_before
try:ctx.classify_configuration(postgres);raise AssertionError('old incomplete scope request accepted')
except RuntimeError as e:assert str(e)=='RECOVERY_THS_REQUEST_SCOPE_CONTRACT_INCOMPLETE'
ctx.owner_overlay_raw=raw;actual['Config']['Env'][-1]='SPRING_APPLICATION_JSON='+raw_after;actual['Config']['Env'].append('SPRING_FLYWAY_ENABLED=false')
try:ctx.classify_configuration(postgres);raise AssertionError('migration override accepted')
except RuntimeError as e:assert str(e)=='UNREVIEWED_SPRING_OVERRIDE_CHANNEL'
print(json.dumps({'status':'EXACT_V38_JAR_UNCHANGED_THS_REQUEST_CONFIGURATION_PASS',
    'jarSha256':ctx.application_jar['sha256'],'applicationYamlSha256':custody['application']['applicationYamlSha256'],
    'actualNativeVerifier':True,'installedEightScopesRetained':True,'oldIncompleteRequestRejected':True,
    'completeInstalledRequestNotPatched':True,'originalOwnerNotRewritten':True,'migrationOverrideRejected':True,
    'engineRequests':0,'sqlSessions':0,'oauthRequests':0,'applicationStarted':False,'runtimeAuthorityIssued':False,
    'targetExecuted':False,'applicationE2EProven':False},sort_keys=True))
