"""Entry seams using actual constructors, private files and the existing Engine fixture.

The fixture observations are synthetic. No target grant, owner HTTP mutation,
installation-key issuance or native Docker effect is performed.
"""
import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

import test_chatbot_cohort_assemble as assembly
import test_chatbot_cohort_containers as containers
from tools.chatbot_file_cohort import entry,plan
from tools.chatbot_file_cohort import preparation


class EntryIntegration(unittest.TestCase):
    def setUp(self):
        self.fixture=assembly.CompleteActionAssembly()
        self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)

    def test_login_instruction_reaches_buffered_output_before_waiting_for_human(self):
        raw=io.BytesIO()
        output=io.TextIOWrapper(raw,encoding='utf-8',line_buffering=False)
        self.addCleanup(output.close)
        with contextlib.redirect_stdout(output):
            entry.emit_line('OPEN_IN_BROWSER=https://fixture.invalid/device')
        self.assertEqual(raw.getvalue(),b'OPEN_IN_BROWSER=https://fixture.invalid/device\n')

    def test_entry_compilation_owner_is_real_and_has_no_issuance_or_output_effect(self):
        f=self.fixture
        owner=entry.compilation_owner(f.prepared['owner'],f.sources,f.closure,f.stage,f.context,f.lineage)
        self.assertEqual(owner.scopes(),f.owner.scopes())
        self.assertEqual(owner.output.scope,f.owner.output.scope)
        with self.assertRaises(Exception):owner.guard()
        f.assert_no_runtime_effects()

    def test_entry_environment_delta_is_consumed_by_the_actual_four_module_compiler(self):
        observed={};images={};packages={}
        origin='https://gateway.fixture.invalid'
        for index,module in enumerate(plan.MODULES):
            old,image,package=containers.container_fixture(module)
            old['Id']=str(index+1)*64;old['Config']['Hostname']=old['Id'][:12]
            observed[module]=old;images[module]=image;packages[module]=package
        observed['ingestion']['Config']['Env'] += [
            'OUF_ING_IAM_ENABLED=true','OUF_INGESTION_ACTIVATION_ENABLED=true',
            'OUF_INGESTION_EXECUTION_ENABLED=true','OUF_INGESTION_ACTIVATION_GATEWAY_URL='+origin,
            'OUF_INGESTION_ACTIVATION_TENANT_ID=tenant-fixture',
            'OUF_INGESTION_ACTIVATION_TOKEN_FILE=/run/existing-tokens/service.jwt']
        issuer='https://issuer.fixture.invalid/realms/fixture'
        observed['ingestion']['Config']['Cmd'] += ['--ouf.ingestion.iam.issuer='+issuer,
            '--ouf.ingestion.iam.audience=ouf-api-gateway']
        observed['onboarding']['Config']['Env'] += [
            'OUF_ONBOARDING_UDP_IDENTITY_GATEWAY_URL='+origin]
        observed['onboarding']['Config']['Cmd'] += [
            '--ouf.onboarding.udp-identity.token-file=/run/existing-tokens/service.jwt']
        observed['udp']['Config']['Env'] += [
            'OUF_UDP_EXECUTION_GATEWAY_URL='+origin,
            'OUF_UDP_EXECUTION_TOKEN_FILE=/run/existing-tokens/service.jwt','OUF_UDP_TENANT_ID=tenant-fixture']
        for module in ('ingestion','onboarding','udp'):
            observed[module]['Mounts'].append({'Type':'bind','Source':'/private/existing-tokens',
                'Destination':'/run/existing-tokens','RW':False})
            observed[module]['HostConfig']['Mounts'].append({'Type':'bind','Source':'/private/existing-tokens',
                'Target':'/run/existing-tokens','ReadOnly':True})
        for module in ('semantic','gateway'):
            packages[module]={'module':module,'cohortSourceLockSha256':'f'*64}
        manifest={'schema':'ouf.chatbot-file-cohort-package.v1','cohortId':'fixture',
                  'sourceLockSha256':'f'*64,'modules':[dict(v,files={}) for v in packages.values()]}
        before=copy.deepcopy(observed)
        docker=containers.DockerFixture(self.fixture.f.root,observed,{'replacements':[]})
        self.addCleanup(docker.close)
        delta=entry.environment_deltas(docker.engine,origin,tenant='tenant-fixture',issuer=issuer,audience='ouf-api-gateway')
        result=plan.compile_cohort(manifest,observed,images,packages,delta,'1'*64,'2'*64,'3'*64)
        onboarding=next(row for row in result['replacements'] if row['module']=='onboarding')
        values=plan.environment(onboarding['creationRequest']['Env'])
        self.assertEqual(values['OUF_WORKFLOW_THS_GATEWAY_BASE_URL'],origin)
        self.assertEqual(values['PASSWORD'],'private-value')
        for module,properties in (
                ('onboarding',{'ouf.onboarding.udp-identity.token-file':'/run/existing-tokens/service.jwt'}),
                ('ingestion',{'ouf.ingestion.iam.issuer':issuer,'ouf.ingestion.iam.audience':'ouf-api-gateway'}),
                ('udp',{'ouf.udp.execution.token-file':'/run/existing-tokens/service.jwt',
                        'ouf.udp.lake.tenant-id':'tenant-fixture','ouf.udp.execution.enabled':'true'})):
            replacement=next(row for row in result['replacements'] if row['module']==module)
            prefix={'onboarding':'OUF_ONB','ingestion':'OUF_ING','udp':'OUF_UDP'}[module]
            _,_,read=entry.configuration({'Name':'/ouf-'+module,'Config':replacement['creationRequest']},prefix)
            for key,value in properties.items():self.assertEqual(read(key),value)
        self.assertEqual(observed,before);self.assertEqual(docker.calls,[])
        self.fixture.assert_no_runtime_effects()

    def test_parent_watch_keeps_observing_after_ready_until_actual_owner_acceptance(self):
        context=self.fixture.stage
        status={'phase':'COHORT_READY_FOR_ACTUAL_CHATBOT_CSV_ACCEPTANCE','chatbotEndToEndProven':False}
        accepted={'phase':'ACTUAL_CSV_OWNER_ACCEPTANCE_OBSERVED',
                  'ownerAcceptance':{'phase':'TWO_SOURCE_COMMIT_AND_REUSE_PROVEN',
                                     'freshChatbotSearchProven':False}}
        path=context/'delivery-status.json';path.write_text(json.dumps(status));path.chmod(0o600)
        with patch('subprocess.run',return_value=subprocess.CompletedProcess([],0,b'active\n')) as alive,\
                patch.object(entry.time,'sleep',side_effect=lambda _:path.write_text(json.dumps(accepted))) as pause,\
                contextlib.redirect_stdout(io.StringIO()) as output:
            entry.watch_child({'context':str(context),'unit':'explicit-fixture.service'},{'path':'/unused'})
        self.assertEqual([json.loads(row) for row in output.getvalue().splitlines()],[status,accepted])
        alive.assert_called_once();pause.assert_called_once_with(2)

    def test_external_ingestion_properties_are_retained_without_new_environment_override(self):
        observed={}
        for index,module in enumerate(plan.MODULES):
            old,_,_=containers.container_fixture(module)
            old['Id']=str(index+1)*64
            observed[module]=old
        origin='https://gateway.fixture.invalid'
        selected=observed['ingestion']
        selected['Config']['Env'] += [
            'SPRING_CONFIG_ADDITIONAL_LOCATION=optional:file:'+preparation.INGESTION_CONFIG_TARGET]
        source='/etc/ouf/deploy-snapshots/review/ingestion-summary.properties'
        selected['Mounts'] += [
            {'Type':'bind','Source':source,'Destination':preparation.INGESTION_CONFIG_TARGET,'RW':False},
            {'Type':'bind','Source':'/private/existing-tokens','Destination':'/run/existing-tokens','RW':False}]
        raw=('ouf.ingestion.iam.enabled=true\n'
             'ouf.ingestion.iam.issuer=https://issuer.fixture.invalid/realms/fixture\n'
             'ouf.ingestion.iam.audience=ouf-api-gateway\n'
             'ouf.ingestion.activation.enabled=true\n'
             'ouf.ingestion.execution.enabled=true\n'
             'ouf.ingestion.activation.gateway-url='+origin+'\n'
             'ouf.ingestion.activation.token-file=/run/existing-tokens/service.jwt\n'
             'ouf.ingestion.activation.tenant-id=tenant-fixture\n').encode()
        binding={'path':source,'sha256':hashlib.sha256(raw).hexdigest(),'metadata':[1,2,3]}
        # The other two applications have already selected their retained
        # gateway and token channels; only Ingestion is the new external case.
        for name,fields in (('onboarding',[
                'OUF_ONBOARDING_UDP_IDENTITY_GATEWAY_URL='+origin,
                'OUF_ONBOARDING_UDP_IDENTITY_TOKEN_FILE=/run/existing-tokens/service.jwt']),
                ('udp',['OUF_UDP_EXECUTION_GATEWAY_URL='+origin,
                'OUF_UDP_EXECUTION_TOKEN_FILE=/run/existing-tokens/service.jwt',
                'OUF_UDP_TENANT_ID=tenant-fixture'])):
            observed[name]['Config']['Env'] += fields
            observed[name]['Mounts'].append({'Type':'bind','Source':'/private/existing-tokens',
                'Destination':'/run/existing-tokens','RW':False})
        docker=containers.DockerFixture(self.fixture.f.root,observed,{'replacements':[]})
        self.addCleanup(docker.close)
        with patch.object(preparation,'private_config',return_value=(raw,binding)):
            result=entry.environment_deltas(docker.engine,origin,tenant='tenant-fixture',
                issuer='https://issuer.fixture.invalid/realms/fixture',audience='ouf-api-gateway',
                ingestion_binding=binding)
        self.assertEqual(result['ingestion'],{})
        self.assertNotIn('SPRING_APPLICATION_JSON',str(selected['Config']['Env']))

    def test_actual_preparation_capsule_imports_isolated_and_rejects_source_drift(self):
        stage=self.fixture.stage;source=stage/'source';source.mkdir(mode=0o700)
        paths=json.loads((assembly.ROOT/'tools/chatbot_file_cohort/preparation_sources.json').read_bytes())['files']
        hashes={}
        for relative in paths:
            original=assembly.ROOT/relative;target=source/relative
            target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            # mkdir(parents=True) follows the current umask for ancestors.
            for directory in (target.parent,*target.parent.parents):
                if directory==source or source in directory.parents:directory.chmod(0o700)
            raw=original.read_bytes();target.write_bytes(raw);target.chmod(0o600)
            hashes[relative]=hashlib.sha256(raw).hexdigest()
        manifest={'schema':'ouf.chatbot-file-preparation-capsule.v1','files':hashes}
        raw=plan.encoded(manifest);manifest_path=stage/'preparation-manifest.json'
        manifest_path.write_bytes(raw);manifest_path.chmod(0o600)
        expected=hashlib.sha256(raw).hexdigest()
        self.assertEqual(entry.verify_preparation_capsule(source,stage,expected),manifest)
        result=subprocess.run([sys.executable,'-I','-B','-S',str(source/'scripts/install-chatbot-file-cohort.py'),
            '--source-directory',str(source),'--help'],capture_output=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr.decode())
        self.assertIn(b'--preparation-source-hash',result.stdout)
        target=source/'tools/chatbot_file_cohort/entry.py';target.write_bytes(target.read_bytes()+b'\n# drift\n')
        with self.assertRaisesRegex(plan.PlanDenied,'PREPARATION_SOURCE_CHANGED'):
            entry.verify_preparation_capsule(source,stage,expected)

    def test_parent_errors_never_report_unissued_after_a_possible_or_completed_issuance(self):
        argv=['entry','--source-directory','/fixture/source','--package-archive','/fixture/archive',
              '--staging-directory','/fixture','--source-commit','a'*40,'--preparation-source-hash','b'*64]
        for state in (None,True):
            for failure,code in ((KeyboardInterrupt(),130),(ValueError('START_OUTCOME_UNPROVEN'),1)):
                with self.subTest(state=state,failure=type(failure).__name__):
                    def interrupted(args):
                        args.authority_issued=state
                        raise failure
                    with patch.object(sys,'argv',argv),patch.object(entry,'collect',side_effect=interrupted),\
                            contextlib.redirect_stdout(io.StringIO()) as output:
                        with self.assertRaises(SystemExit) as stopped:entry.main()
                    self.assertEqual(stopped.exception.code,code)
                    receipt=json.loads(output.getvalue())
                    self.assertIs(receipt['runtimeAuthorityIssued'],state)
                    self.assertFalse(receipt['chatbotEndToEndProven'])


if __name__=='__main__':unittest.main()
