"""Signed readiness persistence and exact numeric mounts; no target operations."""
import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from test_chatbot_cohort_gateway_runtime import GatewayRuntime as Fixture,KEY,r,g,preparation
from tools.chatbot_file_cohort.gateway_numeric_preparation import numeric_config


class NumericPreparation(unittest.TestCase):
    def test_numeric_assets_accept_null_absent_and_empty_binds_with_structured_mounts(self):
        fixture=Fixture();self.addCleanup(fixture.doCleanups)
        owner,native,f=fixture.fixture()
        base=owner.inspect(owner.plan['oldName']);base['Image']=r.NUMERIC_IMAGE
        source=owner.plan['oldConfigBinding']['path']
        base['HostConfig']['Mounts']=[{'Type':'bind','Source':source,
            'Target':'/usr/local/apisix/conf/config.yaml','ReadOnly':True}]
        assets=[]
        for destination,expected in sorted(r.NUMERIC_ASSETS.items()):
            path=Path(__file__).resolve().parents[1]/'tools/chatbot_file_cohort/assets/apisix'/Path(destination).name
            raw=path.read_bytes();self.assertEqual(hashlib.sha256(raw).hexdigest(),expected)
            staged=f.root/Path(destination).name;staged.write_bytes(raw);staged.chmod(0o444)
            _,binding=g.private_config(staged)
            assets.append({'destination':destination,'binding':binding,'readOnly':True})
        for representation in ('null','absent','empty','legacy'):
            old=copy.deepcopy(base)
            if representation=='null':old['HostConfig']['Binds']=None
            elif representation=='absent':old['HostConfig'].pop('Binds')
            elif representation=='empty':old['HostConfig']['Binds']=[]
            else:old['HostConfig'].pop('Mounts')
            before=copy.deepcopy(old)
            with self.subTest(representation=representation):
                plan=r.compile_runtime(old,owner.plan['oldConfigBinding'],owner.plan['newConfigBinding'],
                    'PROPOSAL_KEY',KEY,hashlib.sha256(KEY.encode()).hexdigest(),'fixture',numeric_assets=assets)
                host=plan['creationRequest']['HostConfig']
                self.assertEqual(host['Binds'][-2:],[a['binding']['path']+':'+a['destination']+':ro' for a in assets])
                self.assertEqual(len(plan['expectedMounts']),3)
                self.assertEqual(plan['oldHostConfig'],before['HostConfig'])
                self.assertEqual(plan['oldRuntimeBinding'],r.runtime_pin(before))
                self.assertEqual(old,before)
                if representation!='legacy':
                    self.assertEqual(host['Mounts'],[{**before['HostConfig']['Mounts'][0],
                        'Source':owner.plan['newConfigBinding']['path']}])

    def test_mount_binding_ignores_only_order_preserves_fields_and_rejects_duplicates(self):
        fixture=Fixture();self.addCleanup(fixture.doCleanups)
        owner,native,_=fixture.fixture()
        actual=owner.inspect(owner.plan['oldName'])
        mount=copy.deepcopy(actual['Mounts'][0]);mount['Destination']='/synthetic-extra'
        actual['Mounts'].append(mount)
        legacy=g.Engine.runtime_binding(actual)
        expected=g.apisix_runtime_binding(actual,g.MOUNT_SET_BINDING)
        changed=copy.deepcopy(actual);changed['Mounts'].reverse()
        self.assertEqual(g.apisix_runtime_binding(changed,g.MOUNT_SET_BINDING),expected)
        self.assertNotEqual(g.Engine.runtime_binding(changed),legacy)
        self.assertEqual(g.apisix_runtime_binding(actual),legacy)
        for field,value in [('RW',True),('Source','/other'),('Propagation','shared'),('Mode','rw'),('Type','volume')]:
            changed=copy.deepcopy(actual);changed['Mounts'][0][field]=value
            with self.subTest(field=field):self.assertNotEqual(g.apisix_runtime_binding(changed,g.MOUNT_SET_BINDING),expected)
        changed=copy.deepcopy(actual);changed['Mounts'].append(copy.deepcopy(changed['Mounts'][0]))
        with self.assertRaisesRegex(ValueError,'DUPLICATE'):g.apisix_runtime_binding(changed,g.MOUNT_SET_BINDING)
    def test_two_installations_preserve_every_existing_byte(self):
        import yaml
        for domain,peer,port in [('municipality-a.example','10.8.1.4',9443),('municipality-b.example','172.29.7.2',9180)]:
            raw=f'apisix:\n  node_listen: {port}\n  enable_ipv6: false\ndeployment:\n  etcd:\n    host:\n      - https://{domain}:2379\n  admin:\n    allow_admin:\n      - {peer}/32\n'.encode()
            result=numeric_config(raw);expected=yaml.safe_load(raw)
            expected['apisix'].update(extra_lua_path='/usr/local/apisix/conf/?.lua',lua_module_hook='ouf_json_precision')
            self.assertEqual(yaml.safe_load(result),expected)
            self.assertEqual(result.replace(b'  extra_lua_path: /usr/local/apisix/conf/?.lua\n  lua_module_hook: ouf_json_precision\n',b''),raw)
    def test_extensions_aliases_duplicate_sections_and_ambiguous_yaml_block(self):
        for raw in [b'apisix:\n  lua_module_hook: other\n',b'apisix:\n  extra_lua_path: other\n',
                    b'apisix:\n  x: &alias true\n',b'apisix:\n  x: true\napisix:\n',b'"apisix": {}\n']:
            with self.subTest(raw=raw),self.assertRaises(ValueError):numeric_config(raw)


class FiniteReadiness(unittest.TestCase):
    def fixture(self):
        fixture=Fixture();self.addCleanup(fixture.doCleanups)
        owner,native,f=fixture.fixture()
        expiry=json.loads(owner.action.raw)['expiresAt'];self.wall=expiry-3500;self.mono=10000.
        owner.clock=lambda:self.wall;owner.monotonic=lambda:self.mono
        self.calls=0;self.status=503;self.retry='';self.crash=False
        outer=self
        class Transport:
            retry_after=''
            def request(self,*args):
                outer.calls+=1;self.retry_after=outer.retry
                if outer.crash:raise OSError('simulated process interruption')
                return outer.status,{'total':0,'list':[]}
            def routes(self):return {}
        transport=Transport();owner.transport=lambda:transport
        return owner,native,f
    def advance_to(self,budget):
        delta=max(budget['nextAttemptAt']-self.wall,budget['nextAttemptMonotonic']-self.mono,0)
        self.wall+=delta;self.mono+=delta
    def test_jitter_retry_after_persists_without_repeating_lifecycle(self):
        owner,native,_=self.fixture();self.retry='120'
        with self.assertRaises(r.CohortPaused):owner.apply()
        first=owner.record()['readiness'];self.assertEqual(first['attempts'],1)
        self.assertEqual(first['nextAttemptAt']-self.wall,120)
        calls=copy.deepcopy(native.calls)
        with self.assertRaises(r.CohortPaused):owner.apply()
        self.assertEqual(self.calls,1);self.assertEqual(owner.record()['readiness'],first)
        self.advance_to(first);self.retry=''
        with self.assertRaises(r.CohortPaused):owner.apply()
        second=owner.record()['readiness'];self.assertEqual(second['attempts'],2)
        self.assertGreater(second['nextAttemptAt']-self.wall,15)
        self.assertLessEqual(second['nextAttemptAt']-self.wall,18)
        self.assertEqual(native.calls,calls)
        self.advance_to(second);self.status=200;owner.apply()
        self.assertEqual(owner.record()['readiness']['state'],'COMPLETE')
        self.assertEqual(len(native.calls),7)
    def test_retry_after_beyond_deadline_pauses_without_early_retry(self):
        owner,native,_=self.fixture();self.retry='7200'
        with self.assertRaisesRegex(ValueError,'RETRY_AFTER_EXCEEDS_BUDGET'):owner.apply()
        before=copy.deepcopy(native.calls)
        with self.assertRaisesRegex(ValueError,'TERMINAL_NO_REPLAY'):owner.apply()
        self.assertEqual(self.calls,1);self.assertEqual(native.calls,before)
        self.assertEqual(owner.record()['readiness']['state'],'PAUSED_EXHAUSTED')
    def test_hour_outage_exhaustion_keeps_one_generation_and_budget(self):
        owner,native,_=self.fixture()
        for _ in range(20):
            try:owner.apply()
            except r.CohortPaused:
                budget=owner.record()['readiness']
                self.advance_to(budget)
            except ValueError as error:
                self.assertIn('BUDGET_EXHAUSTED',str(error));break
        else:self.fail('finite deadline did not stop the outage')
        self.assertEqual(owner.record()['readiness']['state'],'PAUSED_EXHAUSTED')
        self.assertLess(self.calls,128);self.assertEqual(sum(c[0]=='start' for c in native.calls),1)
    def test_crash_unknown_http_and_revocation_never_retry(self):
        owner,native,f=self.fixture();self.crash=True
        with self.assertRaises(OSError):owner.apply()
        self.assertEqual(owner.record()['readiness']['state'],'ATTEMPTING')
        with self.assertRaisesRegex(ValueError,'IN_FLIGHT'):owner.apply()
        self.assertEqual(self.calls,1)
        owner,native,f=self.fixture();self.status=401
        with self.assertRaisesRegex(ValueError,'PERMANENT_FAILURE'):owner.apply()
        self.assertEqual(self.calls,1)
        owner,native,f=self.fixture()
        with self.assertRaises(r.CohortPaused):owner.apply()
        budget=owner.record()['readiness'];self.advance_to(budget)
        f.approval['state']='REVOKED';f.write(f.mandate,g.encoded(f.approval))
        with self.assertRaises(Exception):owner.apply()
        self.assertEqual(owner.record()['readiness'],budget);self.assertEqual(self.calls,1)
    def test_changed_generation_boot_and_clock_block(self):
        for change in ('generation','boot','clock'):
            owner,native,_=self.fixture()
            with self.assertRaises(r.CohortPaused):owner.apply()
            budget=owner.record()['readiness'];self.advance_to(budget)
            if change=='generation':native.find('ouf-apisix')['State']['Pid']+=1
            elif change=='boot':owner.boot='other-boot'
            else:self.mono=budget['lastMonotonic']-1
            with self.subTest(change=change),self.assertRaises(ValueError):owner.apply()
            self.assertEqual(self.calls,1)
    def test_http_date_and_invalid_retry_after(self):
        from email.utils import formatdate
        self.assertEqual(r.retry_after_seconds(formatdate(2000,usegmt=True),1900),100)
        for value in ('-1','NaN','tomorrow','1.5'):
            with self.assertRaises(ValueError):r.retry_after_seconds(value,1900)


if __name__=='__main__':unittest.main()
