import ast
import copy
import hashlib
import importlib.util
from pathlib import Path
import subprocess
import unittest

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
PATH=ROOT/'scripts/reconcile-ingestion-frame-mac-20261020.py'
r=load('mac_reconcile',PATH);fixture=load('frame_fixture',ROOT/'tests/test_ingestion_rollout_packet.py').fixture

class LegacyMac(unittest.TestCase):
    def test_two_installation_profiles_keep_distinct_network_ip_and_mac_parameters(self):
        for label,network_id,ip,mac in [('fixture_A','a'*64,'192.0.2.27','02:00:00:00:01:27'),
                                         ('fixture_B','b'*64,'198.51.100.39','02:00:00:00:02:39')]:
            with self.subTest(profile=label):
                actual,draft,image=fixture();row=actual['NetworkSettings']['Networks'].pop('fixture_net')
                row.update(NetworkID=network_id,IPAddress=ip,GlobalIPv6Address='',MacAddress=mac)
                actual['NetworkSettings']['Networks']={label:row};actual['Config']['MacAddress']=mac
                result=r.frames.frame('ingestion',actual,actual['Image'],image,draft)
                observed=result['requestTemplate']['NetworkingConfig']['EndpointsConfig']
                self.assertEqual(set(observed),{label});self.assertEqual(observed[label]['NetworkID'],network_id)
                self.assertEqual(observed[label]['IPAMConfig']['IPv4Address'],ip);self.assertEqual(observed[label]['MacAddress'],mac)

    def test_legacy_mac_transfers_only_to_exact_observed_endpoint_on_both_modules(self):
        for name in ('ingestion','gateway'):
            with self.subTest(module=name):
                actual,draft,image=fixture();actual['Config']['MacAddress']='02:42:C0:00:02:08'
                extra=copy.deepcopy(actual['NetworkSettings']['Networks']['fixture_net'])
                extra.update(NetworkID='f'*64,IPAddress='198.51.100.8',GlobalIPv6Address='',MacAddress='02:42:c6:33:64:08')
                actual['NetworkSettings']['Networks']['second_net']=extra;before=copy.deepcopy(actual)
                result=r.frames.frame(name,actual,actual['Image'],image,draft)
                self.assertTrue(result['legacyContainerMacMovedToExplicitEndpoints'])
                self.assertIsNone(result['requestTemplate']['HostConfig']['OomKillDisable'])
                self.assertNotIn('MacAddress',result['requestTemplate']);self.assertEqual(actual,before)
                ep=result['requestTemplate']['NetworkingConfig']['EndpointsConfig']
                self.assertEqual(ep['fixture_net']['MacAddress'],'02:42:c0:00:02:08')
                self.assertEqual(ep['second_net']['MacAddress'],'02:42:c6:33:64:08')

    def test_unknown_or_malformed_legacy_mac_blocks_without_guessing(self):
        for value in ('02:42:00:00:00:01','bad',[],0,False):
            actual,draft,image=fixture();actual['Config']['MacAddress']=value
            with self.subTest(value=value),self.assertRaisesRegex(ValueError,'LEGACY_CONTAINER_MAC_MUST_MATCH_OBSERVED_ENDPOINT'):
                r.frames.frame('ingestion',actual,actual['Image'],image,draft)

    def test_new_entry_cannot_dispatch_completed_archive_audit_or_config_staging(self):
        tree=ast.parse(PATH.read_text());calls={ast.unparse(n.func)for n in ast.walk(tree)if isinstance(n,ast.Call)}
        self.assertFalse({'custody.archive','custody.tagless_archive','rootfs.rootfs_jar','package.jar_proof',
                          'stage_gateway_config','os.fchown','os.fchmod','subprocess.run','os.unlink','os.replace'}&calls)
        self.assertIn('EXACT_RETAINED_CONFIG_RECONCILIATION_CLAIM_REQUIRED',PATH.read_text())
        self.assertIn('EXACT_ALREADY_STAGED_CONFIG_BYTES_AND_METADATA_REQUIRED',PATH.read_text())
        main=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='main');source=ast.unparse(main)
        self.assertLess(source.index('complete ='),source.index('tempfile.mkdtemp'))
        self.assertIn('verified-inputs.json',source)

    def test_immutable_launcher_and_no_image_download(self):
        path=ROOT/'scripts/launch-ingestion-frame-mac-reconcile-20261020.sh';source=path.read_text();raw=PATH.read_bytes()
        self.assertIn(hashlib.sha256(raw).hexdigest(),source)
        self.assertIn(hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),source)
        self.assertNotIn('actions/artifacts',source);self.assertIn('trap ouf_report_log EXIT',source)
        subprocess.run(['bash','-n',str(path)],check=True)

if __name__=='__main__':unittest.main()
