"""Pure unit proposal checks; native sandbox acceptance is deliberately separate."""
import copy,hashlib,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tools/semantic_lease_recovery'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from tools.m2_discovery_installation_profile import lease_unit as m


class Unit(unittest.TestCase):
    def fixture(self):
        install='/etc/ouf/discovery-lease';ledger='/var/lib/ouf-discovery-lease'
        python={'path':'/usr/bin/python3.12','sha256':'1'*64,'maximumBytes':67108864}
        nft={'path':'/usr/sbin/nft','sha256':'2'*64,'maximumBytes':67108864}
        openssl={'path':'/usr/bin/openssl','sha256':'3'*64,'version':'3.0.1'}
        profiles={r:{'nodeRecipeHash':'a'*64,'applicationHash':'b'*64,
            'imageConfigurationHash':'c'*64,'rootfsSealHash':'d'*64} for r in ('registry','provider')}
        peers={role:{'containerId':str(i)*64,'imageId':'sha256:'+str(i+2)*64,'dockerBindingHash':str(i+4)*64,
            'pid':100+i,'startedAt':'2026-10-29T12:00:00Z','startTicks':123+i,
            'namespace':{'path':'/run/docker/netns/ci-'+role,'identity':[1,100+i]},
            'allowedPausedStates':[False,True] if role=='registry' else [False]} for i,role in enumerate(('registry','provider'),1)}
        snapshot={'schema':'ouf.discovery-lease-generation-observation.v1','desiredProfileHash':'a'*64,
            'profiles':profiles,'nativeProfileHash':m.digest(profiles),'peers':peers,
            'bootId':'12345678-1234-1234-1234-123456789abc',
            'engineBinding':{'socketPath':'/run/docker.sock','socketBinding':[1,2,0,0,49600],
                'peerCredentials':[99,0,0],'startTicks':121}}
        snapshot['generationRef']=m.generation_reference(snapshot)
        recipe={'schema':'ouf.discovery-operational-lease-recipe.v1','kernel':{},'dns':{},'binding':{},'policy':{},
            'scope':{'generationRef':snapshot['generationRef']},'nft':nft,
            'coordinationJournal':ledger+'/coordination.json','leaseCommonLock':'/var/lib/ouf-kernel/common.lock'}
        refs=[python,nft,{k:v for k,v in openssl.items() if k!='version'}|{'maximumBytes':67108864},
            {'path':install+'/capsule.py','sha256':'4'*64,'maximumBytes':2097152},
            {'path':install+'/worker-recipe.json','sha256':m.digest(recipe),'maximumBytes':1048576}]
        c={'schema':'ouf.discovery-operational-lease-configuration.v1','installationInputsHash':'b'*64,
            'desiredProfileHash':snapshot['desiredProfileHash'],'sourceManifest':{'synthetic':True},'sources':copy.deepcopy(refs),
            'verification':{'openssl':openssl,'trustPolicy':{'path':'/etc/ouf/public-trust/policy.json','sha256':'5'*64},
                'context':{}},'serviceUnitPath':'/etc/systemd/system/ouf-discovery-lease.service',
            'serviceUnitHash':'0'*64,'commonInvocationLock':'/var/lib/ouf-fences/discovery.lock','commonLockIdentity':[1,2,0,0,33152,1],
            'generationReceiptPath':install+'/current-generation.json','hostBootIdPath':install+'/host-boot-id',
            'ledgerRoot':ledger,'scopePolicyHash':'6'*64}
        options={'installation_root':install,'signing_key_paths':['/etc/ouf/private-signing/native.key']}
        return c,recipe,snapshot,python,options

    def test_three_stat_files_no_complete_procfs_and_only_net_admin(self):
        c,r,s,p,o=self.fixture();proposal=m.compile_unit(c,r,s,p,**o);body=proposal['unitBody']
        self.assertEqual(proposal['processStatPaths'],['/proc/101/stat','/proc/102/stat','/proc/99/stat'])
        self.assertIn('MountAPIVFS=no\n',body);self.assertIn('CapabilityBoundingSet=CAP_NET_ADMIN\n',body)
        self.assertNotIn('ProtectControlGroups=',body);self.assertNotIn('ProtectProc=',body)
        self.assertNotIn('/proc/1/root',body);self.assertNotIn('/proc:/proc',body)
        for broad in ('/proc','/etc','/run','/usr','/root','/home','/sys'):
            self.assertNotIn(broad,proposal['readOnlyBindings'])
            self.assertNotIn(broad,proposal['readWriteBindings'])
        self.assertFalse(proposal['nativeSandboxProven']);self.assertFalse(proposal['targetApplyAuthorized'])

    def test_unit_hash_does_not_create_configuration_anchor_cycle(self):
        c,r,s,p,o=self.fixture();first=m.compile_unit(c,r,s,p,**o)
        c['serviceUnitHash']=first['unitSha256'];second=m.compile_unit(c,r,s,p,**o)
        self.assertEqual(first,second)
        self.assertEqual(first['unitSha256'],hashlib.sha256(first['unitBody'].encode()).hexdigest())

    def test_changed_generation_pid_or_namespace_is_not_silently_bound(self):
        for role,field,value in (('registry','pid',1234),('provider','namespace',{'path':'/run/docker/netns/replaced','identity':[1,3]})):
            c,r,s,p,o=self.fixture();s['peers'][role][field]=value
            with self.assertRaisesRegex(ValueError,'EXACT_ADMITTED'):m.compile_unit(c,r,s,p,**o)

    def test_private_keys_under_any_binding_or_ledger_are_denied(self):
        for key in ('/usr/lib/private.key','/var/lib/ouf-discovery-lease/private.key',
            '/etc/ouf/discovery-lease/receipt-signatures/private.key',
            '/etc/ouf/discovery-lease/observations/private.key','/usr/bin/python3.12'):
            c,r,s,p,o=self.fixture();o['signing_key_paths']=[key]
            with self.assertRaisesRegex(ValueError,'SIGNING_KEY_WOULD_BE_EXPOSED'):m.compile_unit(c,r,s,p,**o)

    def test_unbound_executable_recipe_or_unit_path_injection_is_denied(self):
        c,r,s,p,o=self.fixture();p['sha256']='f'*64
        with self.assertRaisesRegex(ValueError,'EXECUTABLE_BINDING'):m.compile_unit(c,r,s,p,**o)
        c,r,s,p,o=self.fixture();r['dns']={'unreviewed':True}
        with self.assertRaisesRegex(ValueError,'RECIPE_BINDING_CHANGED'):m.compile_unit(c,r,s,p,**o)
        c,r,s,p,o=self.fixture();c['serviceUnitPath']+='%n\nExecStart=/bin/sh'
        with self.assertRaisesRegex(ValueError,'BOUND_PATH'):m.compile_unit(c,r,s,p,**o)

if __name__=='__main__':unittest.main()
