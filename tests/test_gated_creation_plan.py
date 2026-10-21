"""Pure new-intent boundary: preserve signed image/request remainder, no adoption."""
import copy,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools/semantic_application_cutover'))
from gated_creation_plan import compile_gate,ENTRY
from transition_journal import digest

class GatePlan(unittest.TestCase):
    def fixture(self):
        entry=['java','-XX:MaxRAMPercentage=75','-jar','/app/application.jar']
        image={'config':{'Entrypoint':entry,'Cmd':None,'User':'10001:10001','Env':['PATH=/opt/java/openjdk/bin:/usr/bin:/bin']}}
        request={'Image':'sha256:'+'a'*64,'User':'10001:10001','Env':['FIXTURE_ONLY=1'],'HostConfig':{'Runtime':'runc','Privileged':False,'CapAdd':None,'RestartPolicy':{'Name':'no','MaximumRetryCount':0},'Binds':['/fixture/input:/fixture/input:ro'],'Memory':2147483648,'NetworkMode':'fixture-bridge'},'NetworkingConfig':{'EndpointsConfig':{'fixture-bridge':{'IPAMConfig':{'IPv4Address':'10.233.0.13'}}}}}
        return request,image
    def test_compiles_distinct_intent_with_exact_image_source_mounts_network_and_resource_bytes(self):
        request,image=self.fixture();before=copy.deepcopy(request);following,receipt=compile_gate(request,digest(request),image)
        self.assertEqual(request,before);self.assertEqual(following['Entrypoint'],ENTRY);self.assertEqual(following['Cmd'],image['config']['Entrypoint'])
        for k in request:
            if k!='HostConfig':self.assertEqual(following[k],request[k])
        for k in request['HostConfig']:self.assertEqual(following['HostConfig'][k],request['HostConfig'][k])
        self.assertNotEqual(receipt['creationRequestHash'],receipt['parentCreationRequestHash']);self.assertFalse(receipt['productionApplyReady']);self.assertFalse(receipt['imageRebuilt'])
    def test_changed_image_entry_parent_hash_or_privileged_scope_cannot_inherit_old_approval(self):
        for drift in ('entry','hash','user','privileged','capability','unconfined','host','argv'):
            request,image=self.fixture();expected=digest(request)
            if drift=='entry':image['config']['Entrypoint']=['other']
            if drift=='hash':expected='b'*64
            if drift=='user':request['User']='0:0'
            if drift=='privileged':request['HostConfig']['Privileged']=True
            if drift=='capability':request['HostConfig']['CapAdd']=['SYS_ADMIN']
            if drift=='unconfined':request['HostConfig']['SecurityOpt']=['seccomp=unconfined']
            if drift=='host':request['HostConfig']['PidMode']='host'
            if drift=='argv':request['Cmd']=['unexpected']
            if drift!='hash':expected=digest(request)
            with self.assertRaises(ValueError):compile_gate(request,expected,image)
    def test_existing_reviewed_security_options_are_preserved_but_false_nnp_is_denied(self):
        request,image=self.fixture();request['HostConfig']['SecurityOpt']=['apparmor=docker-default','no-new-privileges:true']
        following,_=compile_gate(request,digest(request),image);self.assertEqual(following['HostConfig']['SecurityOpt'],request['HostConfig']['SecurityOpt'])
        request['HostConfig']['SecurityOpt']=['no-new-privileges:false']
        with self.assertRaises(ValueError):compile_gate(request,digest(request),image)

if __name__=='__main__':unittest.main()
