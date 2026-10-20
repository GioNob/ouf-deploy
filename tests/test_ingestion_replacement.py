"""Adversarial replacement observations; no runtime authorization or effects."""
import copy
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
from tools.ingestion_rollout_execution import replacement as r
from tools.ingestion_rollout_execution.contract import Denied
from test_ingestion_rollout_execution import review_fixture

def observation(module='ingestion',phase='RUNNING'):
    _,packet,_=review_fixture();frame=packet['frames'][module];request=frame['requestTemplate']
    image=packet['candidate']['imageConfig'];cid='9'*64
    config={**copy.deepcopy(image),**{k:copy.deepcopy(v)for k,v in request.items()if k not in('HostConfig','NetworkingConfig')}}
    config['Env']=[k+'='+v for k,v in {**r.environment(image.get('Env')or[]),**r.environment(config['Env'])}.items()]
    if module=='gateway':config['Env']=[v if not v.startswith(r.OWNER_ENV+'=')else r.OWNER_ENV+'='+'a'*64 for v in config['Env']]
    if config.get('Hostname')=='':config['Hostname']=cid[:12]
    networks=copy.deepcopy(request['NetworkingConfig']['EndpointsConfig'])
    for endpoint in networks.values():
        endpoint.update(IPAddress=endpoint['IPAMConfig'].get('IPv4Address',''),
                        GlobalIPv6Address=endpoint['IPAMConfig'].get('IPv6Address',''))
        endpoint['Aliases'].append(cid[:12])
    actual={'Id':cid,'Name':'/'+frame['name'],'Image':request['Image'],'Config':config,
            'HostConfig':copy.deepcopy(request['HostConfig']),
            'Mounts':list(r._mounts(frame).values()),'NetworkSettings':{'Networks':networks},
            'RestartCount':0,'State':{'Status':'running','Running':True,'Paused':False,'Pid':123,
                                    'StartedAt':'2026-10-20T08:00:00Z'}}
    if phase=='CREATED':
        actual['State'].update(Status='created',Running=False,Pid=0,StartedAt='0001-01-01T00:00:00Z')
        for endpoint in networks.values():endpoint.update(IPAddress='',GlobalIPv6Address='',MacAddress='')
    kwargs={'created_id':cid,'phase':phase}
    if module=='gateway':kwargs['resolved_owner_key']='a'*64
    return frame,actual,image,packet['expectedRuntimeBindings'][module]['containerId'],kwargs

class ReplacementObservation(unittest.TestCase):
    def test_full_configuration_and_private_key_emit_only_resource_identity(self):
        for module in('ingestion','gateway'):
            args=observation(module);proof=r.validate(*args[:4],**args[4])
            self.assertEqual(set(proof),{'containerId','pid','startedAt'})
            self.assertNotIn('a'*64,str(proof));self.assertNotIn('ci-only-value',str(proof))

    def test_created_endpoints_unallocated_then_first_running_generation(self):
        for module in('ingestion','gateway'):
            args=observation(module,'CREATED');self.assertTrue(r.validate(*args[:4],**args[4])['neverStarted'])
            args[1]['State']['Status']='exited'
            with self.assertRaises(Denied):r.validate(*args[:4],**args[4])

    def test_api144_config_mac_echo_requires_the_exact_primary_endpoint(self):
        args=observation();frame,actual=args[:2]
        primary=next(iter(frame['requestTemplate']['NetworkingConfig']['EndpointsConfig']))
        frame['requestTemplate']['HostConfig']['NetworkMode']=primary
        actual['HostConfig']['NetworkMode']=primary
        actual['Config']['MacAddress']=frame['requestTemplate']['NetworkingConfig']['EndpointsConfig'][primary]['MacAddress']
        self.assertEqual(r.validate(*args[:4],**args[4])['pid'],123)
        actual['Config']['MacAddress']='02:42:00:00:00:99'
        with self.assertRaises(Denied):r.validate(*args[:4],**args[4])

    def test_network_identity_address_mac_alias_options_and_extra_network_block(self):
        for mutation in('network_id','ipv4','ipv6','mac','alias','duplicate_alias','ipam','driver','priority','extra_network'):
            args=observation();actual=args[1];networks=actual['NetworkSettings']['Networks'];ep=next(iter(networks.values()))
            if mutation=='network_id':ep['NetworkID']='0'*64
            if mutation=='ipv4':ep['IPAddress']='192.0.2.99'
            if mutation=='ipv6':ep['GlobalIPv6Address']='2001:db8::99'
            if mutation=='mac':ep['MacAddress']='02:42:00:00:00:99'
            if mutation=='alias':ep['Aliases'].append('unreviewed')
            if mutation=='duplicate_alias':ep['Aliases'].append(ep['Aliases'][0])
            if mutation=='ipam':ep['IPAMConfig']['IPv4Address']='192.0.2.99'
            if mutation=='driver':ep['DriverOpts']={'unreviewed':'option'}
            if mutation=='priority':ep['GwPriority']=17
            if mutation=='extra_network':networks['foreign']=copy.deepcopy(ep)
            with self.subTest(mutation=mutation),self.assertRaises(Denied):r.validate(*args[:4],**args[4])

    def test_process_restart_mount_secret_and_host_drift_block_without_secret_error(self):
        for mutation in('pid','started','restarted','paused','legacy_mac','mount','extra_mount','env','secret','oom','unknown_config','restart_policy'):
            args=observation('gateway');actual=args[1];args[4]['process']=r.generation(actual)
            if mutation=='pid':actual['State']['Pid']+=1
            if mutation=='started':actual['State']['StartedAt']='2026-10-20T08:01:00Z'
            if mutation=='restarted':actual['RestartCount']=1
            if mutation=='paused':actual['State']['Paused']=True
            if mutation=='legacy_mac':actual['Config']['MacAddress']='02:42:00:00:00:99'
            if mutation=='mount':actual['Mounts'][0]['RW']=True
            if mutation=='extra_mount':actual['Mounts'].append({'Type':'bind','Source':'/foreign','Destination':'/foreign','RW':True})
            if mutation=='env':actual['Config']['Env'].append('FOREIGN=secret-value')
            if mutation=='secret':args[4]['resolved_owner_key']='b'*64
            if mutation=='oom':actual['HostConfig']['OomKillDisable']=False
            if mutation=='unknown_config':actual['Config']['NewUnreviewedField']=True
            if mutation=='restart_policy':actual['HostConfig']['RestartPolicy']=args[0]['restoreRestartPolicy']
            with self.subTest(mutation=mutation),self.assertRaises(Denied)as error:r.validate(*args[:4],**args[4])
            self.assertNotIn('secret-value',str(error.exception));self.assertNotIn('b'*64,str(error.exception))

    def test_explicit_restart_restore_and_original_generation_required(self):
        args=observation();args[1]['HostConfig']['RestartPolicy']=args[0]['restoreRestartPolicy']
        args[4].update(restart_restored=True,process=r.generation(args[1]))
        self.assertEqual(r.validate(*args[:4],**args[4])['pid'],123)
        args[4]['created_id']='8'*64
        with self.assertRaises(Denied):r.validate(*args[:4],**args[4])

if __name__=='__main__':unittest.main()
