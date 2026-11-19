"""Actual Engine creates under a real gate; fixture runtime alias never started.

This qualifies creation ownership/reconciliation, not v4 admission or the
synthetic image's independent rootfs seal. No target image/profile is used.
"""
import copy,hashlib,ipaddress
from pathlib import Path
from test_m2_provider_installation_template import inputs
from tools.m2_discovery_installation_profile import provider_creation as m

def qualify(auth,window,engine,image,network,network_id,ids,cli):
    network_info=__import__('json').loads(cli('network','inspect',network))[0]
    subnet=ipaddress.ip_network(network_info['IPAM']['Config'][0]['Subnet'])
    registry_ip=next(iter(network_info['Containers'].values()))['IPv4Address'].split('/')[0]
    own_ip=str(subnet.network_address+17)
    assert own_ip!=registry_ip and own_ip!=network_info['IPAM']['Config'][0]['Gateway']
    own_mac='02:00:00:77:01:17';completed=[]
    for label,lose_reply in [('provider-create',False),('provider-create-lost-reply',True)]:
        options=inputs();root=auth.root/label;root.mkdir(mode=0o700)
        source=auth.root/(label+'-source');source.write_bytes(b'SYNTHETIC_PROVIDER_CONFIGURATION');source.chmod(0o600)
        uid=options['launch']['startup']['uid'];gid=options['launch']['startup']['gid']
        __import__('os').chown(source,uid,gid)
        old=options['launch']['sources'][0]['source'];target=options['launch']['sources'][0]['target']
        options['launch']['sources'][0].update(source=str(source),sha256=hashlib.sha256(source.read_bytes()).hexdigest())
        options['launch']['manifest']['mounts'][0]['source']=str(source)
        for mount in options['frame_template']['expectedOci']['mounts']:
            if mount['destination']==target:assert mount['source']==old;mount['source']=str(source)
        request=options['request'];request['Image']=image;request['Entrypoint']=['sleep'];request['Cmd']=['600']
        request['HostConfig']['Mounts'][0]['Source']=str(source)
        request['HostConfig']['NetworkMode']=network
        request['NetworkingConfig']={'EndpointsConfig':{network:{'NetworkID':network_id,'MacAddress':own_mac,'IPAMConfig':{'IPv4Address':own_ip}}}}
        options['network_bindings'][0].update(mac=own_mac,ipv4=own_ip,bridge='br-'+network_id[:12])
        options['transport_template'][0].update(source=own_ip,destination=registry_ip)
        peer=options['transport_template'][0]['peerIngress']['declaration']['networkBindings'][0]
        peer.update(ipv4=registry_ip,bridge='br-'+network_id[:12])
        runtime=Path('/opt/ouf-docker-29/runc');options['runtime_binding']={'path':str(runtime),'sha256':hashlib.sha256(runtime.read_bytes()).hexdigest()}
        template=m.templates.template(**options);w=window(label)
        auth.review['components']['providerInstallation']=m.creation_scope(template,w.scope,root)
        w.parent=auth.fixture();w.parent_hash=w.parent.sha
        owner=m.ProviderCreation(parent=w.parent,window=w,template=template,journal_directory=root)
        native=engine.request;dispatches=[]
        def create_request(method,path,body=None):
            result=native(method,path,body)
            if method=='POST' and '/containers/create?' in path:
                dispatches.append(path)
                if result[0]==201:ids.append(result[1]['Id'])
                if lose_reply:raise TimeoutError('CI_LOST_PROVIDER_CREATE_REPLY')
            return result
        engine.request=create_request
        try:
            try:
                with w.peer_window():
                    owner.create_once();assert not lose_reply
                    assert owner.observe()[0]=='APPLIED'
            except TimeoutError as error:assert lose_reply and str(error)=='CI_LOST_PROVIDER_CREATE_REPLY'
        finally:engine.request=native
        assert w.observe_closed()['state']=='CLOSED'
        outcome,proof=owner.observe();assert outcome=='APPLIED' and proof['providerStarted'] is False
        cid=owner.owned_id();assert cid in ids and cid!=w.retained()['runtimeBinding']['containerId']
        status,actual=engine.request('GET','/v1.44/containers/'+cid+'/json')
        assert status==200 and actual['State']['Status']=='created' and actual['State']['Running'] is False and actual['State']['Pid']==0
        before=list(dispatches)
        try:owner.create_once();raise AssertionError('CLOSED_GATE_OR_CREATE_CLAIM_REPLAYED')
        except ValueError:pass
        assert dispatches==before and len(dispatches)==1
        # This is disposable CI cleanup, after the receipt is checked. Target
        # controller has no removal method; no target recovery is modeled.
        cli('rm',cid);ids.remove(cid)
        completed.append({'oneCreate':True,'lostReplyReconciledAfterGateClosure':lose_reply,
            'providerNeverStarted':True,'creationIsNotAdmission':True})
    return completed
