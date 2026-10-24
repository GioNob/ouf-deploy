"""Read-only policy/NAT classification; private address data never projected."""
import copy
import importlib.util
import json
import os
import socket
import stat
import tempfile
import threading
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('network_policy_capture',ROOT/'scripts/capture-registry-network-policy-20261024.py')
capture=importlib.util.module_from_spec(spec);spec.loader.exec_module(capture)

class Policy(unittest.TestCase):
    def test_policy_allow_precedence_and_unknown_format(self):
        policy={'IPAddressAllow':'198.51.100.10/32','IPAddressDeny':'0.0.0.0/0 ::/0'}
        self.assertTrue(capture.permitted('198.51.100.10',policy))
        self.assertFalse(capture.permitted('172.18.0.7',policy))
        self.assertIsNone(capture.permitted('198.51.100.10',{'IPAddressAllow':'unparsed format','IPAddressDeny':''}))

    def test_iptables_local_nat_candidate_retains_unknown_path_and_constraints(self):
        raw=b'*nat\n-A OUTPUT -m addrtype --dst-type LOCAL -j DOCKER\n-A DOCKER ! -i br-fixture -p tcp -m tcp --dport 443 -j DNAT --to-destination 172.18.0.7:9443\nCOMMIT\n'
        rows,unknown=capture.parse_save(raw,'198.51.100.10',443)
        self.assertEqual(unknown,0);self.assertEqual(len(rows),1)
        self.assertEqual((rows[0]['address'],rows[0]['port']),('172.18.0.7',9443))
        self.assertTrue(rows[0]['otherMatchConstraintsPresent']);self.assertFalse(rows[0]['chainTraversalProven'])

    def test_destination_and_port_mismatch_do_not_select_other_exposure(self):
        raw=b'*nat\n-A DOCKER -d 198.51.100.11/32 -p tcp --dport 443 -j DNAT --to-destination 172.18.0.7:9443\n-A DOCKER -p tcp --dport 8443 -j DNAT --to-destination 172.18.0.8:8443\nCOMMIT\n'
        self.assertEqual(capture.parse_save(raw,'198.51.100.10',443),([],0))

    def test_dynamic_nft_target_is_explicitly_unclassified(self):
        data={'nftables':[{'rule':{'family':'ip','chain':'DOCKER','expr':[
            {'match':{'left':{'payload':{'protocol':'tcp','field':'dport'}},'op':'==','right':443}},
            {'dnat':{'addr':{'map':'dynamic'}}}]}}]}
        rows,count=capture.parse_nft(json.dumps(data).encode(),'198.51.100.10',443)
        self.assertEqual(rows,[]);self.assertEqual(count,1)

    def test_nft_literal_projection_and_current_gateway_publication_binding(self):
        data={'nftables':[{'rule':{'family':'ip','chain':'DOCKER','expr':[
            {'match':{'left':{'payload':{'protocol':'tcp','field':'dport'}},'op':'==','right':443}},
            {'dnat':{'addr':'172.18.0.7','port':9443}}]}}]}
        rows,count=capture.parse_nft(json.dumps(data).encode(),'198.51.100.10',443)
        self.assertEqual(count,0)
        gateway={'NetworkSettings':{'Networks':{'fixture':{'IPAddress':'172.18.0.7','IPAMConfig':{'IPv4Address':'172.18.0.7'}}},
            'Ports':{'9443/tcp':[{'HostIp':'0.0.0.0','HostPort':'443'}]}}}
        projected=capture.classify_candidates(rows,gateway,'198.51.100.10',443,
            {'IPAddressAllow':'198.51.100.10/32','IPAddressDeny':'0.0.0.0/0'})
        self.assertTrue(projected[0]['matchesReviewedGatewayEndpoint'] and projected[0]['matchesReviewedPublishedPort'])
        self.assertTrue(projected[0]['gatewayAddressExplicitlyAssigned']);self.assertFalse(projected[0]['permittedByUnitIpPolicy'])
        self.assertFalse(projected[0]['chainTraversalProven'])

    def test_no_static_assignment_or_other_published_port_is_not_adopted(self):
        rows=[{'address':'172.18.0.7','port':9443}]
        gateway={'NetworkSettings':{'Networks':{'fixture':{'IPAddress':'172.18.0.7','IPAMConfig':None}},
            'Ports':{'9443/tcp':[{'HostIp':'198.51.100.11','HostPort':'443'}]}}}
        projected=capture.classify_candidates(rows,gateway,'198.51.100.10',443,{'IPAddressAllow':'','IPAddressDeny':''})
        self.assertFalse(projected[0]['gatewayAddressExplicitlyAssigned']);self.assertFalse(projected[0]['matchesReviewedPublishedPort'])

    def test_ipv6_dnat_and_body_bound(self):
        self.assertEqual(capture.dnat_target('[2001:db8::2]:9443',443),('2001:db8::2',9443))
        with self.assertRaises(ValueError):capture.dnat_target('172.18.0.1:99999',443)
        with self.assertRaises(ValueError):capture.parse_save(b'x'*16777217,'198.51.100.10',443)


    def test_actual_bounded_unix_get_only_and_consumed_ceiling(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            path=Path(directory)/'engine.sock';listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            listener.bind(str(path));path.chmod(0o600);listener.listen(2);listener.settimeout(5)
            info=path.stat();binding={'socketPath':str(path),'socketBinding':[info.st_dev,info.st_ino,info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode)]}
            calls=[];cid='a'*64
            def serve():
                try:
                    for _ in range(2):
                        conn,_=listener.accept()
                        with conn:
                            raw=conn.recv(4096);calls.append(raw.split(b'\r\n')[0])
                            body=json.dumps({'Id':cid}).encode()
                            conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(body)).encode()+b'\r\nConnection: close\r\n\r\n'+body)
                finally:listener.close()
            thread=threading.Thread(target=serve);thread.start();capture.COUNTS['engineGetAttempts']=0
            try:
                for _ in range(2):self.assertEqual(capture.engine_get(binding,cid),{'Id':cid})
                with self.assertRaises(ValueError):capture.engine_get(binding,cid)
            finally:thread.join(6)
            self.assertFalse(thread.is_alive());self.assertEqual(calls,[b'GET /v1.44/containers/'+cid.encode()+b'/json HTTP/1.1']*2)

    def test_current_gateway_binding_detects_replacement_and_network_drift(self):
        row={'Id':'a'*64,'Image':'sha256:'+'b'*64,'State':{'Pid':123,'StartedAt':'fixture-start',
            'Running':True,'Paused':False,'Restarting':False,'Dead':False},
            'Config':{'fixture':True},'HostConfig':{},'Mounts':[],'NetworkSettings':{'Networks':{}},'RestartCount':0}
        binding={'containerId':row['Id'],'imageId':row['Image'],'pid':123,'startedAt':'fixture-start',
            'configHash':capture.digest(capture.encoded(row['Config'])),'hostConfigHash':capture.digest(capture.encoded({})),
            'mountsHash':capture.digest(capture.encoded([])),'networkSettingsHash':capture.digest(capture.encoded(row['NetworkSettings']))}
        pin={'bindingProfile':'ouf.runtime-binding.mounts-sorted-destination.v1','binding':binding,'restartCount':0}
        self.assertEqual(capture.gateway_matches(row,pin),binding)
        bad=copy.deepcopy(row);bad['NetworkSettings']['Networks']['changed']={}
        with self.assertRaises(ValueError):capture.gateway_matches(bad,pin)
        bad=copy.deepcopy(row);bad['State']['Pid']=124
        with self.assertRaises(ValueError):capture.gateway_matches(bad,pin)


if __name__=='__main__':unittest.main()
