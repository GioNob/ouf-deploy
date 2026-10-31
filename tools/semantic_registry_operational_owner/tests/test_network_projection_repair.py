"""Exact kernel framing and authority-neutral input checks for the host repair."""
import copy
import importlib.util
import json
import os
import socket
import struct
import stat
import tempfile
import threading
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('network_projection_repair',ROOT/'scripts/repair-registry-network-projection-20261024.py')
repair=importlib.util.module_from_spec(spec);spec.loader.exec_module(repair)


class Inputs(unittest.TestCase):
    def test_kernel_tuple_wire_roundtrip_ipv4_and_ipv6(self):
        for family,source,destination in((socket.AF_INET,'192.0.2.2','198.51.100.10'),(socket.AF_INET6,'2001:db8::1','2001:db8::2')):
            raw=repair.tuple_bytes(family,source,31000,destination,443)
            self.assertEqual(repair.decode_tuple(family,raw),{'source':source,'sourcePort':31000,
                'destination':destination,'destinationPort':443,'protocol':6})

    def test_kernel_attribute_duplicates_and_truncation_refused(self):
        raw=repair.nla(1,b'fixture')
        with self.assertRaises(repair.Denied):repair.attrs(raw+raw)
        with self.assertRaises(repair.Denied):repair.attrs(raw[:-1])
        with self.assertRaises(repair.Denied):repair.attrs(struct.pack('=HH',2,1))

    def test_only_exact_running_endpoint_owner_selected(self):
        row={'Id':'a'*64,'State':'running','NetworkSettings':{'Networks':{'fixture':{'IPAddress':'172.18.0.2'}}}}
        self.assertEqual(repair.endpoint_owner([row],'172.18.0.2'),'a'*64)
        with self.assertRaises(repair.Denied):repair.endpoint_owner([dict(row,State='exited')],'172.18.0.2')
        with self.assertRaises(repair.Denied):repair.endpoint_owner([row,dict(row,Id='b'*64)],'172.18.0.2')
        with self.assertRaises(repair.Denied):repair.endpoint_owner([row]*513,'172.18.0.2')

    def test_current_published_origin_and_target_port_required(self):
        row={'NetworkSettings':{'Networks':{'fixture':{'IPAddress':'172.18.0.2','IPAMConfig':{'IPv4Address':'172.18.0.2'}}},
            'Ports':{'8443/tcp':[{'HostIp':'0.0.0.0','HostPort':'443'}]}}}
        candidate={'address':'172.18.0.2','port':8443}
        self.assertTrue(repair.publication_matches(row,candidate,'198.51.100.10',443))
        wrong=copy.deepcopy(row);wrong['NetworkSettings']['Ports']['8443/tcp'][0]['HostPort']='444'
        with self.assertRaises(repair.Denied):repair.publication_matches(wrong,candidate,'198.51.100.10',443)
        wrong=copy.deepcopy(row);wrong['NetworkSettings']['Ports']['8443/tcp'][0]['HostIp']='198.51.100.11'
        with self.assertRaises(repair.Denied):repair.publication_matches(wrong,candidate,'198.51.100.10',443)

    def test_endpoint_pin_detects_every_configuration_or_generation_change(self):
        row={'Id':'a'*64,'Image':'sha256:'+'b'*64,'State':{'Pid':100,'StartedAt':'fixture-start',
            'Running':True,'Paused':False,'Restarting':False,'Dead':False},'RestartCount':0,
            'Config':{},'HostConfig':{},'Mounts':[],'NetworkSettings':{}}
        pin=repair.runtime_pin(row)
        changed=copy.deepcopy(row);changed['State']['Pid']=101
        self.assertNotEqual(repair.runtime_pin(changed),pin)
        changed=copy.deepcopy(row);changed['NetworkSettings']['new']='fixture'
        self.assertNotEqual(repair.runtime_pin(changed),pin)
        changed=copy.deepcopy(row);changed['State']['Running']=False
        with self.assertRaises(repair.Denied):repair.runtime_pin(changed)

    def test_unknown_authority_type_cannot_reach_a_manager_effect(self):
        with self.assertRaises(repair.Denied):repair.apply_projection({},object(),None,None,None,None)
        self.assertEqual(repair.COUNTS['managerMutationAttempts'],0)

    def test_actual_unix_inspection_cannot_substitute_selected_container(self):
        with tempfile.TemporaryDirectory(dir=ROOT)as directory:
            path=Path(directory)/'engine.sock';listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            listener.bind(str(path));path.chmod(0o600);listener.listen(1);listener.settimeout(5)
            info=path.stat();binding={'socketPath':str(path),'socketBinding':[info.st_dev,info.st_ino,info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode)]}
            calls=[]
            def serve():
                try:
                    conn,_=listener.accept()
                    with conn:
                        calls.append(conn.recv(4096).split(b'\r\n')[0]);body=json.dumps({'Id':'b'*64}).encode()
                        conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(body)).encode()+b'\r\nConnection: close\r\n\r\n'+body)
                finally:listener.close()
            thread=threading.Thread(target=serve);thread.start();repair.COUNTS['engineGetAttempts']=0
            try:
                with self.assertRaisesRegex(repair.Denied,'EXACT_SELECTED_NAT_PROVIDER_ID_REQUIRED'):
                    repair.engine_get(binding,'/v1.44/containers/'+'a'*64+'/json')
            finally:thread.join(6)
            self.assertFalse(thread.is_alive());self.assertEqual(len(calls),1)
            self.assertEqual(repair.COUNTS['engineGetAttempts'],1);self.assertEqual(repair.COUNTS['managerMutationAttempts'],0)


if __name__=='__main__':unittest.main()
