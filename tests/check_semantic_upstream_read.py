#!/usr/bin/env python3
import ast
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import patch

path = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location('reader', path)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
ast.parse(m.ADMIN_CHILD)
ast.parse(m.DNS_CHILD)
secret = 'TEST_ONLY_SECRET_123456789'
config = ('deployment:\n  admin:\n    admin_key:\n      - name: test\n        key: "'+secret+'"\n        role: admin\n').encode()
assert m.selected_key(config) == secret
with patch.object(m, 'read', return_value=secret.encode()):
    assert m.selected_key(b'deployment:\n  admin:\n    admin_key:\n') == secret
try:
    m.selected_key(config.replace(b'role: admin', b'role: viewer'))
    raise AssertionError('missing admin accepted')
except RuntimeError:
    pass
fake = SimpleNamespace(returncode=0, stdout=('connection refused Authorization: Bearer '+secret).encode(), stderr=b'')
with patch.object(m.subprocess, 'run', return_value=fake):
    logs = m.log_summary('a'*64)
    assert logs['hints'] == {'connectionRefused': 1}
    assert secret not in json.dumps(logs)
route = {'uri':m.ROUTE, 'upstream':{'nodes':{'ouf-semantic:8080':1}}}
gateway = {'Id':'a'*64, 'State':{'Running':True,'Pid':100},
           'Mounts':[{'Destination':m.CONFIG_TARGET,'Source':'/fixture/config','Type':'bind','RW':False}],
           'ResolvConfPath':'/var/lib/docker/containers/'+'a'*64+'/resolv.conf',
           'NetworkSettings':{'Networks':{'ouf-backend':{'NetworkID':'n'}}}}
registry = {'Name':'/ouf-semantic', 'State':{'Running':False},
            'NetworkSettings':{'Networks':{'ouf-backend':{'NetworkID':'n','Aliases':['ouf-semantic'],'IPAddress':''}}}}
with patch.object(m, 'read', return_value=config), patch.object(m.subprocess, 'run',
     return_value=SimpleNamespace(returncode=0,stdout=json.dumps({'list':[{'value':route}],'total':1}).encode())) as proc:
    report = {}
    assert m.route_read(gateway, report) == route
    assert secret not in repr(proc.call_args.args[0])
    assert report == {'adminRouteGetAttempts':1,'semanticRouteFound':True}
report = {}
m.topology(route,gateway,registry,report)
assert report['upstream']['connectivitySkipped'] == 'REGISTRY_STOPPED_OR_NO_SHARED_ADDRESS'
assert report['upstream']['configuredNamesMatchRegistry'] == [True]
registry['State']['Running']=True
registry['NetworkSettings']['Networks']['ouf-backend']['IPAddress']='172.20.0.5'
dns = [{'rcode':0,'dnsUnavailable':False,'addressCount':1,'matchesRegistry':True,
        'onlyRegistryAddresses':True,'matchedTcpReachable':True,'directRegistryTcpReachable':True}]
with patch.object(m, 'read', return_value=b'nameserver 127.0.0.11\n'), patch.object(m.subprocess, 'run',
     return_value=SimpleNamespace(returncode=0,stdout=json.dumps(dns).encode())) as proc:
    report={}
    m.topology(route,gateway,registry,report)
    assert report['upstream']['dnsAndTcp'] == dns
    assert proc.call_args.args[0][:5] == ('/usr/bin/nsenter','--target','100','--net',sys.executable)
    assert report['upstream']['httpBusinessRequestMade'] is False
assert "connection.request('GET','/apisix/admin/routes'" in m.ADMIN_CHILD
for forbidden in ("'start'", "'stop'", "'restart'", "'update'", "'POST'", "'PUT'", "'DELETE'"):
    assert forbidden not in path.read_text(), forbidden
print('PASS: selected admin key, bounded route read, redaction, stopped registry, DNS namespace and GET-only contract')

