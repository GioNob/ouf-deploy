#!/usr/bin/env python3
import importlib.util
import json
from pathlib import Path
import sys
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('reader', sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
secret = 'TEST_ONLY_TOKEN_DO_NOT_EMIT'
args = ['java','-Dserver.port=8081','-Dpassword='+secret,'-jar','/app/application.jar',
        '--management.server.port=9090','--spring.datasource.password='+secret]
launch = m.launch_summary(args)
assert launch['selectedDeclaredProperties'] == {'server.port':'8081','management.server.port':'9090'}
assert launch['jarPath'] == '/app/application.jar'
assert secret not in json.dumps(launch)
config = {'Env':['PORT=8080','PASSWORD='+secret,'JAVA_TOOL_OPTIONS=-Dserver.port=8082 -Dpassword='+secret,
                'SPRING_APPLICATION_JSON='+json.dumps({'server':{'port':8081},'secret':secret})],
          'Entrypoint':['sh','-c','sleep infinity'], 'Cmd':[]}
env = m.selected_environment(config)
assert env['environment'] == {'PORT':'8080'}
assert env['selectedJsonProperties'] == {'server.port':8081}
assert env['selectedJvmProperties'] == {'JAVA_TOOL_OPTIONS': {'server.port':'8082'}}
assert secret not in json.dumps(env)
assert m.launch_summary(config['Entrypoint'])['sleepCommandPresent']
header=b'  sl  local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n'
tcp=header+b'0: 00000000:1F91 00000000:0000 0A 00000000:00000000 00:00000000 00000000 10001 0 12345\n'
local=header+b'0: 0100007F:2382 00000000:0000 0A 00000000:00000000 00:00000000 00000000 10001 0 6789\n'
v6=header+b'0: 00000000000000000000000001000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 10001 0 23456\n'
assert m.socket_rows(tcp,False)[0]['bindScope']=='all-interfaces'
assert m.socket_rows(local,False)[0]['bindScope']=='loopback'
assert m.socket_rows(v6,True)[0]['bindScope']=='loopback'
assert m.socket_rows(v6,True)[0]['port']==8080
registry={'Id':'a'*64,'Image':'sha256:'+'b'*64,'State':{'Running':True,'Pid':100},'Config':config}
image=[{'Config':{'Entrypoint':['java','-jar','/app/application.jar'],'Cmd':[]}}]
with patch.object(m,'process_rows',return_value=[['100','1','sleep']]), patch.object(m,'docker_json',return_value=image), patch.object(m,'proc_read',return_value=header):
    report={}
    m.process_snapshot(registry,report)
    actual=report['semanticProcess']
    assert actual['javaProcessCount']==0 and actual['initProcessKind']=='sleep'
    assert actual['containerLaunchMatchesImageDefault'] is False
    assert actual['imageDefaultLaunch']['javaJarArgumentPresent'] is True
    assert actual['listeners']==[] and actual['processSetUnchangedDuringRead']
def read_proc(path,limit):
    if path.endswith('/tcp'): return tcp
    if path.endswith('/tcp6'): return header
    if path.endswith('/cmdline'): return b'\0'.join(x.encode() for x in args)+b'\0'
    raise AssertionError(path)
def read_link(path):
    return 'pid:[123]' if str(path).endswith('/ns/pid') else 'socket:[12345]'
with patch.object(m,'process_rows',return_value=[['100','1','sleep'],['101','100','java']]), patch.object(m,'docker_json',return_value=image), patch.object(m,'proc_read',side_effect=read_proc), patch.object(m.os,'readlink',side_effect=read_link), patch.object(m.Path,'iterdir',return_value=iter([Path('/proc/101/fd/7')])):
    report={}
    m.process_snapshot(registry,report)
    actual=report['semanticProcess']
    assert actual['javaProcessCount']==1
    assert actual['listeners'][0]['ownedByObservedJavaProcess']
    assert actual['listeners'][0]['port']==8081
    assert secret not in json.dumps(actual)
print('PASS: no-secret launch/environment projection, IPv4/IPv6 listeners, sleeping init, image launch comparison and Java socket ownership')

