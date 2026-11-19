#!/usr/bin/env python3
import copy
import importlib.util
import json
import os
from pathlib import Path
import signal
import selectors
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('runtime',sys.argv[1])
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
# The live PID guard accepts only the known non-root gate with SIGUSR1 caught.
guard_doc={'Image':r.SEMANTIC_IMAGE,'Config':{'Entrypoint':r.SEMANTIC_ENTRY,
           'Cmd':r.SEMANTIC_JAVA,'User':'10001:10001'},
           'State':{'Running':True,'Pid':4321}}
proc_status=('Uid: 10001 10001 10001 10001\nNoNewPrivs: 1\n'
             'CapInh: 0\nCapPrm: 0\nCapEff: 0\nCapBnd: 0\nCapAmb: 0\n'
             'SigCgt: '+format(1<<(signal.SIGUSR1-1),'x')+'\n').encode()
proc_args=r.SEMANTIC_ENTRY+r.SEMANTIC_JAVA
def process_fixture(path):
    if path.name=='stat':return ('4321 (sh) '+' '.join(['S']+['0']*18+['123'])).encode()
    if path.name=='status':return proc_status
    if path.name=='cmdline':return b'\0'.join(v.encode() for v in proc_args)+b'\0'
    raise AssertionError(path)
with patch.object(r,'process_bytes',side_effect=process_fixture), patch.object(r.Path,'stat',return_value=SimpleNamespace(st_ino=999)):
    assert r.semantic_process(guard_doc)['processKind']=='GATE_WAITING'
    proc_args=r.SEMANTIC_JAVA
    assert r.semantic_process(guard_doc)['processKind']=='APPLICATION_RUNNING'
    proc_args=r.SEMANTIC_ENTRY+r.SEMANTIC_JAVA
    proc_status=proc_status.replace(b'SigCgt: 200',b'SigCgt: 0')
    try:r.semantic_process(guard_doc);raise AssertionError('uncaught signal accepted')
    except ValueError as error:assert str(error)=='SEMANTIC_GATE_OR_APPLICATION_NOT_PROVEN'
cid='a'*64
doc={'Id':cid,'State':{'Pid':4321,'Running':True,'StartedAt':'2026-11-07T00:00:00Z'}}
generation={'pid':4321,'startTicks':123,'networkNamespaceInode':999}
gate={'generation':generation,'processKind':'GATE_WAITING'}
app={'generation':generation,'processKind':'APPLICATION_RUNNING'}
def inspect(*ids):
    return {value:copy.deepcopy(doc) for value in ids}
def do_case(root, process, docker=None, current_inspect=inspect):
    return patch.multiple(r,SEMANTIC_STARTS=root,inspect=current_inspect,
        semantic_process=process,semantic_readiness=lambda actual:(200,True),
        semantic_startup_details=lambda *args:None,**({'docker':docker} if docker else {}))
with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
    root=Path(tmp)
    states=iter([gate,gate,app])
    calls=[]
    with do_case(root/'one',lambda actual:next(states),lambda *args,**kwargs:calls.append(args)):
        report={}
        r.ensure_semantic_application(cid,report)
    assert calls==[('kill','--signal=SIGUSR1',cid)]
    assert report['semanticJavaIsContainerInit'] and report['semanticReadinessUp']
    assert len(list((root/'one').glob('*.json')))==1
    with do_case(root/'already',lambda actual:app,lambda *args,**kwargs:(_ for _ in ()).throw(AssertionError('signal to Java'))):
        report={}
        r.ensure_semantic_application(cid,report)
        assert report['semanticReadinessUp'] and 'semanticGateSignalDispatched' not in report
        assert not (root/'already').exists()
    attempts=[]
    def lost(*args,**kwargs):
        attempts.append(args)
        raise subprocess.TimeoutExpired('docker',15)
    with do_case(root/'lost',lambda actual:gate,lost):
        report={}
        try:r.ensure_semantic_application(cid,report);raise AssertionError('lost ack accepted')
        except subprocess.TimeoutExpired:pass
        assert report['semanticGateSignalDispatched']
        try:r.ensure_semantic_application(cid,{});raise AssertionError('signal replay accepted')
        except ValueError as error:assert str(error)=='SEMANTIC_SIGNAL_ALREADY_CLAIMED_READBACK_REQUIRED'
    assert len(attempts)==1
    def unknown(actual):raise ValueError('SEMANTIC_GATE_OR_APPLICATION_NOT_PROVEN')
    with do_case(root/'unknown',unknown,lambda *a,**k:(_ for _ in ()).throw(AssertionError('unknown process signalled'))):
        try:r.ensure_semantic_application(cid,{});raise AssertionError('unknown accepted')
        except ValueError as error:assert str(error)=='SEMANTIC_GATE_OR_APPLICATION_NOT_PROVEN'
        assert not (root/'unknown').exists()
    states=iter([gate,{'generation':dict(generation,pid=5555),'processKind':'GATE_WAITING'}])
    with do_case(root/'drift',lambda actual:next(states),lambda *a,**k:(_ for _ in ()).throw(AssertionError('changed generation signalled'))):
        try:r.ensure_semantic_application(cid,{});raise AssertionError('drift accepted')
        except ValueError as error:assert str(error)=='SEMANTIC_GATE_CHANGED_BEFORE_SIGNAL'
    with do_case(root/'timeout',lambda actual:app,lambda *a,**k:(_ for _ in ()).throw(AssertionError('signal to Java'))):
        with patch.object(r.time,'monotonic',side_effect=[0,151]):
            try:r.ensure_semantic_application(cid,{});raise AssertionError('no readiness accepted')
            except ValueError as error:assert str(error)=='SEMANTIC_APPLICATION_READINESS_TIMEOUT'
roles=[role for group in r.GROUPS for role in group]
assert all(roles.index(role)<roles.index('semantic') for role in ('gateway-owner','apisix','caddy'))
assert roles.index('semantic')<roles.index('mcp')
# Native shell proof: the exact gate waits, catches SIGUSR1, and execs in the same PID.
child=subprocess.Popen([r.SEMANTIC_ENTRY[0],'-x',*r.SEMANTIC_ENTRY[1:],sys.executable,'-I','-B','-S','-c',
                        'import os;print("EXEC_PID="+str(os.getpid()),flush=True)'],
                       stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
try:
    deadline=time.monotonic()+3
    trace=''
    with selectors.DefaultSelector() as selector:
        selector.register(child.stderr,selectors.EVENT_READ)
        while time.monotonic()<deadline:
            if selector.select(0.1):
                chunk=os.read(child.stderr.fileno(),4096).decode()
                trace+=chunk
                if '+ [ 0 = 0 ]' in trace:break
                if not chunk:raise AssertionError('native shell exited: '+trace)
        else:raise AssertionError('native gate did not reach waiting loop: '+trace)
    assert child.poll() is None
    child.send_signal(signal.SIGUSR1)
    stdout,stderr=child.communicate(timeout=5)
    assert child.returncode==0 and stdout.strip()=='EXEC_PID='+str(child.pid),(stdout,stderr)
finally:
    if child.poll() is None:child.kill();child.wait(timeout=5)
print('PASS: one-shot signal, existing Java no signal, lost-ack no replay, unknown/drift rejected, readiness required, dependency order and native same-PID shell exec')

