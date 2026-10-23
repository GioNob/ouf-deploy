"""Foreground credential worker. A process manager owns restart/liveness only.

No container orchestration, Docker socket, endpoint discovery, startup signal,
policy change, source activation or native recovery journal mutation.
"""
import os
from pathlib import Path
import signal
import socket
import threading
import time
from .core import Worker, RenewalPolicy, require, encoded
from .guard import InstalledGuard
from .store import Store
from .adapter import NativeAdapter


def clocks():
    return Path('/proc/sys/kernel/random/boot_id').read_text().strip(),time.time(),time.monotonic()


def notify(message):
    # Only fixed process status is sent; no endpoint, credential or policy data.
    target=os.environ.get('NOTIFY_SOCKET')
    if not target:return
    if target.startswith('@'):target='\0'+target[1:]
    client=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM)
    try:client.settimeout(1);client.connect(target);client.sendall(message.encode())
    except OSError:pass
    finally:client.close()


def status(row):
    return {'schema':'ouf.registry-operational-token-status.v1','state':row['state'],
            'controlledCumulativeGrantAttempts':row['cumulativeAttempts'],
            'newOperationalGrantAttempts':row['attempts'],'publications':row['publications'],
            'processLive':True,'applicationReadinessProven':False,'runtimeAuthorityIssued':False}


def run(configuration_path,configuration_hash,emit=print):
    require(os.geteuid()==os.getegid()==0,'ROOT_OPERATIONAL_OWNER_REQUIRED')
    guard=InstalledGuard(configuration_path,configuration_hash)
    c=guard.configuration;policy=dict(c['policy']);policy['failure_delays']=tuple(policy['failure_delays'])
    policy=RenewalPolicy(**policy);store=Store(c['destinations']['ledgerRoot'])
    stop=threading.Event();handlers={}
    for sig in(signal.SIGTERM,signal.SIGINT):handlers[sig]=signal.signal(sig,lambda *_:stop.set())
    last=None
    try:
        with guard.invocation(),store.invocation():
            adapter=NativeAdapter(guard,store,clocks)
            worker=Worker(store,adapter,policy,configuration_hash,c['predecessorInputsHash'],c['priorControlledAttempts'],clocks)
            worker.start();notify('READY=1\nSTATUS=Credential worker running; application health unproven')
            while not stop.is_set():
                try:
                    row=worker.step() if worker.started_here else worker.row()
                    public=status(row)
                    if public!=last:emit(encoded(public).decode(),flush=True);last=public
                    notify('WATCHDOG=1\nSTATUS='+('Reconciliation required' if row['state'] in('BLOCKED','REVOKED') else 'Credential worker running'))
                except Exception:
                    # Unknown grant/publication outcome is already parked by
                    # Worker. No new attempt can follow without reconciliation.
                    notify('STOPPING=1\nSTATUS=Credential owner stopped; outcome retained')
                    raise
                stop.wait(5)
    finally:
        # Stopping does not unlink a valid token or rewrite a cancelled native
        # owner. A restart must obtain the same locks and readmit its own lease.
        notify('STOPPING=1');store.close()
        for sig,handler in handlers.items():signal.signal(sig,handler)
