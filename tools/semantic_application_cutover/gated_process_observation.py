"""Bounded read-only process identity for the proposed pre-Java launch gate.

No signal, lifecycle effect or acceptance. Parent owns source/custody/complete
OCI/peer and artifact proof; process arguments and environment are not printed.
"""
import os,signal
from pathlib import Path
from transition_journal import require
from gated_creation_plan import ENTRY

class GatedProcessObservation:
    def __init__(self,creation_request):
        require(os.geteuid()==0 and creation_request.get('Entrypoint')==ENTRY
                and creation_request.get('User')=='10001:10001','ROOT_EXACT_GATED_PROCESS_SCOPE_REQUIRED')
        self.gate_args=[*ENTRY,*creation_request['Cmd']];self.application_args=list(creation_request['Cmd'])
    def observe(self,pid):
        require(type(pid) is int and 1<pid<2147483647,'EXACT_GATED_PROCESS_PID_REQUIRED');root=Path('/proc')/str(pid)
        def generation():
            value=(root/'stat').read_text();parts=value.rsplit(')',1)[1].split()
            return {'pid':pid,'startTicks':int(parts[19]),'namespaceInode':(root/'ns/net').stat().st_ino},parts[0]
        before,state=generation()
        with (root/'cmdline').open('rb') as stream:raw=stream.read(65537)
        require(len(raw)<=65536 and raw.endswith(b'\0'),'BOUNDED_GATED_PROCESS_ARGUMENTS_REQUIRED')
        args=[v.decode('utf-8') for v in raw[:-1].split(b'\0')]
        status={}
        with (root/'status').open('rb') as stream:status_raw=stream.read(65537)
        require(len(status_raw)<=65536,'BOUNDED_GATED_PROCESS_METADATA_REQUIRED')
        for line in status_raw.decode().splitlines():
            if ':' in line:
                key,value=line.split(':',1);status[key]=value.strip()
        require(status.get('Uid','').split()==['10001']*4 and status.get('NoNewPrivs')=='1'
                and all(int(status.get(k,'-1'),16)==0 for k in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb')),'GATED_PROCESS_NONROOT_CAPABILITY_OR_NNP_DRIFT')
        after,endstate=generation()
        # R/S/D/I are scheduler states, not identity or readiness changes.
        # Preserve generation/argv checks and require both observations in the
        # accepted liveness category; never certify a stopped/zombie Java exec.
        require(before==after and (root/'cmdline').read_bytes()==raw,'GATED_PROCESS_CHANGED_DURING_READ')
        caught=int(status.get('SigCgt','0'),16)&(1<<(signal.SIGUSR1-1))
        kind='GATE_WAITING' if args==self.gate_args and caught and state in ('R','S','D','I','T','t') and endstate in ('R','S','D','I','T','t') else 'APPLICATION_RUNNING' if args==self.application_args and state in ('R','S','D','I') and endstate in ('R','S','D','I') else 'UNPROVEN'
        return {'generation':before,'processKind':kind,'nonRootIdentityVerified':True,'capabilitiesEmpty':True,'noNewPrivileges':True}
