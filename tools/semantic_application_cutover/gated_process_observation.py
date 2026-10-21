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


class RunningWorkloadBinding:
    """Read-only binding to the same already verified Registry process.

    This cannot start/unpause/re-attest a workload. The current token owner
    independently authenticates the renewable token; historical effect receipts
    identify the process without extending their old authority.
    """
    def __init__(self,engine,transition,request,store):
        from engine_creation import Engine
        from transition_journal import Transition
        from native_evidence_store import NativeEvidenceStore
        require(type(engine) is Engine and type(transition) is Transition and type(store) is NativeEvidenceStore,
            'TYPED_RUNNING_REGISTRY_BINDING_REQUIRED')
        self.engine,self.transition,self.request,self.store=engine,transition,request,store
        self.process=GatedProcessObservation(request)
    def observe(self):
        from transition_journal import digest
        row=self.transition.read()
        require(row['nextPhase']>=10 and row['creationRequestHash']==digest(self.request),
            'RUNNING_BINDING_REQUIRES_COMPLETED_REGISTRY_VERIFICATION')
        release=next(e for e in row['effects'] if e['phase']=='START_REPLACEMENT' and e['state']=='APPLIED')
        verified=next(e for e in row['effects'] if e['phase']=='VERIFY_APPLICATION' and e['state']=='APPLIED')
        before=self.store.read('START_REPLACEMENT',release['nativeEvidenceHash'])
        verification=self.store.read('VERIFY_APPLICATION',verified['nativeEvidenceHash'])
        actual=self.engine.matching_configuration(self.transition,self.request,self.engine.inspect(self.transition))
        binding=self.engine.runtime_binding(actual);process=self.process.observe(binding['pid'])
        require(actual['State']['Running'] is True and actual['State']['Paused'] is False
            and actual['State']['Status']=='running' and actual['RestartCount']==0
            and binding==before['runtimeBinding']==verification['runtimeBinding']
            and process['generation']==before['generation'] and process['processKind']=='APPLICATION_RUNNING',
            'SAME_VERIFIED_RUNNING_REGISTRY_GENERATION_REQUIRED')
        require(self.transition.read()==row and self.engine.runtime_binding(self.engine.inspect(self.transition))==binding
            and self.process.observe(binding['pid'])==process,'RUNNING_REGISTRY_CHANGED_DURING_OBSERVATION')
        return {'runtimeBinding':binding,'process':process}
