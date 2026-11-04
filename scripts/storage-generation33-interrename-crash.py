#!/usr/bin/env python3
"""Observe one real DAT rename, then hold IDX rename entry until fixture SIGKILL.

Reuse the qualified read-only ptrace transport. First capture the complete
post-marker pair, then allow native execution up to the exact second rename.
No storage/registry/syscall edits, detach, retry or resume after the final freeze.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import time

def load(name, filename):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(filename))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

commit=load('commit_observer33','storage-generation33-commit-crash.py')
relocation=load('interrename_witness33','storage-generation33-relocation.py')
pre,require,atomic_json=commit.pre,commit.require,commit.atomic_json

def raw_storage(root):
    """Do not decode old IDX offsets against the intentionally new DAT."""
    paths=sorted(root.glob('*.dat'))
    require(0<len(paths)<=24,'BOUNDED_RAW_VOLUME_SET')
    result={p.name:pre.files(root,p.name) for p in paths}
    require(sum(v['bytes'] for files in result.values() for v in files.values())<=128*1024*1024,'BOUNDED_RAW_VOLUME_BYTES')
    return result

def validate_mixed(before, first, frozen, states, first_result):
    require(states and set(states.values())=={'t'},'ALL_INTERRENAME_THREADS_STOPPED')
    require(set(before)=={'.dat','.idx'},'CLEAN_INTERRENAME_BASELINE')
    require(set(first)=={'.dat','.idx','.cpd','.cpx','.cpc'} and first['.cpc']['bytes']==0,'POSTMARKER_COPY_PAIR_REQUIRED')
    require(all(first[x]==before[x] for x in before),'FIRST_RENAME_NOT_YET_EXECUTED_IN_SOURCE_CAPTURE')
    require(set(frozen)=={'.dat','.idx','.cpx','.cpc'},'DAT_ONLY_RENAMED_FILE_SET_REQUIRED')
    require(first_result.get('returnValue')==0 and first_result.get('operation')=='exit' and not first_result.get('isError'),
            'FIRST_RENAME_SUCCESSFUL_EXIT_REQUIRED')
    require(frozen['.dat']==first['.cpd'] and frozen['.dat']!=before['.dat'],'EXACT_COMPACTED_DAT_INODE_PROMOTED')
    require(frozen['.idx']==before['.idx'],'OLD_IDX_UNRENAMED_REQUIRED')
    require(frozen['.cpx']==first['.cpx'] and frozen['.cpc']==first['.cpc'],'PENDING_INDEX_AND_MARKER_UNCHANGED')

def validate_pair(frozen, recovered):
    require(set(recovered)=={'.dat','.idx'},'INTERRENAME_RECOVERY_REMOVES_MARKER_AND_COPY')
    require(recovered['.dat']==frozen['.dat'] and recovered['.idx']==frozen['.cpx'],'EXACT_PENDING_INDEX_PROMOTED_DAT_UNCHANGED')

def validate_unselected(before, after, target):
    require(set(before)==set(after) and target in before,'UNCHANGED_RAW_VOLUME_SET')
    require(all(before[name]==after[name] for name in before if name!=target),'UNSELECTED_RAW_FILES_UNCHANGED')

def mixed_witness(old_index, pending_index, data, witness, before_dat_bytes):
    require(witness==relocation.identity(witness),'EXACT_MIXED_WITNESS_IDENTITY')
    def entry(raw):
        require(0<len(raw)<=1024 and len(raw)%16==0,'BOUNDED_COMPLETE_MIXED_INDEX')
        rows=[struct.unpack('>QIi',raw[p:p+16]) for p in range(0,len(raw),16)]
        matches=[(offset*8,size) for nid,offset,size in rows if nid==witness['needleId']]
        require(len(matches)==1 and matches[0][1]>0,'ONE_LIVE_MIXED_WITNESS_ENTRY')
        return matches[0]
    old_offset,old_size=entry(old_index);new_offset,new_size=entry(pending_index)
    require(8<=len(data)<=33*1024*1024 and data[0] in (2,3),'BOUNDED_MIXED_DAT')
    require(old_offset>=len(data),'OLD_WITNESS_OFFSET_OUTSIDE_NEW_DAT_REQUIRED')
    require(new_offset>=8 and new_offset%8==0 and old_offset-new_offset>=4194304
            and old_offset-new_offset==before_dat_bytes-len(data)
            and new_offset+20+witness['dataBytes']<=len(data),'PENDING_INDEX_RELOCATES_VALID_WITNESS')
    cookie,nid,size,length=struct.unpack('>IQiI',data[new_offset:new_offset+20])
    digest=pre.sha(data[new_offset+20:new_offset+20+length])
    require(nid==witness['needleId'] and format(cookie,'08x')==witness['cookieHex'] and size==old_size==new_size
            and length==witness['dataBytes'] and digest==witness['dataSha256'],'PENDING_INDEX_BINDS_EXACT_WITNESS_BODY')
    return {**witness,'oldNeedleOffset':old_offset,'pendingNeedleOffset':new_offset,'needleSize':size,
            'newDatBytes':len(data),'oldIndexInvalidForNewDat':True,'pendingIndexBodyVerified':True,'mutatingRequests':0}

class Observer(commit.Observer):
    def __init__(self,*args,**kwargs):
        self.stop_signals={};super().__init__(*args,**kwargs)

    def event(self,tid,status):
        kind,sig=super().event(tid,status)
        if kind=='signal':self.stop_signals[tid]=sig
        return kind,sig

    def resume(self,tid,sig=0):
        # Preserve genuine signal-delivery stops while releasing the first freeze.
        pending=self.stop_signals.pop(tid,0);super().resume(tid,sig or pending)

    def observe_second(self,first,timeout=15):
        require(first['operation']=='entry' and first['syscallNotResumed'] and self.tids==self.stopped,'FIRST_RENAME_HELD_BEFORE_RELEASE')
        first_tid=first['tid'];first_result=None
        old_path=str(Path(self.old_path).with_suffix('.cpx'));new_path=str(Path(self.new_path).with_suffix('.idx'))
        for tid in sorted(self.tids):self.resume(tid)
        deadline=time.monotonic()+timeout
        while True:
            tid,status=self.wait(deadline);kind,sig=self.event(tid,status)
            require(kind!='exit','NO_THREAD_EXIT_BETWEEN_RENAMES')
            if kind=='syscall':
                info=self.info(tid)
                if tid==first_tid and first_result is None:
                    require(info['op']=='exit' and info['returnValue']==0 and not info['isError'],'FIRST_NATIVE_DAT_RENAME_MUST_SUCCEED')
                    first_result={'tid':tid,'operation':'exit','returnValue':0,'isError':False,
                                  'number':first['number'],'oldPath':first['oldPath'],'newPath':first['newPath']}
                elif info['op']=='entry' and info['number'] in (82,264,316):
                    nr,args=info['number'],info['args']
                    old,new=(args[0],args[1]) if nr==82 else (args[1],args[3])
                    paths=(self.string(tid,old),self.string(tid,new))
                    require(paths!=(self.old_path,self.new_path),'NO_SECOND_DAT_RENAME_ATTEMPT')
                    if paths==(old_path,new_path):
                        require(first_result is not None and (nr!=316 or args[4]==0),'SUCCESSFUL_FIRST_PLAIN_SECOND_RENAME')
                        states=self.freeze_all(time.monotonic()+5)
                        return {'tid':tid,'number':nr,'operation':'entry','oldPath':paths[0],'newPath':paths[1],
                                'syscallNotResumed':True,'threadStates':states,'successfulSyncs':self.syncs,
                                'firstRenameResult':first_result,'cloneEvents':self.clone_events}
            self.resume(tid,sig if kind=='signal' else 0)

def retain(root,target,output,prefix,extensions):
    for ext in extensions:
        path=(root/target).with_suffix(ext)
        require(path.is_file() and not path.is_symlink(),'RETAINED_REGULAR_INTERRENAME_FILE')
        (output/(prefix+ext)).write_bytes(path.read_bytes())

def run(root,target,pid,container,output):
    report={'status':'UNQUALIFIED','instrumentation':'external read-only ptrace scheduling','vacuumResubmissions':0}
    try:
        require(os.geteuid()==0 and pid>1 and len(container)==64 and output.is_dir(),'EXACT_PRIVILEGED_INTERRENAME_OBSERVER')
        identity=pre.process_identity(pid);require(container in identity['cgroup'],'EXACT_CONTAINER_CGROUP_REQUIRED')
        with (Path('/proc')/str(pid)/'exe').open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
        require(digest==pre.BINARY_SHA,'UNCHANGED_GENERATION33_BINARY_REQUIRED')
        before=pre.files(root,target);require(set(before)=={'.dat','.idx'},'CLEAN_INTERRENAME_BASELINE')
        raw_before=raw_storage(root);witness=json.loads((output/'relocation-witness.json').read_bytes())
        report.update(processBefore=identity,binarySha256=digest,filesBefore=before,rawStorageBefore=raw_before)
        observer=Observer(pid,root,target);observer.attach()
        atomic_json(output/'interrename-observer-ready.json',report)
        first=observer.observe();first_files=pre.files(root,target)
        commit.validate_phase(before,first_files,first['threadStates'],first['successfulSyncs'])
        first_witness=relocation.observe(root,witness)
        first_raw=raw_storage(root);validate_unselected(raw_before,first_raw,target)
        retain(root,target,output,'interrename-before-dat-retained',('.cpd','.cpx','.cpc','.idx'))
        report.update(beforeDatRenamePhase=first,filesBeforeDatRename=first_files,witnessBeforeDatRename=first_witness)
        atomic_json(output/'interrename-before-dat-rename.json',report)
        phase=observer.observe_second(first);frozen=pre.files(root,target)
        require(pre.process_identity(pid)==identity,'SAME_PROCESS_BETWEEN_RENAMES')
        validate_mixed(before,first_files,frozen,phase['threadStates'],phase['firstRenameResult'])
        raw_frozen=raw_storage(root);validate_unselected(raw_before,raw_frozen,target)
        mixed=mixed_witness((root/target).with_suffix('.idx').read_bytes(),(root/target).with_suffix('.cpx').read_bytes(),(root/target).read_bytes(),witness,before['.dat']['bytes'])
        retain(root,target,output,'interrename-frozen-retained',('.dat','.idx','.cpx','.cpc'))
        require(pre.files(root,target)==frozen and pre.thread_states(pid)==phase['threadStates'],'MIXED_FROZEN_STATE_STABLE')
        report.update(phase);report.update(status='OBSERVED_INTERRENAME_FROZEN',processFrozen=pre.process_identity(pid),
            filesFrozen=frozen,rawStorageFrozen=raw_frozen,mixedWitness=mixed)
        atomic_json(output/'interrename-freeze.json',report)
        exits=observer.wait_for_kill()
        atomic_json(output/'interrename-observer-exit.json',{'status':'ALL_TRACED_THREADS_KILLED','exits':exits})
    except Exception as error:
        report.update(status='UNQUALIFIED',failure=type(error).__name__+': '+str(error))
        atomic_json(output/'interrename-failure.json',report);raise

if __name__=='__main__':
    parser=argparse.ArgumentParser();subs=parser.add_subparsers(dest='operation',required=True)
    p=subs.add_parser('observe');p.add_argument('root',type=Path);p.add_argument('target');p.add_argument('pid',type=int)
    p.add_argument('container');p.add_argument('output',type=Path)
    p=subs.add_parser('raw-storage');p.add_argument('root',type=Path)
    args=parser.parse_args()
    if args.operation=='raw-storage':print(json.dumps(raw_storage(args.root)))
    else:run(args.root,args.target,args.pid,args.container,args.output)
