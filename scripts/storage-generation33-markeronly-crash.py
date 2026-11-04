#!/usr/bin/env python3
"""Hold real marker unlink after both native renames and directory fsync."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import time
import importlib.util

spec=importlib.util.spec_from_file_location('marker_inter33',Path(__file__).with_name('storage-generation33-interrename-crash.py'))
inter=importlib.util.module_from_spec(spec);spec.loader.exec_module(inter)
pre,require,atomic_json=inter.pre,inter.require,inter.atomic_json
raw_storage=inter.raw_storage

def validate_phase(first,mixed,frozen,states,second_result,syncs):
    require(states and set(states.values())=={'t'},'ALL_MARKERONLY_THREADS_STOPPED')
    require(set(first)=={'.dat','.idx','.cpd','.cpx','.cpc'} and set(mixed)=={'.dat','.idx','.cpx','.cpc'},'PRIOR_PHASES_REQUIRED')
    require(set(frozen)=={'.dat','.idx','.cpc'},'ONLY_MARKER_REMAINS_AFTER_BOTH_RENAMES')
    require(second_result.get('operation')=='exit' and second_result.get('returnValue')==0 and not second_result.get('isError'),
            'SECOND_RENAME_SUCCESS_REQUIRED')
    require(frozen['.dat']==mixed['.dat']==first['.cpd'] and frozen['.idx']==mixed['.cpx']==first['.cpx'],
            'EXACT_BOTH_COMPACTED_INODES_PROMOTED')
    require(frozen['.cpc']==mixed['.cpc']==first['.cpc'] and frozen['.cpc']['bytes']==0,'SAME_MARKER_REMAINS')
    require(len(syncs)==1 and syncs[0]['kind']=='directory' and syncs[0]['returnValue']==0,'POST_RENAME_DIRECTORY_SYNC_REQUIRED')

def validate_pair(frozen,recovered):
    require(set(recovered)=={'.dat','.idx'},'MARKERONLY_RECOVERY_REMOVES_MARKER')
    require(all(recovered[x]==frozen[x] for x in recovered),'ALREADY_PROMOTED_PAIR_UNCHANGED')

class Observer(inter.Observer):
    def observe_marker(self,second,timeout=15):
        require(second['operation']=='entry' and second['syscallNotResumed'] and self.tids==self.stopped,'SECOND_RENAME_HELD_BEFORE_RELEASE')
        second_tid=second['tid'];second_result=None;syncs=[];pending_sync={}
        marker=str(Path(self.new_path).with_suffix('.cpc'))
        for tid in sorted(self.tids):self.resume(tid)
        deadline=time.monotonic()+timeout
        while True:
            tid,status=self.wait(deadline);kind,sig=self.event(tid,status)
            require(kind!='exit','NO_THREAD_EXIT_BEFORE_MARKER_UNLINK')
            if kind=='syscall':
                info=self.info(tid)
                if tid==second_tid and second_result is None:
                    require(info['op']=='exit' and info['returnValue']==0 and not info['isError'],'SECOND_NATIVE_IDX_RENAME_MUST_SUCCEED')
                    second_result={'tid':tid,'operation':'exit','returnValue':0,'isError':False,
                                   'number':second['number'],'oldPath':second['oldPath'],'newPath':second['newPath']}
                elif info['op']=='entry':
                    nr,args=info['number'],info['args'];pending_sync.pop(tid,None)
                    if nr==74 and self.sync_kind(tid,args[0])=='directory':
                        require(second_result is not None,'DIRECTORY_SYNC_AFTER_SECOND_EXIT')
                        pending_sync[tid]=True
                    if nr in (82,264,316):
                        old,new=(args[0],args[1]) if nr==82 else (args[1],args[3])
                        require(self.string(tid,old) not in (self.old_path,second['oldPath']),'NO_REPEATED_COMPACTION_RENAME')
                    if nr in (87,263):
                        name=self.string(tid,args[0] if nr==87 else args[1])
                        if name==marker:
                            require(second_result is not None and tid==second_tid and len(syncs)==1,'BOTH_RENAMES_AND_SYNC_BEFORE_UNLINK')
                            require(nr!=263 or args[2]==0,'PLAIN_MARKER_UNLINK_REQUIRED')
                            states=self.freeze_all(time.monotonic()+5)
                            return {'tid':tid,'number':nr,'operation':'entry','path':name,'syscallNotResumed':True,
                                    'threadStates':states,'successfulSyncs':self.syncs,'firstRenameResult':second['firstRenameResult'],
                                    'secondRenameResult':second_result,'postRenameDirectorySyncs':syncs,'cloneEvents':self.clone_events}
                elif pending_sync.pop(tid,None):
                    require(info['returnValue']==0 and not info['isError'],'SUCCESSFUL_POST_RENAME_DIRECTORY_FSYNC')
                    syncs.append({'kind':'directory','tid':tid,'returnValue':0})
                    require(len(syncs)==1,'ONE_POST_RENAME_DIRECTORY_FSYNC')
            self.resume(tid,sig if kind=='signal' else 0)

def run(root,target,pid,container,output):
    report={'status':'UNQUALIFIED','instrumentation':'external read-only ptrace scheduling','vacuumResubmissions':0}
    try:
        require(os.geteuid()==0 and pid>1 and len(container)==64 and output.is_dir(),'EXACT_PRIVILEGED_MARKERONLY_OBSERVER')
        identity=pre.process_identity(pid);require(container in identity['cgroup'],'EXACT_CONTAINER_CGROUP_REQUIRED')
        with (Path('/proc')/str(pid)/'exe').open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
        require(digest==pre.BINARY_SHA,'UNCHANGED_GENERATION33_BINARY_REQUIRED')
        before=pre.files(root,target);require(set(before)=={'.dat','.idx'},'CLEAN_MARKERONLY_BASELINE')
        raw_before=raw_storage(root);witness=json.loads((output/'relocation-witness.json').read_bytes())
        report.update(processBefore=identity,binarySha256=digest,filesBefore=before,rawStorageBefore=raw_before)
        observer=Observer(pid,root,target);observer.attach()
        atomic_json(output/'markeronly-observer-ready.json',report)
        first=observer.observe();first_files=pre.files(root,target)
        inter.commit.validate_phase(before,first_files,first['threadStates'],first['successfulSyncs'])
        first_witness=inter.relocation.observe(root,witness)
        inter.validate_unselected(raw_before,raw_storage(root),target)
        inter.retain(root,target,output,'markeronly-before-dat-retained',('.cpd','.cpx','.cpc','.idx'))
        report.update(beforeDatRenamePhase=first,filesBeforeDatRename=first_files,witnessBeforeDatRename=first_witness)
        atomic_json(output/'markeronly-before-dat-rename.json',report)
        second=observer.observe_second(first);mixed_files=pre.files(root,target)
        inter.validate_mixed(before,first_files,mixed_files,second['threadStates'],second['firstRenameResult'])
        inter.validate_unselected(raw_before,raw_storage(root),target)
        mixed=inter.mixed_witness((root/target).with_suffix('.idx').read_bytes(),(root/target).with_suffix('.cpx').read_bytes(),(root/target).read_bytes(),witness)
        inter.retain(root,target,output,'markeronly-before-idx-retained',('.dat','.idx','.cpx','.cpc'))
        report.update(beforeIdxRenamePhase=second,filesBeforeIdxRename=mixed_files,mixedWitness=mixed)
        atomic_json(output/'markeronly-before-idx-rename.json',report)
        phase=observer.observe_marker(second);frozen=pre.files(root,target)
        require(pre.process_identity(pid)==identity,'SAME_PROCESS_THROUGH_BOTH_RENAMES')
        validate_phase(first_files,mixed_files,frozen,phase['threadStates'],phase['secondRenameResult'],phase['postRenameDirectorySyncs'])
        raw_frozen=raw_storage(root);inter.validate_unselected(raw_before,raw_frozen,target)
        witness_frozen=inter.relocation.observe(root,witness)
        inter.retain(root,target,output,'markeronly-frozen-retained',('.dat','.idx','.cpc'))
        require(pre.files(root,target)==frozen and pre.thread_states(pid)==phase['threadStates'],'MARKERONLY_FROZEN_STATE_STABLE')
        report.update(phase);report.update(status='OBSERVED_MARKERONLY_FROZEN',processFrozen=pre.process_identity(pid),
            filesFrozen=frozen,rawStorageFrozen=raw_frozen,witnessFrozen=witness_frozen)
        atomic_json(output/'markeronly-freeze.json',report)
        exits=observer.wait_for_kill()
        atomic_json(output/'markeronly-observer-exit.json',{'status':'ALL_TRACED_THREADS_KILLED','exits':exits})
    except Exception as error:
        report.update(status='UNQUALIFIED',failure=type(error).__name__+': '+str(error))
        atomic_json(output/'markeronly-failure.json',report);raise

if __name__=='__main__':
    parser=argparse.ArgumentParser();subs=parser.add_subparsers(dest='operation',required=True)
    p=subs.add_parser('observe');p.add_argument('root',type=Path);p.add_argument('target');p.add_argument('pid',type=int)
    p.add_argument('container');p.add_argument('output',type=Path)
    p=subs.add_parser('raw-storage');p.add_argument('root',type=Path)
    args=parser.parse_args()
    if args.operation=='raw-storage':print(json.dumps(raw_storage(args.root)))
    else:run(args.root,args.target,args.pid,args.container,args.output)
