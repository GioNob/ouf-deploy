"""Versioned pure assembler with an explicit installation runtime parent.

The consumed legacy intake's source closure stays byte exact. Reuse its producer
assembly and bind the new Broker plus BOTH initial journals to the selected
approved parent. No keys, native observation, authority or publication occurs.
"""
from pathlib import PurePosixPath
from .assemble_provider_profiles import AssemblyDenied,require,encoded,digest,source_closure
from .assemble_provider_profiles import assemble_profiles as legacy_assembly

def assemble_profiles(root,source_root,sources,authority,python,crypto,intent_binding,intent,template,
                      final_mandate_binding,observer_binding,runtime_parents,bundle_parents,rootfs_limits,
                      *,broker_runtime_root_parent=None):
    require(type(runtime_parents) is list and bool(runtime_parents)
        and all(type(p) is str and PurePosixPath(p).is_absolute() and p!='/'
            and str(PurePosixPath(p))==p and '..' not in PurePosixPath(p).parts for p in runtime_parents)
        and len(set(runtime_parents))==len(runtime_parents),'EXPLICIT_APPROVED_RUNTIME_PARENTS_REQUIRED')
    if broker_runtime_root_parent is None:
        require(len(runtime_parents)==1,'EXPLICIT_UNAMBIGUOUS_BROKER_RUNTIME_PARENT_REQUIRED')
        broker_runtime_root_parent=runtime_parents[0]
    require(broker_runtime_root_parent in runtime_parents,'BROKER_RUNTIME_PARENT_OUTSIDE_APPROVED_NODE_PARENTS')
    files=legacy_assembly(root,source_root,sources,authority,python,crypto,intent_binding,intent,template,
        final_mandate_binding,observer_binding,runtime_parents,bundle_parents,rootfs_limits)
    files['broker.json']['runtimeRootParent']=broker_runtime_root_parent
    configuration_hash=digest(encoded(files['broker.json']))
    for name in ('broker-state.json','deployment.json'):files[name]['configurationHash']=configuration_hash
    return files
