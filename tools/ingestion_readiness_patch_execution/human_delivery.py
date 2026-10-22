"""Seal new HUMAN governance using the frozen operator and native core bytes.

Build only: no target I/O, login, grant or authority. The authenticated completed
archive capsule is a source carrier; its preparation entrypoint is never run.
"""
import ast
from pathlib import Path
from tools.governed_human_successor import auth_delivery
from tools.ingestion_readiness_patch_execution import operator_delivery as runtime_delivery

ENTRY='tools.ingestion_readiness_patch_execution.human_governance'
BOOTSTRAP=auth_delivery.BOOTSTRAP.replace(
    'import ast,base64,gzip,hashlib,importlib.abc,importlib.util,io,json,os,sys',
    'import ast,base64,gzip,hashlib,importlib.abc,importlib.util,io,json,os,signal,sys')
BOOTSTRAP=BOOTSTRAP.replace(
    " require(len(sys.argv)in(2,3)and sys.argv[1]in('open-window','step','status','reconcile-read'),'ONE_EXPLICIT_OPERATOR_MODE_REQUIRED')\n require((sys.argv[1]=='open-window')==(len(sys.argv)==2),'EXACT_OPERATOR_CONTROL_ARGUMENT_REQUIRED')",
    " modes=('prepare','grant-budget','budget-status','open-window','step','status','reconcile-read')\n require(len(sys.argv)in(2,3)and sys.argv[1]in modes,'ONE_EXPLICIT_PATCH_HUMAN_MODE_REQUIRED')\n require((sys.argv[1]in modes[:4])==(len(sys.argv)==2),'EXACT_PATCH_HUMAN_CONTROL_ARGUMENT_REQUIRED')\n signal.signal(signal.SIGALRM,lambda *_:require(False,'FINITE_PATCH_HUMAN_INVOCATION_DEADLINE'))\n signal.alarm(240)")


def generate(root,case):
    root=Path(root);payload,manifest=runtime_delivery.core(root)
    if case.get('nativeDeclaration')!=manifest:
        raise ValueError('EXACT_FROZEN_PATCH_HUMAN_NATIVE_DECLARATION_REQUIRED')
    tree=ast.parse((root/'tools/ingestion_readiness_patch_execution/runtime.py').read_bytes())
    values={n.targets[0].id:ast.literal_eval(n.value)for n in tree.body
        if isinstance(n,ast.Assign)and isinstance(n.targets[0],ast.Name)and n.targets[0].id=='SOURCE_PATHS'}
    paths={}
    for name,source in payload['sources'].items():
        # The immutable runtime declares exact paths; no module-name guessing
        # or executable import of the archived loader is needed by the builder.
        path=values['SOURCE_PATHS'][name]
        if (root/path).read_bytes()!=source.encode():raise ValueError('IMMUTABLE139_HUMAN_SOURCE_BYTES_CHANGED')
        paths[name]=path
    paths[ENTRY]='tools/ingestion_readiness_patch_execution/human_governance.py'
    control='tools.ingestion_readiness_patch_execution.operator_control'
    paths[control]='tools/ingestion_readiness_patch_execution/operator_control.py'
    if runtime_delivery.sha((root/paths[ENTRY]).read_bytes())!=case['governanceSourceHash']:
        raise ValueError('EXACT_PATCH_HUMAN_GOVERNANCE_SOURCE_REQUIRED')
    if runtime_delivery.sha((root/paths[control]).read_bytes())!=case['runtimeCase']['controlSourceHash']:
        raise ValueError('EXACT_PATCH_HUMAN_RUNTIME_CONTROL_SOURCE_REQUIRED')
    raw,declaration=auth_delivery.generate(root,case,{},entry=ENTRY,bootstrap=BOOTSTRAP,extra_paths=paths)
    if len(raw)>1048576:raise ValueError('BOUNDED_PATCH_HUMAN_DELIVERY_REQUIRED')
    return raw,declaration
