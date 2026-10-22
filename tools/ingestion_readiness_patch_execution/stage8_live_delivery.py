"""Build a closed one-use read-only metadata capsule; no target I/O at build."""
from pathlib import Path
from tools.governed_human_successor import auth_delivery
from tools.ingestion_readiness_patch_execution import runtime_successor,operator_delivery_v2

ENTRY='tools.ingestion_readiness_patch_execution.stage8_live_inputs'
BOOTSTRAP=auth_delivery.BOOTSTRAP.replace(
    'import ast,base64,gzip,hashlib,importlib.abc,importlib.util,io,json,os,sys',
    'import ast,base64,gzip,hashlib,importlib.abc,importlib.util,io,json,os,re,signal,sys')
BOOTSTRAP=BOOTSTRAP.replace(
    " require(len(sys.argv)in(2,3)and sys.argv[1]in('open-window','step','status','reconcile-read'),'ONE_EXPLICIT_OPERATOR_MODE_REQUIRED')\n require((sys.argv[1]=='open-window')==(len(sys.argv)==2),'EXACT_OPERATOR_CONTROL_ARGUMENT_REQUIRED')",
    " require(len(sys.argv)==2 and sys.argv[1]=='prepare','ONE_EXPLICIT_STAGE8_CAPTURE_REQUIRED')\n signal.signal(signal.SIGALRM,lambda *_:require(False,'FINITE_STAGE8_CAPTURE_DEADLINE'));signal.alarm(240)")
BOOTSTRAP=BOOTSTRAP.replace("reason=str(error)if type(error).__name__ in('Denied','PlanDenied','ValueError','HumanSessionPaused')and str(error)in SAFE_REASONS", "reason=str(error)if re.fullmatch('[A-Z][A-Z0-9_]{0,127}',str(error))")
BOOTSTRAP=BOOTSTRAP.replace('ouf.human-explicit-successor-operator-result.v1','ouf.ingestion-readiness-stage8-live-input-result.v1')


def generate(root,case):
    root=Path(root);paths=dict(runtime_successor.SOURCE_PATHS)
    # Every original139 source is still byte-for-byte the authenticated carrier.
    payload,_=operator_delivery_v2.core(root)
    for name,source in payload['sources'].items():
        if (root/paths[name]).read_bytes()!=source.encode():raise ValueError('ORIGINAL139_CAPTURE_SOURCES_CHANGED')
    for name in ('stage8_live_inputs','stopped_patch_snapshot','unissued_reconcile'):
        paths['tools.ingestion_readiness_patch_execution.'+name]='tools/ingestion_readiness_patch_execution/'+name+'.py'
    if auth_delivery.sha((root/paths[ENTRY]).read_bytes())!=case['readerSourceHash']:
        raise ValueError('EXACT_STAGE8_CAPTURE_SOURCE_REQUIRED')
    raw,declaration=auth_delivery.generate(root,case,{},entry=ENTRY,bootstrap=BOOTSTRAP,extra_paths=paths)
    if len(raw)>1048576:raise ValueError('BOUNDED_STAGE8_CAPTURE_CAPSULE_REQUIRED')
    return raw,declaration
