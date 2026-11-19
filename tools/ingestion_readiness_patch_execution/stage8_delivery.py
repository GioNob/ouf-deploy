"""Closed verified-memory continuation delivery; no target or authority at build.

All original 144 runtime sources remain byte-for-byte unchanged. The new loader
adds only the continuation controller and its read-only retained-input readers.
"""
import base64,gzip,io,json,re
from pathlib import Path
from tools.ingestion_readiness_patch_execution import runtime_stage8 as loader,operator_delivery_v2 as previous
from tools.ingestion_readiness_patch_execution import release_delivery_v2 as release

ENTRY='tools.ingestion_readiness_patch_execution.stage8_continuation'
BOOTSTRAP=previous.BOOTSTRAP.replace(
    "('preflight','review','approve','initialize','step','reconcile','status')",
    "('preflight','review','approve','import-prefix','reconcile-import','step','reconcile','status')")
BOOTSTRAP=BOOTSTRAP.replace('tools.ingestion_readiness_patch_execution.operator_control_v2',ENTRY)
BOOTSTRAP=BOOTSTRAP.replace("control['execute'](entry,manifest,CASE,DELIVERY['controlSourceHash'],reader,sys.argv[1:])",
    "control['execute'](manifest,CASE,sys.argv[1:])")
BOOTSTRAP=BOOTSTRAP.replace("mode in('initialize','step','reconcile')","mode in('import-prefix','step','reconcile')")
BOOTSTRAP=BOOTSTRAP.replace('ouf.ingestion-readiness-patch-operator-result.v1','ouf.ingestion-readiness-stage8-continuation-result.v1')


def core(root,commit,pins):
    root=Path(root);payload,old=previous.core(root)
    sources={n:(root/loader.SOURCE_PATHS[n]).read_bytes()for n in loader.MODULES}
    for n,v in payload['sources'].items():
        if sources[n]!=v.encode():raise ValueError('ORIGINAL139_CONTINUATION_SOURCES_CHANGED')
    # V2's unchanged source carrier is additionally covered by its published
    # manifest. Check every one of its 144 modules, not only the old 139.
    oldcase=json.loads((root/'releases/ingestion-readiness-successor-runtime-case-20261022.json').read_bytes())
    for n,h in oldcase['qualification']['sourceHashes'].items():
        if previous.sha(sources[n])!=h:raise ValueError('ORIGINAL144_CONTINUATION_SOURCES_CHANGED')
    raw_loader=(root/'tools/ingestion_readiness_patch_execution/runtime_stage8.py').read_bytes()
    manifest=loader.declaration(commit,sources,raw_loader,pins)
    return {'loader':raw_loader.decode(),'sources':{n:v.decode()for n,v in sources.items()}},manifest


def generate(root,case,manifest):
    root=Path(root);case=json.loads(previous.encoded(case))
    payload,current=core(root,manifest['sourceCommit'],manifest['sourcePins'])
    control=(root/loader.SOURCE_PATHS[ENTRY]).read_bytes()
    if current!=manifest or previous.sha(control)!=case['controlSourceHash']or previous.sha(previous.encoded(manifest))!=case['nativeDeclarationHash']:
        raise ValueError('EXACT_STAGE8_CONTINUATION_DECLARATION_AND_CASE_REQUIRED')
    payload['controller']=control.decode()
    declaration={'schema':'ouf.ingestion-readiness-stage8-continuation-delivery.v1','nativeDeclaration':manifest,
        'caseHash':previous.sha(previous.encoded(case)),'controlSourceHash':previous.sha(control),
        'bootstrapHash':previous.sha(BOOTSTRAP.encode()),'runtimeAuthorityIssued':False}
    stream=io.BytesIO()
    with gzip.GzipFile(filename='',fileobj=stream,mode='wb',mtime=0)as compressed:compressed.write(previous.encoded(payload))
    packed=base64.b64encode(stream.getvalue()).decode()
    raw=('CASE='+repr(case)+'\nDELIVERY='+repr(declaration)+'\nDELIVERY_HASH='+repr(previous.sha(previous.encoded(declaration)))+
        '\nPACKED='+repr(packed)+'\nBOOTSTRAP='+repr(BOOTSTRAP)+'\nexec(compile(BOOTSTRAP,"<stage8-continuation>","exec"))\n').encode()
    if len(raw)>1048576:raise ValueError('BOUNDED_STAGE8_CONTINUATION_DELIVERY_REQUIRED')
    return raw,declaration


def launcher(raw):
    text=release.launcher('runtime',raw).decode()
    text=text.replace('preflight|approve|initialize|step|reconcile|status)',
        'preflight|approve|import-prefix|reconcile-import|step|reconcile|status)')
    text=text.replace('ouf-readiness-runtime.','ouf-stage8-continuation.')
    return text.encode()


def human_generate(root,case):
    from tools.governed_human_successor import auth_delivery
    from tools.ingestion_readiness_patch_execution import human_delivery_v2
    root=Path(root);case=json.loads(previous.encoded(case))
    payload,manifest=core(root,case['nativeDeclaration']['sourceCommit'],case['nativeDeclaration']['sourcePins'])
    if manifest!=case['nativeDeclaration']:raise ValueError('EXACT_STAGE8_HUMAN_NATIVE_MANIFEST_REQUIRED')
    entry='tools.ingestion_readiness_patch_execution.stage8_human';paths=dict(loader.SOURCE_PATHS)
    paths[entry]='tools/ingestion_readiness_patch_execution/stage8_human.py'
    if previous.sha((root/paths[entry]).read_bytes())!=case['governanceSourceHash']:
        raise ValueError('EXACT_STAGE8_HUMAN_GOVERNANCE_SOURCE_REQUIRED')
    raw,decl=auth_delivery.generate(root,case,{},entry=entry,bootstrap=human_delivery_v2.BOOTSTRAP,extra_paths=paths)
    if len(raw)>1048576:raise ValueError('BOUNDED_STAGE8_HUMAN_CAPSULE_REQUIRED')
    return raw,decl
