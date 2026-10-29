"""CI-only fake review. Never contacts OUF, IAM, SQL, Engine or production UUIDs."""
import hashlib
import importlib.util
import json
import os
import shutil
from pathlib import Path
import sys
import tempfile
import termios
import time

ROOT=Path(__file__).resolve().parents[2]
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
legacy=module('legacy_review',ROOT/'scripts/publish-existing-descriptor-draft-20261025.py')
terminal=module('new_review',ROOT/'tools/human_terminal_line_review.py')
mode,case,report=sys.argv[1:]
if mode=='continuation':legacy=module('continuation_review',ROOT/'scripts/continue-existing-descriptor-publication-editable-20261026.py')
legacy.DRAFT_ID='00000000-0000-4000-8000-000000000050'
plan={'nonce':case,'expiresAt':time.time()+2,'baselineGrantCount':106,'countsAtReview':dict(legacy.INHERITED)}
review_hash=legacy.digest(plan)
deadline=time.monotonic()+2
before=termios.tcgetattr(0)
result={'schema':'CI_SYNTHETIC_REVIEW_ONLY','mode':mode,'case':case,'accepted':False,'terminalRestored':False,
        'root':os.geteuid()==0,'stdinIsTTY':os.isatty(0),'states':[],
        'stdinForeground':os.tcgetpgrp(0)==os.getpgrp()}
control=os.open('/dev/tty',os.O_RDONLY|os.O_NOCTTY)
try:
    result['controlForeground']=os.tcgetpgrp(control)==os.getpgrp()
    control_before=termios.tcgetattr(control)
finally:os.close(control)
def guard():
    if time.monotonic()>=deadline:raise TimeoutError('CI_TIMEOUT')
def emit(value):
    print(value,flush=True)
    if value=='Conferma:':print('CI_PROMPT_READY',flush=True)
print('CI_HASH='+review_hash,flush=True)
tmp=tempfile.mkdtemp()
log=None
try:
    if True:
        journal=legacy.Journal(Path(tmp)/'ci-review')
        if mode=='continuation':log=legacy.OperatorLog(journal)
        transport=legacy.Transport('CI_SYNTHETIC_TOKEN',journal);transport.deadline=deadline
        if mode in ('legacy','continuation'):
            legacy.approve(plan,journal,transport,emit=emit)
        else:
            print('CI_PROMPT_READY',flush=True)
            terminal.read_exact(review_hash,guard,emit=emit,progress=result['states'].append,heartbeat=.25)
        result['accepted']=True
        result['ttyInput']=journal.row.get('ttyInput')
except BaseException as error:
    result['errorType']=type(error).__name__
    result['reason']=str(error)
    if 'journal' in globals():result['ttyInput']=journal.row.get('ttyInput')
finally:
    control=os.open('/dev/tty',os.O_RDONLY|os.O_NOCTTY)
    try:result['terminalRestored']=termios.tcgetattr(0)==before and termios.tcgetattr(control)==control_before
    finally:os.close(control)
    if log is not None:
        print('CI_OPERATOR_LOG_FINAL_MARKER',flush=True)
        log.close()
        result['operatorLogPrivate']=log.path.stat().st_mode&0o777==0o600
        result['operatorLogHasResult']='CI_OPERATOR_LOG_FINAL_MARKER' in log.path.read_text()
    Path(report).write_text(json.dumps(result));os.chmod(report,0o644)
    print('CI_SYNTHETIC_RESULT='+json.dumps(result),flush=True)
    shutil.rmtree(tmp)
