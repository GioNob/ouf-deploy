"""CI-only fake review. Never contacts OUF, IAM, SQL, Engine or production UUIDs."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import termios
import time

ROOT=Path(__file__).resolve().parents[2]
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
legacy=module('legacy_review',ROOT/'scripts/publish-existing-descriptor-draft-20261025.py')
terminal=module('new_review',ROOT/'tools/human_terminal_review.py')
mode,case,report=sys.argv[1:]
plan={'nonce':case,'expiresAt':time.time()+2,'baselineGrantCount':106,'countsAtReview':dict(legacy.INHERITED)}
review_hash=legacy.digest(plan)
deadline=time.monotonic()+2
before=termios.tcgetattr(0)
result={'schema':'CI_SYNTHETIC_REVIEW_ONLY','mode':mode,'case':case,'accepted':False,'terminalRestored':False,
        'root':os.geteuid()==0,'stdinIsTTY':os.isatty(0),'states':[]}
def guard():
    if time.monotonic()>=deadline:raise TimeoutError('CI_TIMEOUT')
def emit(value):
    print(value,flush=True)
    if value=='Conferma:':print('CI_PROMPT_READY',flush=True)
print('CI_HASH='+review_hash,flush=True)
try:
    with tempfile.TemporaryDirectory() as tmp:
        journal=legacy.Journal(Path(tmp)/'ci-review')
        transport=legacy.Transport('CI_SYNTHETIC_TOKEN',journal);transport.deadline=deadline
        if mode=='legacy':
            legacy.approve(plan,journal,transport,emit=emit)
        else:
            print('CI_PROMPT_READY',flush=True)
            terminal.read_exact(review_hash,guard,emit=emit,progress=result['states'].append,heartbeat=.25)
        result['accepted']=True
except BaseException as error:
    result['errorType']=type(error).__name__
finally:
    result['terminalRestored']=termios.tcgetattr(0)==before
    Path(report).write_text(json.dumps(result));os.chmod(report,0o644)
    print('CI_SYNTHETIC_RESULT='+json.dumps(result),flush=True)
