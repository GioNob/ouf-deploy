"""CI-only integrated MCP prompt/logger. No authority/signing/runtime calls."""
import hashlib,importlib.util,json,os,sys,tempfile,termios,time,types
from pathlib import Path
BASE=Path(__file__).resolve().parents[2]
def module(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
entry=module('mcp_entry_probe',BASE/'scripts/apply-mcp-diagnostic-update-20261026.py')
terminal=module('mcp_terminal_probe',BASE/'tools/human_terminal_line_review.py')
core=module('mcp_authority_probe',BASE/'tools/mcp_diagnostic_update/authority.py')
case,report=sys.argv[1:];before=termios.tcgetattr(0);states=[];original=terminal.read_exact
def bounded(reviewed,guard,*,emit,progress):
    # Additional CI ceiling only; the real review's900s/hash/counters unchanged.
    deadline=time.monotonic()+2
    def check():
        guard()
        if time.monotonic()>=deadline:raise TimeoutError('CI_ONLY_INPUT_WINDOW')
    return original(reviewed,check,emit=emit,progress=progress,heartbeat=.25)
terminal.read_exact=bounded
with tempfile.TemporaryDirectory(prefix='ouf-ci-mcp-tty-')as directory:
    root=Path(directory);plan={'schema':'CI_SYNTHETIC_REVIEW_ONLY','case':case,'counts':{'retained':306},'deadlineNeverExtended':True};reviewed=core.digest(plan)
    (root/'review.json').write_bytes(core.encoded(plan));(root/'review.json').chmod(0o400)
    ctx=types.SimpleNamespace(core=core,root=root,terminal=terminal,check_sources=lambda:None,evidence=lambda name,row:states.append(row),read=lambda path,expected:json.loads(Path(path).read_bytes())if hashlib.sha256(Path(path).read_bytes()).hexdigest()==expected else(_ for _ in()).throw(ValueError('CI_REVIEW_CHANGED')))
    ctx.case={'priorPreflight':{'synthetic':True}};ctx.proposal={'mcpReplacement':{'request':{'HostConfig':{'Memory':0}}}}
    original_plan=(root/'review.json').read_bytes();log=root/'operator.log';logger=entry.Logger(log);sys.stdout=logger;accepted=False;reason=None
    try:decision=entry.terminal(ctx,plan);accepted=True;assert decision['reviewHash']==reviewed
    except BaseException as error:reason=str(error)
    finally:
        logger.flush();sys.stdout=logger.original;logger.file.close()
        result={'schema':'ouf.synthetic-mcp-terminal-ci.v1','case':case,'accepted':accepted,'reason':reason,'root':os.geteuid()==0,'stdinIsTTY':os.isatty(0),'foreground':os.tcgetpgrp(0)==os.getpgrp(),'terminalRestored':termios.tcgetattr(0)==before,'operatorLogPrivate':log.stat().st_mode&0o777==0o600,'operatorLogHasPrompt':('APPROVO '+reviewed)in log.read_text(),'privateReviewAndCountsUnchanged':(root/'review.json').read_bytes()==original_plan,'states':states,'productionAuthorityIssued':False}
        Path(report).write_text(json.dumps(result));os.chmod(report,0o644)
        print('CI_RESULT='+json.dumps(result),flush=True)
