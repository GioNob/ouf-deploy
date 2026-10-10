"""Try only this pinned read with noninteractive sudo; never prompt in CI."""
import hashlib,json,pathlib,subprocess,sys
READ_HASH='7daf8e08eb530fe8a89fb56e93386c1d995679a4edff7005ed120ff8e92996dc'
READER_HASH='b9ea8aa1a8cf31d28dfa1df0960dcf6930880d11244fe1f84e710bfe0b9ec4cf'
BOOTSTRAP='''
import hashlib,pathlib,sys
sources=[]
for path,expected in zip(sys.argv[1:],("7daf8e08eb530fe8a89fb56e93386c1d995679a4edff7005ed120ff8e92996dc","b9ea8aa1a8cf31d28dfa1df0960dcf6930880d11244fe1f84e710bfe0b9ec4cf")):
    with pathlib.Path(path).open("rb") as stream:raw=stream.read(131073)
    if len(raw)>131072 or hashlib.sha256(raw).hexdigest()!=expected:raise SystemExit("OUF_R9_READ_DELIVERY_HASH_MISMATCH")
    sources.append(raw)
if len(sources)!=2:raise SystemExit("OUF_R9_READ_EXACT_SOURCE_PAIR_REQUIRED")
p=sys.argv[1];sys.argv=[p]
exec(compile(sources[0],p,"exec"),{"__name__":"__main__","__file__":p,"__reader_source_bytes__":sources[1]})
'''
def main():
    here=pathlib.Path(__file__).resolve().parent
    paths=[here/'read_current_r9_transition.py',here/'read_cutover_inputs.py']
    for path,expected in zip(paths,(READ_HASH,READER_HASH)):
        if hashlib.sha256(path.read_bytes()).hexdigest()!=expected:raise SystemExit('OUF_R9_READ_DELIVERY_HASH_MISMATCH')
    result=subprocess.run(['/usr/bin/sudo','-n','/usr/bin/python3','-I','-B','-c',BOOTSTRAP,*map(str,paths)],capture_output=True,timeout=90)
    lines=result.stdout.decode(errors='replace').splitlines()
    reports=[line for line in lines if line.startswith('OUF_CURRENT_R9_TRANSITION_READ=')]
    if reports:
        for line in reports:print(line)
        return result.returncode
    reason=result.stderr.decode(errors='replace').lower()
    if result.returncode and any(term in reason for term in ('password is required','not allowed to execute','may not run sudo','a terminal is required','not in the sudoers')):
        print('OUF_CURRENT_R9_TRANSITION_ACCESS='+json.dumps({'status':'OPERATOR_SUDO_REQUIRED','readOnly':True,'targetApplied':False,'automaticPrivilegeChange':False}))
        return 0
    print('OUF_CURRENT_R9_TRANSITION_ACCESS='+json.dumps({'status':'PINNED_READ_EXECUTION_UNPROVEN','exitCode':result.returncode,'stdoutSha256':hashlib.sha256(result.stdout).hexdigest(),'stderrSha256':hashlib.sha256(result.stderr).hexdigest()}))
    return 1
if __name__=='__main__':raise SystemExit(main())
