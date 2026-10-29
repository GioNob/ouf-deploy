"""Read only metadata of the three already proposed protected roots.

No token, secret, key, journal content, directory member names, command line or
environment is read. This observation is not IAM or runtime acceptance.
"""
import json
import os
import stat
import subprocess

ROOTS={
    'reviewedCode':'/usr/local/libexec/ouf-policy-token',
    'ownerCredential':'/etc/ouf/policy-token/credentials/semantic',
    'durableRecovery':'/var/lib/ouf/policy-token/semantic',
}
UNITS=('ouf-policy-token@semantic.service','ouf-policy-token@semantic.timer')

def observe(path):
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);rows=[]
    try:
        for depth,name in enumerate(path.strip('/').split('/'),1):
            try:s=os.stat(name,dir_fd=fd,follow_symlinks=False)
            except FileNotFoundError:return {'state':'ABSENT','depth':depth,'ancestors':rows,'custodyAccepted':False}
            value={'depth':depth,'uid':s.st_uid,'gid':s.st_gid,'modeOctal':format(stat.S_IMODE(s.st_mode),'04o'),
                   'directory':stat.S_ISDIR(s.st_mode),'symlink':stat.S_ISLNK(s.st_mode)}
            rows.append(value)
            if not value['directory'] or value['symlink']:
                return {'state':'NON_DIRECTORY_OR_SYMLINK','depth':depth,'ancestors':rows,'custodyAccepted':False}
            child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            actual=os.fstat(child);again=os.stat(name,dir_fd=fd,follow_symlinks=False)
            if any((x.st_dev,x.st_ino,x.st_uid,x.st_gid,x.st_mode)!=(s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode) for x in (actual,again)):
                os.close(child);raise RuntimeError('NAMED_DIRECTORY_CHANGED')
            os.close(fd);fd=child
        protected=all(x['uid']==x['gid']==0 and not int(x['modeOctal'],8)&0o022 for x in rows)
        return {'state':'PRESENT','ancestors':rows,'rootAncestryProtected':protected,'leafMode0700':stat.S_IMODE(os.fstat(fd).st_mode)==0o700,
                'directoryIdentity':{'device':os.fstat(fd).st_dev,'inode':os.fstat(fd).st_ino},'custodyAccepted':False}
    finally:os.close(fd)

def main():
    if os.geteuid()!=0:raise SystemExit('phase=ROOT_METADATA reason=ROOT_EXECUTION_REQUIRED')
    result={'schema':'ouf.policy-token-protected-scope-observation.v1','status':'METADATA_OBSERVED_NOT_ACCEPTED',
            'roots':{},'units':[],'secretOrJournalContentReads':0,'providerCalls':0,'serviceMutations':0,
            'protectedFileWrites':0,'r12Touched':False,'budgetReset':False,'runtimeAuthorityIssued':False,'notReleaseAcceptance':True}
    for role,path in ROOTS.items():
        try:result['roots'][role]=observe(path)
        except Exception as error:result['roots'][role]={'state':'UNPROVEN','phase':'ROOT_METADATA','reason':type(error).__name__,'errno':getattr(error,'errno',None),'custodyAccepted':False}
    try:
        response=subprocess.run(['/usr/bin/systemctl','show',*UNITS,'--no-pager','--property=Id,LoadState,ActiveState,UnitFileState,MainPID'],
            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=5,
            env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
        if response.returncode or len(response.stdout)>8192:raise RuntimeError('UNIT_METADATA_UNAVAILABLE')
        for block in response.stdout.decode('ascii').strip().split('\n\n'):
            row={}
            for line in block.splitlines():
                key,separator,value=line.partition('=')
                if not separator or key not in ('Id','LoadState','ActiveState','UnitFileState','MainPID') or key in row:raise ValueError('UNIT_METADATA_SCHEMA')
                if key=='Id' and value not in UNITS:raise ValueError('UNIT_SCOPE_DRIFT')
                if key in ('LoadState','ActiveState','UnitFileState') and not value.replace('-','').isalnum():raise ValueError('UNIT_STATE_FORMAT')
                if key=='MainPID' and not value.isdecimal():raise ValueError('UNIT_PID_FORMAT')
                row[key]=value
            if row.get('Id') not in UNITS:raise ValueError('UNIT_SCOPE_DRIFT')
            result['units'].append(row)
    except Exception as error:
        allowed={'UNIT_METADATA_UNAVAILABLE','UNIT_METADATA_SCHEMA','UNIT_SCOPE_DRIFT','UNIT_STATE_FORMAT','UNIT_PID_FORMAT'}
        reason=str(error) if type(error) in (ValueError,RuntimeError) and str(error) in allowed else type(error).__name__
        result['unitObservation']={'phase':'LEGACY_WRITER_METADATA','reason':reason,'state':'UNPROVEN'}
    print(json.dumps(result,sort_keys=True,separators=(',',':')))

if __name__=='__main__':main()
