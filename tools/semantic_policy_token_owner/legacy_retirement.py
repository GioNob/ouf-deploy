"""Governed retirement component; no installer, credentials, grant or restart.

The caller must bind this module and its dependencies into the independently
reviewed executing closure. A chat design approval cannot invoke this component.
One durable command reservation survives crash and reapproval. Subsequent calls
only reconcile observed unit state; they never replay a consumed command.
"""
import fcntl
import os
import re
import stat
import subprocess
import tempfile
import uuid
import iam_binding_candidate as binding
import iam_governance_intake as governance
from cutover_authority import CutoverAuthority
from accounting_gap_session import boot_identity

UNITS=('ouf-policy-token@semantic.timer','ouf-policy-token@semantic.service')
HOST_HASH='93fa9bc8fe4d90fe445bb310363f11966f9ed89df74d169ad925cda0a157acc4'

def read_units():
    with tempfile.TemporaryFile() as output:
        result=subprocess.run(['/usr/bin/systemctl','show',*UNITS,'--no-pager',
            '--property=Id,LoadState,ActiveState,UnitFileState,MainPID'],stdin=subprocess.DEVNULL,
            stdout=output,stderr=subprocess.DEVNULL,timeout=10,
            env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
        output.seek(0);raw=output.read(8193)
    binding.require(result.returncode==0 and 0<len(raw)<=8192,'LEGACY_UNIT_READ_UNAVAILABLE')
    rows={}
    for block in raw.decode('ascii').strip().split('\n\n'):
        row={}
        for line in block.splitlines():
            key,sep,value=line.partition('=')
            binding.require(sep and key in {'Id','LoadState','ActiveState','UnitFileState','MainPID'}
                and key not in row,'LEGACY_UNIT_SCHEMA_DRIFT')
            row[key]=value
        binding.require({'Id','LoadState','ActiveState','UnitFileState'}<=set(row)
            and row['Id'] in UNITS and row['Id'] not in rows,'EXACT_LEGACY_UNITS_REQUIRED')
        rows[row['Id']]=row
    binding.require(set(rows)==set(UNITS),'EXACT_LEGACY_UNITS_REQUIRED')
    return rows

def quiescent(rows):
    return set(rows)==set(UNITS) and all(row.get('LoadState')=='masked'
        and row.get('UnitFileState')=='masked' and row.get('ActiveState')=='inactive'
        and row.get('MainPID', '0' if unit.endswith('.timer') else None)=='0'
        for unit,row in rows.items())

class LegacyRetirement:
    def __init__(self,authority,authority_raw,host_raw):
        binding.require(type(authority)is CutoverAuthority and type(authority_raw)is bytes,
            'CURRENT_TYPED_DUAL_ROLE_AUTHORITY_REQUIRED')
        binding.require(type(host_raw)is bytes and binding.sha(host_raw)==HOST_HASH,
            'EXACT_RETAINED_MIGRATION_HOST_HASH_REQUIRED')
        host=binding.decode(host_raw)
        binding.require(host.get('schema')=='ouf.policy-token-migration-host-inputs.v1'
            and host.get('legacyHistory')=={'state':'UNKNOWN','cumulativeGrantAttemptCount':None,
                'reconciled':False,'gapRemainsOpen':True}
            and host.get('runtimeAuthorityIssued')is False,'EXACT_UNKNOWN_HISTORY_HOST_INPUT_REQUIRED')
        logical=host.get('logicalOwnerScopeHash')
        binding.require(type(logical)is str and re.fullmatch('[0-9a-f]{64}',logical),
            'EXACT_LOGICAL_OWNER_SCOPE_REQUIRED')
        units=host.get('legacyUnitsMetadata')
        binding.require(type(units)is list and len(units)==2 and {u.get('Id') for u in units}==set(UNITS),
            'EXACT_RETAINED_LEGACY_UNITS_REQUIRED')
        self.host=host;self.host_raw=host_raw;self.authority=authority;self.raw=authority_raw
        self.scope={'schema':'ouf.policy-token-legacy-retirement-scope.v1',
            'hostInputsHash':HOST_HASH,'logicalOwnerScopeHash':logical,
            'sourceClosureHash':authority.expected['sourceClosureHash'],
            'operation':'MASK_AND_STOP_EXACT_LEGACY_UNITS','units':list(UNITS),
            'maximumCommandAttempts':1,'automaticUnmaskOrRestartAllowed':False}
        # Stable across host reviews, source versions, decisions and process IDs.
        self.operation=binding.sha(binding.encoded({'logicalOwnerScopeHash':logical,'units':list(UNITS),
            'operation':'FIRST_GOVERNED_LEGACY_RETIREMENT'}))
        self.name='policy-token-legacy-retirement-'+self.operation+'.private.json'
    def guard(self):
        binding.require(binding.sha(binding.encoded(self.host))==HOST_HASH,'HOST_INPUT_DRIFT')
        binding.require(binding.decode(self.raw).get('policyTokenLegacyRetirement')==self.scope,
            'EXPLICIT_SIGNED_LEGACY_RETIREMENT_SCOPE_REQUIRED')
        binding.require(self.authority(self.raw)is True,'CURRENT_HUMAN_AND_DUAL_ROLE_AUTHORITY_REQUIRED')
        binding.require(boot_identity()==self.host['kernelBootId'],'MIGRATION_BOOT_CHANGED')
        binding.require(governance.executable('/usr/bin/systemctl')==self.host['executables']['systemctl'],
            'SYSTEMCTL_EXECUTABLE_CHANGED')
    def run(self):
        self.guard()
        with binding.protected_parent() as directory:
            binding.require(binding.read_member(directory,'policy-token-migration-host-inputs-'+HOST_HASH+'.private.json')
                ==self.host_raw,'RETAINED_HOST_INPUT_CHANGED')
            lock=os.open(self.name+'.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600,dir_fd=directory)
            try:
                info=os.fstat(lock)
                binding.require(stat.S_ISREG(info.st_mode) and info.st_uid==info.st_gid==0
                    and stat.S_IMODE(info.st_mode)==0o600 and info.st_nlink==1,'RETIREMENT_FENCE_CUSTODY_REQUIRED')
                fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                seal=binding.identity(info)
                def fence():
                    binding.require(seal==binding.identity(os.fstat(lock))
                        ==binding.identity(os.stat(self.name+'.lock',dir_fd=directory,follow_symlinks=False)),
                        'RETIREMENT_FENCE_CHANGED')
                def save(row,first=False):
                    fence();raw=binding.encoded(row);name=self.name if first else '.'+self.name+'.'+uuid.uuid4().hex
                    fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
                    try:
                        with os.fdopen(os.dup(fd),'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
                        fence()
                        if not first:os.replace(name,self.name,src_dir_fd=directory,dst_dir_fd=directory)
                        os.fsync(directory)
                        binding.require(binding.read_member(directory,self.name)==raw,'RETIREMENT_PUBLICATION_UNPROVEN')
                    finally:os.close(fd)
                try:row=binding.decode(binding.read_member(directory,self.name))
                except FileNotFoundError:row=None
                self.guard();fence();observed=read_units()
                if row is not None:
                    binding.require(set(row)=={'schema','operation','scope','commandAttemptConsumed','state','version'}
                        and row['schema']=='ouf.policy-token-legacy-retirement.v1' and row['operation']==self.operation
                        and row['scope']==self.scope and row['commandAttemptConsumed']is True
                        and type(row['version'])is int and row['version']>=0
                        and row['state']in {'COMMAND_RESERVED_OUTCOME_UNPROVEN','QUIESCENCE_OBSERVED'},
                        'RETAINED_RETIREMENT_DRIFT')
                    binding.require(quiescent(observed),'RETIREMENT_RECONCILIATION_REQUIRED_NO_COMMAND_REPLAY')
                else:
                    baseline={u['Id']:u for u in self.host['legacyUnitsMetadata']}
                    binding.require(observed==baseline,'LEGACY_UNIT_BASELINE_CHANGED')
                    self.guard();fence()
                    row={'schema':'ouf.policy-token-legacy-retirement.v1','operation':self.operation,'scope':self.scope,
                        'commandAttemptConsumed':True,'state':'COMMAND_RESERVED_OUTCOME_UNPROVEN','version':0}
                    save(row,first=True)
                    self.guard();fence()
                    # Any timeout/nonzero/crash leaves the durable reservation.
                    # No automatic retry or rollback can re-enable the writer.
                    result=subprocess.run(['/usr/bin/systemctl','mask','--now',*UNITS],stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=20,
                        env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
                    binding.require(result.returncode==0,'RETIREMENT_COMMAND_OUTCOME_REQUIRES_RECONCILIATION')
                    observed=read_units()
                    binding.require(quiescent(observed),'RETIREMENT_QUIESCENCE_UNPROVEN')
                self.guard();fence()
                if row['state']!='QUIESCENCE_OBSERVED':
                    row.update(state='QUIESCENCE_OBSERVED',version=row['version']+1);save(row)
                return dict(row)
            finally:os.close(lock)
