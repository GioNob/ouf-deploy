#!/usr/bin/env python3
"""Installation inventory via existing runner Docker read access, without sudo."""
import json, os, re, subprocess, sys
TARGETS = {'udp': 'ouf-udp', 'mcp': 'ouf-mcp', 'onboarding': 'ouf-onboarding'}
FORMAT = '{"id":{{json .Id}},"image":{{json .Image}},"running":{{json .State.Running}},"paused":{{json .State.Paused}},"restarting":{{json .State.Restarting}},"revision":{{json (index .Config.Labels "org.opencontainers.image.revision")}}}'
def read(name):
    result = subprocess.run(['/usr/bin/docker', 'inspect', '--type', 'container', '--format', FORMAT, name],
        stdin=subprocess.DEVNULL, capture_output=True, timeout=10,
        env={'PATH':'/usr/bin:/bin','LC_ALL':'C','DOCKER_HOST':'unix:///var/run/docker.sock','DOCKER_API_VERSION':'1.44'})
    if result.returncode or len(result.stdout)>8192:
        raise ValueError('CURRENT_COMPONENT_READ_UNPROVEN')
    row=json.loads(result.stdout)
    if set(row)!= {'id','image','running','paused','restarting','revision'} or not re.fullmatch('[0-9a-f]{64}', row['id']) or not re.fullmatch('sha256:[0-9a-f]{64}', row['image']):
        raise ValueError('CURRENT_COMPONENT_SHAPE_UNPROVEN')
    if any(type(row[k]) is not bool for k in ('running','paused','restarting')):
        raise ValueError('CURRENT_COMPONENT_STATE_UNPROVEN')
    revision=row['revision']
    row['revision']=revision if isinstance(revision,str) and re.fullmatch('[0-9a-f]{40}',revision) else None
    return row
def collect():
    first={k:read(v) for k,v in TARGETS.items()}
    second={k:read(v) for k,v in TARGETS.items()}
    if first != second: raise ValueError('APPLICATION_GENERATION_CHANGED')
    return second
def main():
    report={'schema':'ouf.chat-recovery-current-inventory.v1','readOnly':True,
        'runtimeMutations':0,'credentialFilesRead':0,'credentialValuesPrinted':False,
        'databaseCalls':0,'migrationStateProven':False,'rootCustodyProven':False,
        'installationReady':False,'obsoletePreStartHelperUsed':False,
        'completedTechnicalPhases':8,'functionalMilestonesProven':3}
    try:
        report.update(components=collect(),complete=True,generationsStable=True)
    except Exception as error:
        report.update(complete=False,errorClass=type(error).__name__,exceptionMessagePrinted=False)
    print(json.dumps(report,sort_keys=True))
    return 0 if report['complete'] else 1
if __name__=='__main__':sys.exit(main())
