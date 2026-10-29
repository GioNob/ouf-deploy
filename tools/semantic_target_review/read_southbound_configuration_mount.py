"""Docker mount metadata only: never open APISIX config or any TLS/key file."""
import json,os,subprocess,tempfile
from pathlib import Path
CID='1fc5ae6a0db4600e0124bb1f9d2998780d533fd2b4de7cb086d8675b6afb5916'
SOURCE='/etc/ouf/deploy-snapshots/semantic-provider-v2-inputs-XE7IwlGm/config.yaml'
report={'schema':'ouf.discovery.southbound-configuration-mount-read.v1','containerLifecycleOperations':0,'configurationFilesOpened':0,'privateKeyFilesOpened':0,'existingConfigurationWrites':0,'r9Touched':False,'notReleaseAcceptance':True}
try:
    with tempfile.TemporaryDirectory(prefix='ouf-southbound-mount-read-',dir=Path.home()) as d:
        def read():
            p=subprocess.run(['/usr/bin/docker','--config',d,'inspect','--type','container',CID],capture_output=True,timeout=15,env={'PATH':'/usr/bin:/bin','DOCKER_HOST':'unix:///var/run/docker.sock'})
            if p.returncode or len(p.stdout)>2000000 or len(p.stderr)>131072:raise ValueError('BOUNDED_DOCKER_METADATA_UNPROVEN')
            v=json.loads(p.stdout)[0];mounts=[m for m in v['Mounts'] if m.get('Destination')=='/usr/local/apisix/conf/config.yaml']
            if not (v['Id']==CID and v['Image']=='sha256:c15541037a08276e36715a3c3798c2d07fe6faabf5547d3885a66cd10575e366' and v['State']['Running'] is True and len(mounts)==1 and mounts[0]['Type']=='bind' and mounts[0]['Source']==SOURCE and mounts[0]['RW'] is False):raise ValueError('EXACT_CURRENT_READ_ONLY_CONFIGURATION_MOUNT_UNPROVEN')
            return {'imageId':v['Image'],'generation':{k:v['State'][k] for k in ('Pid','StartedAt','Running')},'mount':mounts[0]}
        if read()!=read():raise ValueError('MOUNT_METADATA_CHANGED_DURING_READ')
    report.update(status='EXACT_READ_ONLY_APISIX_CONFIGURATION_MOUNT_CAPTURED',sourceMatchesPreparedStartupInputs=True,certificateMountedSeparatelyRequired=False);code=0
except Exception as error:
    report.update(status='MOUNT_METADATA_READ_BLOCKED',reason=str(error) if type(error) is ValueError else 'MOUNT_METADATA_UNPROVEN');code=1
print('OUF_SOUTHBOUND_CONFIGURATION_MOUNT='+json.dumps(report,sort_keys=True));raise SystemExit(code)
