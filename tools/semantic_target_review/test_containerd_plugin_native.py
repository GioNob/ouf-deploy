"""Read an actual disposable containerd's plugin exports; no Docker/start."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

engine=Path(os.environ['OUF_PLUGIN_ENGINE_DIRECTORY']).resolve()
with tempfile.TemporaryDirectory(prefix='ouf-plugin-read-',dir='/root') as directory:
    root=Path(directory);config=root/'containerd.toml';config.write_text('version = 2\n')
    socket=root/'containerd.sock';state=root/'state'
    with (root/'daemon.log').open('wb') as log:
        daemon=subprocess.Popen([str(engine/'containerd'),'--config',str(config),'--root',str(root/'storage'),
            '--state',str(state),'--address',str(socket)],stdout=log,stderr=log)
        try:
            deadline=time.monotonic()+15
            while not socket.exists():
                assert daemon.poll() is None and time.monotonic()<deadline
                time.sleep(0.1)
            ctr=str(engine/'ctr')
            help_text=subprocess.check_output([ctr,'plugins','info','--help'],timeout=5).decode()
            args=[ctr,'--address',str(socket),'plugins','info']+(
                ['--type','io.containerd.runtime.v2','--id','task'] if '--type' in help_text and '--id' in help_text
                else ['io.containerd.runtime.v2','task'])
            value=json.loads(subprocess.check_output(args,timeout=5));plugin=value.get('plugin',value)
            assert plugin.get('type',plugin.get('Type'))=='io.containerd.runtime.v2'
            assert plugin.get('id',plugin.get('ID'))=='task'
            exports=plugin.get('exports',plugin.get('Exports',{}))
            assert exports['state']==str(state/'io.containerd.runtime.v2.task')
            assert exports['root']==str(root/'storage/io.containerd.runtime.v2.task')
            print('OUF_PLUGIN_NATIVE_READ=PASS ACTUAL_SERVER_EXPORTS=true LIFECYCLE_OPERATIONS=0 TARGET_AUTHORITY=false')
        finally:
            daemon.terminate()
            try:daemon.wait(timeout=5)
            except subprocess.TimeoutExpired:daemon.kill();daemon.wait()
