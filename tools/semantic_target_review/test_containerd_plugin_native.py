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
            raw=subprocess.check_output([ctr,'--address',str(socket),'plugins','ls','--detailed',
                'type==io.containerd.runtime.v2,id==task'],timeout=5).decode()
            print('CI_PUBLIC_PLUGIN_METADATA_BEGIN\n'+raw+'CI_PUBLIC_PLUGIN_METADATA_END')
            assert str(state/'io.containerd.runtime.v2.task') in raw
            assert str(root/'storage/io.containerd.runtime.v2.task') in raw
            print('OUF_PLUGIN_NATIVE_READ=PASS ACTUAL_SERVER_EXPORTS=true CONTAINER_OPERATIONS=0 DISPOSABLE_CI_DAEMON=true TARGET_AUTHORITY=false')
        finally:
            daemon.terminate()
            try:daemon.wait(timeout=5)
            except subprocess.TimeoutExpired:daemon.kill();daemon.wait()
