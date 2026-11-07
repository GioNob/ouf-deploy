"""Exercise the real keytool merge with a synthetic CA and the local JDK's public roots."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('switch', Path(sys.argv[1]))
s = importlib.util.module_from_spec(spec); spec.loader.exec_module(s)

with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
    root = Path(tmp).resolve()
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                    '-subj', '/CN=OUF synthetic CA/', '-addext', 'basicConstraints=critical,CA:TRUE',
                    '-keyout', str(root / 'synthetic.key'), '-out', str(root / 'ca.pem')],
                   check=True, capture_output=True)
    folder = root / 'application'; folder.mkdir()
    def local_exec(*args, data=None, timeout=25, checked=True):
        assert args[0] == 'exec'
        index = 2 if args[1] == '-i' else 1
        assert args[index] == 'synthetic-container'
        command = list(args[index+1:])
        command = [str(root / Path(a).name) if a.startswith('/tmp/ouf-seaweedfs-trust-') else a for a in command]
        result = subprocess.run(command, input=data, capture_output=True, timeout=timeout)
        if checked:
            assert result.returncode == 0, 'local keytool subprocess failed'
        return result
    report = {}
    with patch.object(s, 'docker', local_exec):
        s.prepare_truststore({'Id': 'synthetic-container'}, folder, (root / 'ca.pem').read_bytes(), report)
    assert report['existingTrustCertificatesPreserved'] and report['privateCaAdded']
    assert report['temporaryTruststoreRemoved'] and (folder / 'truststore.p12').is_file()
    assert not list(root.glob('ouf-seaweedfs-trust-*.p12'))
    print('PASS: real local keytool retained', report['existingTrustCertificates'],
          'existing certificates, added one synthetic CA, and removed the temporary store.')
    print('Scope: local JDK keytool only; VPS image and Docker execution remain untested here.')
