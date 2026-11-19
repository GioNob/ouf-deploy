#!/usr/bin/env python3
"""CI-only packaging after independent original-byte and publisher verification."""
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('runtime_image', ROOT/'tools/storage_security/runtime_image.py')
image = importlib.util.module_from_spec(spec); spec.loader.exec_module(image)


def main():
    image.require(os.environ.get('GITHUB_ACTIONS') == 'true', 'CI_ONLY')
    # The preceding unchanged reader authenticates the full archive checksums,
    # upstream Git blobs/modes, dependency patch and all old source closures.
    original = ROOT/'sw-readback'
    publisher = json.loads((original/'publisher-verification.json').read_bytes())
    image.require(isinstance(publisher, list) and bool(publisher), 'PUBLISHER_VERIFICATION_REQUIRED')
    with zipfile.ZipFile(original/'original.zip') as z:
        binary = z.read('bin/weed')
        with tarfile.open(fileobj=io.BytesIO(z.read('source.tar'))) as source:
            licence = source.extractfile('LICENSE').read()
    record = image.write_image(binary, licence, ROOT/'storage-runtime-image')
    print(json.dumps(record, indent=2))


if __name__ == '__main__':
    main()
