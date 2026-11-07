"""New exact candidate; retain the original Registry fixture selection unchanged."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from qualify_m2_discovery_frame_native import main

if __name__ == '__main__':
    assert len(sys.argv) == 3
    main(Path(sys.argv[1]), Path(sys.argv[2]), package_binding={
        'recordSha256': '5beb010a21367e9fae1556a5ee9836082db42a3cebc550bc23eb01525e4f10aa',
        'imageId': 'sha256:a6f00cda30f1c570082c94cb49d5564f40d512758441f6b6eac75e21f423d14f',
        'sourceCommit': 'c2dae77b42f1811b704465f6ab813c91d808ade4',
        'archiveSha256': '7f6482b79589fd1063eaf96508ea948d6411a7b4f0dbe76d663746a08953a223'})
