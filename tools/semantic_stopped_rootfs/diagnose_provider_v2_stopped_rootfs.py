"""Fixed diagnostic entrypoint. Preserve mismatches; no acceptance or repair."""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parent))
from compare_provider_v2_stopped_rootfs import main

if __name__=='__main__':
    try:main(diagnose=True)
    except Exception:
        print('OUF_ROOTFS_DIAGNOSIS=BLOCKED NO_RAW_OUTPUT=true',flush=True)
        raise SystemExit(1)
