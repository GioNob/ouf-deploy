"""Fixed diagnostic entrypoint. Preserve mismatches; no acceptance or repair."""
import sys
import json
import re
import traceback
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parent))
from compare_provider_v2_stopped_rootfs import main

if __name__=='__main__':
    try:main(diagnose=True)
    except Exception as error:
        reason=str(error) if isinstance(error,ValueError) and re.fullmatch('[A-Z_]{1,100}',str(error)) else None
        detail={'status':'BLOCKED','errorClass':type(error).__name__,'reason':reason,
            'errno':getattr(error,'errno',None),'commandReturnCode':getattr(error,'returncode',None),
            'callChain':[{'function':frame.name,'line':frame.lineno} for frame in traceback.extract_tb(error.__traceback__)[-6:]],
            'rawValuesPrinted':False,'repeatPreparationRequired':False}
        print('OUF_ROOTFS_DIAGNOSIS='+json.dumps(detail,sort_keys=True),flush=True)
        raise SystemExit(1)
