"""CI only: probe system nft in a fresh namespace, no target binding."""
import hashlib
import json
import os
from pathlib import Path
import shutil
from probe_installed_nft_units import prove

assert os.geteuid()==0
binary=str(Path(shutil.which('nft')).resolve())
result=prove(binary,hashlib.sha256(Path(binary).read_bytes()).hexdigest())
print('CI_ISOLATED_NFT_UNIT_PROBE='+json.dumps(result,sort_keys=True))
