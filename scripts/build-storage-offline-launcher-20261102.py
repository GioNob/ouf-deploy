#!/usr/bin/env python3
import ast,json,re,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def build(delivery,publication):
 assert re.fullmatch('[a-f0-9]{40}',publication)
 template=(ROOT/'tools/storage_planning/offline_bootstrap_20261102.py').read_text()
 assert template.count('DELIVERY=None')==template.count('PUBLICATION=None')==1
 result='#!/usr/bin/env python3\n'+template.replace('DELIVERY=None','DELIVERY='+repr(delivery)).replace('PUBLICATION=None','PUBLICATION='+repr(publication));ast.parse(result);return result
if __name__=='__main__':Path(sys.argv[3]).write_text(build(json.loads(Path(sys.argv[1]).read_text()),sys.argv[2]))
