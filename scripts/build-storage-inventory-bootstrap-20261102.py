#!/usr/bin/env python3
"""Bind the qualified delivery manifest and immutable publication to its launcher."""
import ast,json,re,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def build(delivery,publication):
 assert re.fullmatch('[a-f0-9]{40}',publication)
 template=(ROOT/'tools/storage_migration/inventory_bootstrap.py').read_text()
 assert template.count('DELIVERY=None')==template.count('PUBLICATION=None')==1
 script=template.replace('DELIVERY=None','DELIVERY='+repr(delivery)).replace('PUBLICATION=None','PUBLICATION='+repr(publication))
 ast.parse(script);return '#!/usr/bin/env python3\n'+script
if __name__=='__main__':
 raw=build(json.loads(Path(sys.argv[1]).read_text()),sys.argv[2]);Path(sys.argv[3]).write_text(raw)
