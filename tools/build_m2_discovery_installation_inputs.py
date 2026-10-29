"""Standalone reference reader, reusing unchanged qualified capture primitives."""
from pathlib import Path
import importlib.util
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('qualified_binding_builder',ROOT/'tools/build_m2_discovery_bindings.py')
parent=importlib.util.module_from_spec(spec);spec.loader.exec_module(parent)
definitions,parent_build=parent.definitions,parent.build


def build():
    code='''#!/usr/bin/env python3
"""Finite installation reference inventory. No configuration/credential content or effects."""
import copy,hashlib,http.client,json,os,pwd,re,signal,socket,stat,struct,sys,time
from pathlib import Path
from urllib.parse import urlsplit
MAXIMUMS={'engineGets':9,'privateMetadataReads':3,'responseBytes':2097152,'totalBytes':25165824,'seconds':90}
'''
    code+=definitions('tools/managed_csv_recovery/retained_inputs.py',
                     ('Stop','require','encoded','digest','decode','frame','ancestry','Capture','process_pin','stable_binding','Engine'))
    code+=definitions('scripts/read-managed-profile-ths-scopes-20261028.py',('Logger',))
    code+=(ROOT/'tools/m2_discovery_installation_inputs/inventory.py').read_text()+'\n'
    main=parent_build().split('\ndef main():',1)[1]
    main=main.replace("c=Capture(CASE['outputRoot'],13)","c=Capture(CASE['outputRoot'],4)")
    main=main.replace('result=capture_bindings(c)','result=installation_inputs(c)')
    main=main.replace('ouf.m2-discovery-current-bindings-result.v1','ouf.m2-discovery-installation-inputs-result.v1')
    main=main.replace('ISOLATED_OUFADMIN_BINDING_CAPTURE_REQUIRED','ISOLATED_OUFADMIN_INSTALLATION_INPUTS_REQUIRED')
    main=main.replace('M2_BINDING_CAPTURE_CONSUMED_NO_REPLAY','M2_INSTALLATION_INPUT_SCOPE_CONSUMED_NO_REPLAY')
    main=main.replace('PRIVATE_M2_BINDING_CAPTURE_FAILURE_RECONCILE','PRIVATE_M2_INSTALLATION_INPUTS_FAILURE_RECONCILE')
    main=main.replace('ROOT400_BINDING_CAPTURE_REQUIRED','ROOT400_INSTALLATION_INPUTS_REQUIRED')
    main=main.replace('FINITE_BINDING_CAPTURE_WINDOW_EXPIRED','FINITE_INSTALLATION_INPUT_WINDOW_EXPIRED')
    first=main.index("        print('Nuova sola lettura:")
    last=main.index('\n',first)
    main=main[:first]+"        print('Nuovo scope: due metadata della cattura consumata; nove GET Engine su quattro container esatti (Registry,MCP,Gateway owner,APISIX). Riferimenti nonsegreti e impronte mount,90s/24MiB. Nessun contenuto config/credenziale/chiave,SQL,IAM/OAuth,write,import,lifecycle,grant,budget,resume o acquisizione. Env completi restano privati root0600. Nessuna authority. STOP conserva e consuma:non rilanciare.',flush=True)"+main[last:]
    return code+'\ndef main():'+main


if __name__=='__main__':
    (ROOT/'scripts/read-m2-discovery-installation-inputs-20261029.py').write_text(build())
