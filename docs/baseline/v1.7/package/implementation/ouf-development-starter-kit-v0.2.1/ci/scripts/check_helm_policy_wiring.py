#!/usr/bin/env python3
from pathlib import Path
import sys
R=Path(__file__).resolve().parents[2]
v=(R/'helm/ouf-service/values.yaml').read_text(); t=(R/'helm/ouf-service/templates/networkpolicy.yaml').read_text(); p=(R/'ci/pipeline-contract.yaml').read_text()
errs=[]
for token in ['allowedIngress','allowedEgress']:
    if token not in v or token not in t: errs.append(token+' not wired')
for token in ['helm lint','helm template/render']:
    if token not in p: errs.append(token+' not blocking')
if errs: print('\n'.join(errs)); sys.exit(1)
print('Helm policy wiring: OK; actual helm lint/template is mandatory in target CI.')
