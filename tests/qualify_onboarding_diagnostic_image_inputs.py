"""Root-only disposable exact-archive qualification; never production context."""
import importlib.util,json,os,pathlib,socket,subprocess
from unittest.mock import patch
root=pathlib.Path('/root/ouf-diag-image-inputs-ci')
spec=importlib.util.spec_from_file_location('unit',root/'repo/tests/test_onboarding_diagnostic_image_inputs.py');unit=importlib.util.module_from_spec(spec);spec.loader.exec_module(unit);m=unit.m
assert os.geteuid()==0
inputs,receipt=unit.fixtures();m.INPUT_HASH=m.digest(inputs);receipt['inputsHash']=m.INPUT_HASH
source=root/'captured';source.mkdir(mode=0o700)
for name,value in [('inputs.json',inputs),('result.json',receipt)]:m.put(source/name,value)
target=root/'prepared'
with patch.object(socket,'socket',side_effect=AssertionError('Engine/network forbidden')),patch.object(subprocess,'run',side_effect=AssertionError('Subprocess forbidden')):
    result=m.prepare(root/'candidate.zip',root/'repo/tools/acquisition_read_native',root=target,input_root=source)
assert result['complete'] and result['counts']=={'privateMetadataReads':2,'ciZipReads':1,'nativeArchivesPrepared':1,'engineGets':0,'containerWrites':0,'imageImports':0}
private=json.loads((target/'execution-inputs.json').read_text());assert private['currentOnboarding']==inputs['onboardingObservation']
assert 'PRIVATE_CANARY' not in str(result) and not result['runtimeAuthorityIssued'] and not result['executionEntryQualified']
try:m.prepare(root/'candidate.zip',root/'repo/tools/acquisition_read_native',root=target,input_root=source);raise AssertionError('scope replay allowed')
except m.Stop:pass
print('EXACT_ARCHIVE_INPUTS_PREPARED_WITH_ZERO_RUNTIME_IO_PASS')
print(json.dumps(result,sort_keys=True))
