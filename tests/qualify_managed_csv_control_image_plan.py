"""CI actual qualified archives and synthetic protected metadata; no runtime ports."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
from unittest.mock import patch


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


assert os.geteuid() == os.getegid() == 0
base = Path(__file__).parents[1]
m = load('private_plan', base/'tools/managed_csv_recovery/image_plan.py')
fixture = load('plan_fixture', base/'tests/test_managed_csv_control_image_plan.py')
stage = load('existing_ci_unpack', base/'scripts/stage_managed_profile_control_image.py')
custody = load('existing_teatri_custody', base/'tools/acquisition_read_native/image_custody.py')
root = Path('/root/ouf-managed-csv-control-plan-ci'); root.mkdir(mode=0o700)
values = fixture.fixture(root)
inputs, result, review, receipts, _, case = values
capture = root/'capture'; capture.mkdir(mode=0o700)
for path, value in [(capture/'inputs.json', inputs), (capture/'result.json', result), (root/'review.json', review)]:
    path.write_bytes(m.encoded(value)); path.chmod(0o400)
retained = {path: path.read_bytes() for path in [capture/'inputs.json', capture/'result.json', root/'review.json']}
zips = {}
for role in receipts:
    target = root/(role+'.zip'); shutil.copyfile(os.environ['OUF_EXACT_ZIP_DIRECTORY']+'/'+role+'.zip', target); target.chmod(0o400); zips[role] = target
scope = m.Scope(root/'image-plan')
with patch('socket.socket', side_effect=AssertionError('runtime/network I/O forbidden in preparation')), \
     patch('subprocess.Popen', side_effect=AssertionError('runtime processes forbidden in preparation')):
    output = m.prepare(scope, case, receipts, zips, fixture.p, fixture.mac, custody, stage.unpack)
assert output['complete'] is True and output['counts'] == {
    'privateMetadataReads': 3, 'privateMetadataBytes': sum(len(value) for value in retained.values()),
    'ciZipReads': 2, 'nativeArchivesPrepared': 2, 'engineGets': 0, 'containerWrites': 0, 'imageImports': 0}
assert output['newDatabaseMigrations'] == 0 and output['unchangedPeers'] == 11
assert output['runtimeAuthorityIssued'] is False and output['executionEntryQualified'] is False
assert all(path.read_bytes() == raw for path, raw in retained.items())
for role, receipt in receipts.items():
    target = scope.root/(role+'-native.tar')
    with target.open('rb') as stream:
        checksum, size = custody.hashed(stream, 1024*1024*1024)
    assert checksum == receipt['derivedArchiveSha256'] and size == receipt['nativeArchiveBytes']
try:
    m.Scope(scope.root); raise AssertionError('consumed image scope reused')
except m.Stop:
    pass
print(json.dumps({'status': 'MANAGED_CSV_EXACT_IMAGES_CONDITIONAL_PLAN_PASS', 'actualQualifiedCiArchives': 2,
                  'cohortSize': 13, 'metadataReads': 3, 'nativeArchivesPrepared': 2, 'runtimePortsAndProcessesDenied': True,
                  'all36MigrationsAndYamlRetained': True, 'privateFixtureNotTargetProof': True, 'runtimeAuthorityIssued': False,
                  'imageImports': 0, 'applicationE2EProven': False}, sort_keys=True))
