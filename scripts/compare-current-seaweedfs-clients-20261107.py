#!/usr/bin/env python3
"""One curl/installed-Java PUT+GET comparison on the existing private SeaweedFS.

Creates one temporary container and one new tiny diagnostic object. Does not boot
Spring, touch databases, change live application bindings, or replay old uploads.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import uuid

ROOT = Path('/var/lib/ouf-storage-migration')
PLAN = ROOT / 'cold-host-bound-20261107-v1/plan.private.json'
PLAN_SHA = 'f4cc75450360a1a30a7210b5ee8e492bc99c6737d98131537b87b65fa284cc3d'
APP_IMAGE = 'sha256:7b9d3e918beea500929cb9e3e88165b6c574cedac6067e56206fb2ffa1d65b51'
SEA_IMAGE = 'sha256:d23a50eb6cf56dc994ddc10f43590cc9a8a22a20019cab36d4ad00c3ad3b4af2'
NETWORK, SEA = 'ouf-seaweedfs-private', 'ouf-seaweedfs-stage'
ENDPOINT = 'https://ouf-seaweedfs-stage:9002'
BINDINGS = ROOT / 'seaweedfs/staging-oci33-20261107-v1/application-s3-v1'
DOCKER = ('/usr/bin/docker', '--host', 'unix:///run/docker.sock', '--config', '/nonexistent')
PAYLOAD = b'id,label\n1,ouf-storage-probe\n'
CLASS_SHA = 'd23f692727e14a9ed2c6937992448f4605e34b85279934eaf1a77baaefc3cca9'
CLASS_B64 = 'yv66vgAAAD0BXwoAAgADBwAEDAAFAAYBABBqYXZhL2xhbmcvT2JqZWN0AQAGPGluaXQ+AQADKClWCAAIAQAZW0EtWmEtejAtOV8uJDovIC1dezEsMTYwfQoACgALBwAMDAANAA4BABBqYXZhL2xhbmcvU3RyaW5nAQAHbWF0Y2hlcwEAFShMamF2YS9sYW5nL1N0cmluZzspWggAEAEAC1VOQVZBSUxBQkxFEgAAABIMABMAFAEAF21ha2VDb25jYXRXaXRoQ29uc3RhbnRzAQAmKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZzsKABYAFwcAGAwAGQAaAQATamF2YS91dGlsL0hleEZvcm1hdAEAAm9mAQAXKClMamF2YS91dGlsL0hleEZvcm1hdDsIABwBAAdTSEEtMjU2CgAeAB8HACAMACEAIgEAG2phdmEvc2VjdXJpdHkvTWVzc2FnZURpZ2VzdAEAC2dldEluc3RhbmNlAQAxKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9zZWN1cml0eS9NZXNzYWdlRGlnZXN0OwoAHgAkDAAlACYBAAZkaWdlc3QBAAYoW0IpW0IKABYAKAwAKQAqAQAJZm9ybWF0SGV4AQAWKFtCKUxqYXZhL2xhbmcvU3RyaW5nOwoALAAtBwAuDAAvADABAA9qYXZhL2xhbmcvQ2xhc3MBAAdmb3JOYW1lAQAlKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL0NsYXNzOwgAMgEAB2J1aWxkZXIKACwANAwANQA2AQAJZ2V0TWV0aG9kAQBAKExqYXZhL2xhbmcvU3RyaW5nO1tMamF2YS9sYW5nL0NsYXNzOylMamF2YS9sYW5nL3JlZmxlY3QvTWV0aG9kOwoAOAA5BwA6DAA7ADwBABhqYXZhL2xhbmcvcmVmbGVjdC9NZXRob2QBAAZpbnZva2UBADkoTGphdmEvbGFuZy9PYmplY3Q7W0xqYXZhL2xhbmcvT2JqZWN0OylMamF2YS9sYW5nL09iamVjdDsKAAIAPgwAPwBAAQAIZ2V0Q2xhc3MBABMoKUxqYXZhL2xhbmcvQ2xhc3M7CABCAQAGYnVja2V0CABEAQAGb2JqZWN0CABGAQAGc3RyZWFtBwBIAQATamF2YS9pby9JbnB1dFN0cmVhbQkASgBLBwBMDABNAE4BAA5qYXZhL2xhbmcvTG9uZwEABFRZUEUBABFMamF2YS9sYW5nL0NsYXNzOwcAUAEAHGphdmEvaW8vQnl0ZUFycmF5SW5wdXRTdHJlYW0KAE8AUgwABQBTAQAFKFtCKVYKAEoAVQwAVgBXAQAHdmFsdWVPZgEAEyhKKUxqYXZhL2xhbmcvTG9uZzsF//////////8IAFsBAAtjb250ZW50VHlwZQgAXQEACHRleHQvY3N2CABfAQAFYnVpbGQJAGEAYgcAYwwAZABlAQAQamF2YS9sYW5nL1N5c3RlbQEAA291dAEAFUxqYXZhL2lvL1ByaW50U3RyZWFtOxIAAQASCgBoAGkHAGoMAGsAbAEAE2phdmEvaW8vUHJpbnRTdHJlYW0BAAdwcmludGxuAQAVKExqYXZhL2xhbmcvU3RyaW5nOylWCABuAQAJUFJFRkxJR0hUCABwAQAFY2hlY2sIAHIBAANydW4LAHQAdQcAdgwAGQB3AQAOamF2YS91dGlsL0xpc3QBADYoTGphdmEvbGFuZy9PYmplY3Q7TGphdmEvbGFuZy9PYmplY3Q7KUxqYXZhL3V0aWwvTGlzdDsLAHQAeQwAegB7AQAIY29udGFpbnMBABUoTGphdmEvbGFuZy9PYmplY3Q7KVoIAH0BACBbYS16MC05XVthLXowLTkuLV17MSw2MX1bYS16MC05XQgAfwEAG21hbmFnZWQtZmlsZXMvWzAtOWEtZi1dezM2fQcAgQEAImphdmEvbGFuZy9JbGxlZ2FsQXJndW1lbnRFeGNlcHRpb24KAIAAAwgAhAEAEC9wcm9iZS9pbnB1dC5jc3YLAIYAhwcAiAwAGQCJAQASamF2YS9uaW8vZmlsZS9QYXRoAQA7KExqYXZhL2xhbmcvU3RyaW5nO1tMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbmlvL2ZpbGUvUGF0aDsKAIsAjAcAjQwAjgCPAQATamF2YS9uaW8vZmlsZS9GaWxlcwEADHJlYWRBbGxCeXRlcwEAGChMamF2YS9uaW8vZmlsZS9QYXRoOylbQggAkQEASWl0LmNvbXVuZS50cmllc3RlLm91Zi5vbmJvYXJkaW5nLmFwcGxpY2F0aW9uLk1pbmlvTWFuYWdlZEZpbGVTdGFnaW5nU3RvcmUKACwAkwwAlACVAQAOZ2V0Q29uc3RydWN0b3IBADMoW0xqYXZhL2xhbmcvQ2xhc3M7KUxqYXZhL2xhbmcvcmVmbGVjdC9Db25zdHJ1Y3RvcjsIAJcBACBodHRwczovL291Zi1zZWF3ZWVkZnMtc3RhZ2U6OTAwMggAmQEAES9wcm9iZS9hY2Nlc3Mta2V5CACbAQARL3Byb2JlL3NlY3JldC1rZXkKAJ0AngcAnwwAoAChAQAdamF2YS9sYW5nL3JlZmxlY3QvQ29uc3RydWN0b3IBAAtuZXdJbnN0YW5jZQEAJyhbTGphdmEvbGFuZy9PYmplY3Q7KUxqYXZhL2xhbmcvT2JqZWN0OwgAowEABW1pbmlvCgAsAKUMAKYApwEAEGdldERlY2xhcmVkRmllbGQBAC0oTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvcmVmbGVjdC9GaWVsZDsKAKkAqgcAqwwArACtAQAXamF2YS9sYW5nL3JlZmxlY3QvRmllbGQBAA1zZXRBY2Nlc3NpYmxlAQAEKFopVgoAqQCvDACwALEBAANnZXQBACYoTGphdmEvbGFuZy9PYmplY3Q7KUxqYXZhL2xhbmcvT2JqZWN0OwgAswEAFmlvLm1pbmlvLlB1dE9iamVjdEFyZ3MIALUBABZpby5taW5pby5HZXRPYmplY3RBcmdzCAC3AQAJcHV0T2JqZWN0CAC5AQAJZ2V0T2JqZWN0CgAsALsMALwAvQEAB2dldE5hbWUBABQoKUxqYXZhL2xhbmcvU3RyaW5nOwoAvwDABwDBDADCAMMBABJTdG9yYWdlQ2xpZW50UHJvYmUBAARhcmdzAQBMKExqYXZhL2xhbmcvU3RyaW5nO0xqYXZhL2xhbmcvU3RyaW5nO0xqYXZhL2xhbmcvU3RyaW5nO1tCKUxqYXZhL2xhbmcvT2JqZWN0OwoACgDFDADGAHsBAAZlcXVhbHMIAMgBACJNaW5pb01hbmFnZWRGaWxlU3RhZ2luZ1N0b3JlLmNsYXNzCgAsAMoMAMsAzAEAE2dldFJlc291cmNlQXNTdHJlYW0BACkoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2lvL0lucHV0U3RyZWFtOwoARwDODACOAM8BAAQoKVtCCgC/ANEMANIAKgEABGhhc2gKAL8A1AwA1QAUAQAFcXVvdGUIANcBAAxqYXZhLnZlcnNpb24KAGEA2QwA2gAUAQALZ2V0UHJvcGVydHkKACwA3AwA3QDeAQAKZ2V0UGFja2FnZQEAFSgpTGphdmEvbGFuZy9QYWNrYWdlOwoA4ADhBwDiDADjAL0BABFqYXZhL2xhbmcvUGFja2FnZQEAGGdldEltcGxlbWVudGF0aW9uVmVyc2lvbhIAAgDlDAATAOYBAEooTGphdmEvbGFuZy9TdHJpbmc7TGphdmEvbGFuZy9TdHJpbmc7TGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvU3RyaW5nOwoAvwDoDADpAGwBAARlbWl0CgBHAOsMAOwABgEABWNsb3NlBwDuAQATamF2YS9sYW5nL1Rocm93YWJsZQoA7QDwDADxAPIBAA1hZGRTdXBwcmVzc2VkAQAYKExqYXZhL2xhbmcvVGhyb3dhYmxlOylWCAD0AQADUFVUCAD2AQADR0VUCgBHAPgMAPkA+gEACnJlYWROQnl0ZXMBAAUoSSlbQgoA/AD9BwD+DADGAP8BABBqYXZhL3V0aWwvQXJyYXlzAQAHKFtCW0IpWggBAQEADVBVVF9HRVRfTUFUQ0gIAQMBAA1CT0RZX01JU01BVENIEgADAQUMABMBBgEAOShMamF2YS9sYW5nL1N0cmluZztaTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvU3RyaW5nOwoAYQEIDAEJAQoBAARleGl0AQAEKEkpVgcBDAEAE2phdmEvdXRpbC9BcnJheUxpc3QKAQsAAwsAdAEPDAEQAREBAARzaXplAQADKClJBwETAQAramF2YS9sYW5nL3JlZmxlY3QvSW52b2NhdGlvblRhcmdldEV4Y2VwdGlvbgsAdAEVDAEWAHsBAANhZGQIARgBACZpby5taW5pby5lcnJvcnMuRXJyb3JSZXNwb25zZUV4Y2VwdGlvbggBGgEADWVycm9yUmVzcG9uc2UIARwBAARjb2RlCAEeAQAIcmVzcG9uc2UHASABABFqYXZhL2xhbmcvSW50ZWdlcgcBIgEAJmphdmEvbGFuZy9SZWZsZWN0aXZlT3BlcmF0aW9uRXhjZXB0aW9uCgDtASQMASUBJgEACGdldENhdXNlAQAXKClMamF2YS9sYW5nL1Rocm93YWJsZTsIASgBAAEsCgAKASoMASsBLAEABGpvaW4BAEAoTGphdmEvbGFuZy9DaGFyU2VxdWVuY2U7TGphdmEvbGFuZy9JdGVyYWJsZTspTGphdmEvbGFuZy9TdHJpbmc7CAEuAQAEbnVsbAoBHwEwDAExAREBAAhpbnRWYWx1ZQoACgEzDABWATQBACYoTGphdmEvbGFuZy9PYmplY3Q7KUxqYXZhL2xhbmcvU3RyaW5nOxIABAE2DAATATcBAF0oTGphdmEvbGFuZy9TdHJpbmc7WkxqYXZhL2xhbmcvU3RyaW5nO0xqYXZhL2xhbmcvU3RyaW5nO0xqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZzsBAARDb2RlAQAPTGluZU51bWJlclRhYmxlAQANU3RhY2tNYXBUYWJsZQEACkV4Y2VwdGlvbnMHAT0BABNqYXZhL2xhbmcvRXhjZXB0aW9uAQAEbWFpbgEAFihbTGphdmEvbGFuZy9TdHJpbmc7KVYHAUEBAAJbQgcBQwEAE1tMamF2YS9sYW5nL1N0cmluZzsHAUUBABRqYXZhL2lvL1NlcmlhbGl6YWJsZQEAClNvdXJjZUZpbGUBABdTdG9yYWdlQ2xpZW50UHJvYmUuamF2YQEAEEJvb3RzdHJhcE1ldGhvZHMPBgFKCgFLAUwHAU0MABMBTgEAJGphdmEvbGFuZy9pbnZva2UvU3RyaW5nQ29uY2F0RmFjdG9yeQEAmChMamF2YS9sYW5nL2ludm9rZS9NZXRob2RIYW5kbGVzJExvb2t1cDtMamF2YS9sYW5nL1N0cmluZztMamF2YS9sYW5nL2ludm9rZS9NZXRob2RUeXBlO0xqYXZhL2xhbmcvU3RyaW5nO1tMamF2YS9sYW5nL09iamVjdDspTGphdmEvbGFuZy9pbnZva2UvQ2FsbFNpdGU7CAFQAQADIgEiCAFSAQALT1VGX1BST0JFIAEIAVQBAFZ7InN0YXR1cyI6IkpBVkFfQ0xJRU5UX1JFQURZIiwiYWRhcHRlckNsYXNzU2hhMjU2IjoBLCJqYXZhVmVyc2lvbiI6ASwibWluaW9WZXJzaW9uIjoBfQgBVgEAQnsic3RhdHVzIjoBLCJwdXRBY2tub3dsZWRnZWQiOnRydWUsImJvZHlNYXRjaGVzIjoBLCJib2R5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'
DEADLINE = 0


def need(condition, code):
    if not condition:
        raise RuntimeError(code)


def command(args, *, data=None, timeout=20):
    remaining = DEADLINE - time.monotonic()
    need(remaining > 0, 'DIAGNOSTIC_DEADLINE')
    return subprocess.run(args, input=data, capture_output=True, timeout=min(timeout, remaining))


def docker(*args, data=None, timeout=20, checked=True):
    p = command((*DOCKER, *args), data=data, timeout=timeout)
    if checked:
        need(p.returncode == 0, 'DOCKER_COMMAND_FAILED')
    return p


def inspect(ref):
    rows = json.loads(docker('container', 'inspect', ref).stdout)
    need(len(rows) == 1, 'CONTAINER_NOT_UNIQUE')
    return rows[0]


def read(path, limit=1048576):
    with path.open('rb') as stream:
        data = stream.read(limit + 1)
    need(len(data) <= limit, 'INPUT_TOO_LARGE')
    return data


def safe_code(body):
    match = re.search(rb'<Code>([A-Za-z][A-Za-z0-9_-]{0,79})</Code>', body[:65536])
    return match.group(1).decode() if match else None


def curl(cid, method, bucket, key, access, secret):
    def quoted(s):
        return '"' + s.replace('\\', '\\\\').replace('"', '\\"') + '"'
    config = {
        'url': ENDPOINT + '/' + bucket + '/' + key, 'request': method,
        'aws-sigv4': 'aws:amz:us-east-1:s3', 'user': access + ':' + secret,
        'cacert': '/probe/ca.pem', 'noproxy': '*', 'connect-timeout': '5',
        'max-time': '30', 'retry': '0', 'max-filesize': '65536',
        'write-out': '\\nOUF_HTTP:%{http_code}\\n',
    }
    # write-out must retain curl's newline escape rather than quote-escaping it twice.
    text = 'silent\nshow-error\n' + ''.join(k + ' = ' + quoted(v) + '\n' for k, v in config.items() if k != 'write-out')
    text += 'write-out = "\\nOUF_HTTP:%{http_code}\\n"\n'
    payload = PAYLOAD if method == 'PUT' else b''
    text += 'header = "X-Amz-Content-Sha256: ' + hashlib.sha256(payload).hexdigest() + '"\n'
    if method == 'PUT':
        text += 'header = "Content-Type: text/csv"\ndata-binary = "@/probe/input.csv"\n'
    p = docker('exec', '-i', cid, 'curl', '--config', '-', data=text.encode(), timeout=35, checked=False)
    body, marker, tail = p.stdout.rpartition(b'\nOUF_HTTP:')
    status = int(tail.strip()) if marker and re.fullmatch(rb'[0-9]{3}\n?', tail) else None
    return {'exitCode': p.returncode, 'httpStatus': status, 'providerCode': safe_code(body),
            'bodyMatches': method == 'GET' and p.returncode == 0 and status == 200 and body == PAYLOAD}


def java(cid, mode, bucket, key):
    p = docker('exec', cid, 'java', '-Xmx128m',
               '-Djavax.net.ssl.trustStore=/tmp/probe.p12', '-Djavax.net.ssl.trustStorePassword=changeit',
               '-Dloader.main=StorageClientProbe', '-Dloader.path=/probe',
               '-Dloader.config.location=file:/probe/loader.properties',
               '-cp', '/app/application.jar', 'org.springframework.boot.loader.launch.PropertiesLauncher',
               mode, bucket, key, timeout=75, checked=False)
    rows = [line[len(b'OUF_PROBE '):] for line in p.stdout.splitlines() if line.startswith(b'OUF_PROBE ')]
    if len(rows) != 1:
        # No raw JVM logs/messages leave the host.
        return {'status': 'JAVA_LAUNCH_FAILED', 'exitCode': p.returncode}
    result = json.loads(rows[0])
    result['exitCode'] = p.returncode
    return result


def run(report):
    global DEADLINE
    DEADLINE = time.monotonic() + 220
    need(os.geteuid() == 0, 'ROOT_REQUIRED')
    raw = read(PLAN)
    need(hashlib.sha256(raw).hexdigest() == PLAN_SHA, 'RETAINED_PLAN_MISMATCH')
    binding = json.loads(raw)['roles']['onboarding']
    app = inspect(binding['containerId'])
    need(app['State']['Running'] and app['Image'] == APP_IMAGE, 'CURRENT_ONBOARDING_IMAGE_CHANGED')
    app_state = (app['Id'], app['Image'], app['State']['StartedAt'])
    sea = inspect(SEA)
    need(sea['State']['Running'] and sea['Image'] == SEA_IMAGE
         and set(sea['NetworkSettings']['Networks']) == {NETWORK}
         and not sea['HostConfig'].get('PortBindings'), 'SEAWEEDFS_BINDING_CHANGED')
    need(any(m['Source'] == str(BINDINGS / 'config') and m['Destination'] == '/config' and not m['RW']
             for m in sea['Mounts']), 'SEAWEEDFS_CONFIG_MOUNT_CHANGED')
    network = json.loads(docker('network', 'inspect', NETWORK).stdout)[0]
    need(network['Internal'], 'PRIVATE_NETWORK_REQUIRED')
    client = BINDINGS / 'clients/onboarding'
    env = json.loads(read(client / 'binding.private.json'))['environment']
    bucket = env['OUF_ONBOARDING_STAGING_BUCKET']
    need(env['OUF_ONBOARDING_STAGING_ENDPOINT'] == ENDPOINT
         and re.fullmatch('[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]', bucket), 'TARGET_BINDING_INVALID')
    access, secret = (read(client / name, 4096).decode().strip() for name in ('access-key', 'secret-key'))
    need(access and secret and ':' not in access and not any(c in access + secret for c in '\r\n\x00'), 'CREDENTIAL_FILE_INVALID')
    class_bytes = base64.b64decode(CLASS_B64, validate=True)
    need(hashlib.sha256(class_bytes).hexdigest() == CLASS_SHA, 'PROBE_CLASS_MISMATCH')
    work = Path(tempfile.mkdtemp(prefix='client-compare-', dir=ROOT))
    key = 'managed-files/' + str(uuid.uuid4())
    files = {'access-key': access.encode(), 'secret-key': secret.encode(),
             'ca.pem': read(BINDINGS / 'config/tls/ca.pem', 16384), 'input.csv': PAYLOAD,
             'StorageClientProbe.class': class_bytes, 'loader.properties': b''}
    for name, data in files.items():
        path = work / name
        path.write_bytes(data)
        os.chmod(path, 0o400)
        os.chown(path, 10003, 10003)
    os.chown(work, 10003, 10003)
    os.chmod(work, 0o500)
    report.update(privateEvidenceDirectory=str(work), bucket=bucket, diagnosticObjectKey=key,
                  payloadBytes=len(PAYLOAD), payloadSha256=hashlib.sha256(PAYLOAD).hexdigest(),
                  onboardingImage=APP_IMAGE, seaweedfsImage=SEA_IMAGE, endpoint=ENDPOINT,
                  sameIdentityEndpointPayloadAndKey=True, curlRegion='us-east-1', javaRegion='INSTALLED_ADAPTER_DEFAULT',
                  sameClientContainerNetwork=True, clientNetwork=NETWORK,
                  originalApplicationNetwork=sorted(app['NetworkSettings']['Networks']),
                  applicationHttpUploadTested=False, applicationDatabaseTouched=False,
                  existingApplicationBindingsChanged=False, secretsEmitted=False)
    cid = None
    container_name = 'ouf-s3-compare-' + uuid.uuid4().hex[:12]
    try:
        cid = docker('create', '--name', container_name,
                     '--network', NETWORK, '--pull=never', '--restart=no', '--read-only',
                     '--cap-drop=ALL', '--security-opt=no-new-privileges', '--user', '10003:10003',
                     '--memory=512m', '--cpus=1', '--pids-limit=128',
                     '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=32m,mode=1777',
                     '--mount', 'type=bind,src=' + str(work) + ',dst=/probe,readonly',
                     '--entrypoint', '/bin/sh', APP_IMAGE, '-c', 'sleep 240').stdout.decode().strip()
        need(re.fullmatch('[a-f0-9]{64}', cid), 'CREATED_CONTAINER_ID_INVALID')
        docker('start', cid)
        report['temporaryContainerStarted'] = True
        report['phase'] = 'CURL_CAPABILITY_CHECK'
        help_result = docker('exec', cid, 'curl', '--help', 'all').stdout
        need(b'--aws-sigv4' in help_result, 'CURL_SIGV4_UNAVAILABLE')
        report['phase'] = 'JAVA_TLS_IMPORT'
        docker('exec', cid, 'keytool', '-importcert', '-noprompt', '-alias', 'ouf-probe',
               '-file', '/probe/ca.pem', '-keystore', '/tmp/probe.p12', '-storetype', 'PKCS12', '-storepass', 'changeit')
        report['phase'] = 'JAVA_PREFLIGHT'
        report['javaPreflight'] = java(cid, 'check', bucket, key)
        need(report['javaPreflight'].get('status') == 'JAVA_CLIENT_READY'
             and report['javaPreflight'].get('exitCode') == 0, 'JAVA_PREFLIGHT_FAILED')
        report['diagnosticObjectMayExist'] = True
        intent = work / 'request-intent.json'
        intent.write_text(json.dumps({'bucket': bucket, 'key': key,
                                     'payloadSha256': report['payloadSha256'],
                                     'maximumLogicalPutCalls': 2}) + '\n')
        os.chmod(intent, 0o600)
        report['phase'] = 'CURL_PUT'
        report['curlPut'] = curl(cid, 'PUT', bucket, key, access, secret)
        report['phase'] = 'CURL_GET'
        report['curlGet'] = curl(cid, 'GET', bucket, key, access, secret)
        report['phase'] = 'JAVA_PUT_GET'
        report['javaTransfer'] = java(cid, 'run', bucket, key)
        report['phase'] = 'COMPLETE'
        report['status'] = 'COMPARISON_COMPLETE'
        report['bothClientsPassed'] = (report['curlPut']['exitCode'] == 0
            and report['curlPut']['httpStatus'] == 200 and report['curlGet']['bodyMatches']
            and report['javaTransfer'].get('status') == 'PUT_GET_MATCH'
            and report['javaTransfer'].get('exitCode') == 0)
    finally:
        # The fresh random name also handles a lost create response. No existing container is selected.
        cleanup = subprocess.run((*DOCKER, 'rm', '-f', container_name), capture_output=True, timeout=20)
        report['temporaryContainerRemoved'] = cleanup.returncode == 0
        # Credentials are only temporary copies; the original binding files remain untouched.
        for name in ('access-key', 'secret-key'):
            (work / name).unlink(missing_ok=True)
        report['temporaryCredentialCopiesRemoved'] = True
        try:
            current = inspect(app_state[0])
            report['originalApplicationStillRunningUnchangedImage'] = (
                current['State']['Running'] and (current['Id'], current['Image'], current['State']['StartedAt']) == app_state)
        except Exception:
            report['originalApplicationStillRunningUnchangedImage'] = None


if __name__ == '__main__':
    report = {'schema': 'ouf.seaweedfs-client-comparison.v1', 'status': 'INCOMPLETE',
              'bothClientsPassed': False, 'diagnosticObjectMayExist': False}
    try:
        run(report)
    except Exception as exc:
        report['status'] = 'INCOMPLETE'
        report['reason'] = str(exc) if isinstance(exc, RuntimeError) and re.fullmatch('[A-Z_]+', str(exc)) else type(exc).__name__
    if 'privateEvidenceDirectory' in report:
        evidence = Path(report['privateEvidenceDirectory']) / 'result.json'
        evidence.write_text(json.dumps(report, sort_keys=True) + '\n')
        os.chmod(evidence, 0o600)
    print(json.dumps(report, sort_keys=True))
    raise SystemExit(0 if report['status'] == 'COMPARISON_COMPLETE' else 1)
