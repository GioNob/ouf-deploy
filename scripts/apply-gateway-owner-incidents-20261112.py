#!/usr/bin/env python3
"""B: Image-only owner replacement after A, API1.44 and manual recovery only."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import time
from urllib.parse import quote

SOURCE = '2a760ca90cf860a6dcae3eef536e87524aa0fa04'
COMMON_SHA = '487798d53ae88ed0a0f31f4c62ed608a2403b4427a236efd61330bc2d93909eb'


def common():
    path = Path(__file__).resolve().with_name('apply-ingestion-operational-receipt-20261112.py')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != COMMON_SHA:
        raise RuntimeError('COMMON_HELPER_HASH_CHANGED')
    spec = importlib.util.spec_from_file_location('gateway_owner_common', path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


c = common()
need, digest, sha = c.need, c.digest, c.sha
Engine, mac_helper = c.Engine, c.mac_helper


def transition_present(path):
    # Root, actual WAL view. Never open immutable or create an absent store.
    need(all(p.is_file() for p in (path, Path(str(path) + '-wal'), Path(str(path) + '-shm'))),
         'LIVE_WAL_SIDECARS_REQUIRED')
    db = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=8)
    try:
        need(db.execute('pragma journal_mode').fetchone()[0] == 'wal', 'WAL_STORE_REQUIRED')
        return db.execute("select 1 from sqlite_master where type='table' and name='gateway_incident_transition'").fetchone() is not None
    finally:
        db.close()


def request(old, image, mac):
    mac.policy(old)
    config, host = copy.deepcopy(old['Config']), copy.deepcopy(old['HostConfig'])
    need(bool(config.get('Entrypoint')) and
         [old['Path']] + old['Args'] == config['Entrypoint'] + (config.get('Cmd') or []),
         'DIRECT_ENTRYPOINT_REQUIRED')
    need(host.get('RestartPolicy') == {'Name': 'no', 'MaximumRetryCount': 0} and
         not host.get('AutoRemove') and not host.get('VolumesFrom'), 'SUPPORTED_RETAINED_LIFECYCLE_REQUIRED')
    net, ep = next(iter(old['NetworkSettings']['Networks'].items()))
    need(host['NetworkMode'] == net and bool(ep.get('IPAddress')), 'SINGLE_NAMED_IPV4_NETWORK_REQUIRED')
    need(all(m['Type'] == 'bind' and not m['RW'] for m in old['Mounts']), 'READONLY_BIND_MOUNTS_REQUIRED')
    declared = {m['Target'] for m in host.get('Mounts') or []}
    declared.update(b.split(':')[1] for b in host.get('Binds') or [])
    need(all(m['Destination'] in declared for m in old['Mounts']), 'EXPLICIT_MOUNT_DECLARATIONS_REQUIRED')
    c.environment(old)  # Reject duplicate keys; preserve order and every value.
    config['Image'] = image
    ipam = copy.deepcopy(ep.get('IPAMConfig') or {})
    ipam['IPv4Address'] = ep['IPAddress']
    if ep.get('GlobalIPv6Address'):
        ipam['IPv6Address'] = ep['GlobalIPv6Address']
    endpoint = {'IPAMConfig': ipam, 'Aliases': list(ep.get('Aliases') or []), 'MacAddress': ep['MacAddress']}
    for k in ('Links', 'DriverOpts'):
        if ep.get(k):
            endpoint[k] = copy.deepcopy(ep[k])
    return dict(config, HostConfig=host, NetworkingConfig={'EndpointsConfig': {net: endpoint}})


def delta_guard(old, req, image, mac):
    need(req == request(old, image, mac), 'UNEXPECTED_CREATE_DELTA')


def manifest_guard(args):
    raw = c.read(args.bundle_manifest)
    need(sha(raw) == args.manifest_sha256, 'BUNDLE_MANIFEST_HASH_MISMATCH')
    manifest = json.loads(raw)
    need(manifest['schema'] == 'ouf.gateway-owner-incidents-archive.v1' and
         manifest['sourceCommit'] == SOURCE and args.candidate_image in manifest['imageIds'],
         'CANDIDATE_NOT_IN_REVIEWED_MANIFEST')
    return sha(raw)


def compile_plan(old, candidate, predecessor, args, mac, running_args, store_ready, manifest_sha):
    need(store_ready, 'COLLECTOR_TRANSITION_TABLE_REQUIRED')
    need(old['Image'] == args.expected_current_image and predecessor['Id'] == args.expected_current_image,
         'CURRENT_IMAGE_MISMATCH')
    need(candidate['Id'] == args.candidate_image, 'CANDIDATE_IMAGE_MISMATCH')
    need(candidate.get('Architecture') and candidate['Architecture'] == predecessor.get('Architecture') and
         candidate.get('Os') and candidate['Os'] == predecessor.get('Os'), 'CANDIDATE_PLATFORM_MISMATCH')
    state = old['State']
    need(state['Running'] is True and not state.get('Paused') and not state.get('Restarting'),
         'CURRENT_RUNNING_REQUIRED')
    need(running_args == [old['Path']] + old['Args'], 'RUNNING_ARGUMENTS_CHANGED')
    # Prove the CLI store is the one this owner sees, without reading properties or keys.
    need(c.mounted_source(old, args.store_target).resolve() == args.store.resolve(), 'OWNER_STORE_MOUNT_MISMATCH')
    req = request(old, args.candidate_image, mac)
    delta_guard(old, req, args.candidate_image, mac)
    c.image_defaults_guard(req, candidate)
    old = {k: copy.deepcopy(old[k]) for k in
           ('Id', 'Name', 'Image', 'Created', 'Config', 'HostConfig', 'Mounts', 'Path', 'Args', 'NetworkSettings', 'State')}
    old['State'] = {k: old['State'].get(k) for k in ('Running', 'Paused', 'Restarting', 'StartedAt', 'OOMKilled', 'Pid')}
    return {'schema': 'ouf.gateway-owner-incidents-plan.v1', 'sourceCommit': SOURCE,
            'controllerSha256': sha(Path(__file__).read_bytes()), 'commonSha256': COMMON_SHA,
            'macHelperSha256': c.MAC_SHA, 'bundleManifestSha256': manifest_sha,
            'old': old, 'oldFrame': c.frame(old), 'request': req, 'transitionTablePresent': True,
            'candidateImageSha256': digest(candidate), 'predecessorImageSha256': digest(predecessor),
            'parameters': {k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()
                           if k not in ('plan', 'apply', 'plan_sha256')}}


def collect(engine, args, mac):
    manifest_sha = manifest_guard(args)
    need(transition_present(args.store), 'COLLECTOR_TRANSITION_TABLE_REQUIRED')
    old = engine.inspect(args.container)
    plan = compile_plan(old, engine.image(args.candidate_image), engine.image(old['Image']), args, mac,
                        c.process(old), True, manifest_sha)
    need(c.frame(engine.inspect(old['Id'])) == c.frame(old), 'CONTAINER_CHANGED_DURING_PLAN')
    return plan


def public_plan(plan):
    return {'planSha256': digest(plan), 'sourceCommit': SOURCE,
            'candidateImageId': plan['request']['Image'], 'oldImageId': plan['old']['Image'],
            'oldContainerId': plan['old']['Id'], 'beforeFrameSha256': digest(plan['oldFrame']),
            'createRequestSha256': digest(plan['request']), 'bundleManifestSha256': plan['bundleManifestSha256'],
            'privateFieldDigests': {k: digest(v) for k, v in plan['request'].items() if k != 'Image'},
            'transitionTablePresent': True, 'delta': ['Image'],
            'legacyMacPresentStringMatchingEndpoint': True}


def http_observation(doc, args, method, path):
    # Host stdlib Python enters only the network namespace. No Docker exec,
    # credentials, receipt, Authorization header or business work is sent.
    code = '''import http.client,json,sys
try:
 c=http.client.HTTPConnection('127.0.0.1',int(sys.argv[1]),timeout=2)
 method,path=sys.argv[2:4]
 c.request(method,path,body=b'{}' if method=='POST' else None,headers={'Content-Type':'application/json'})
 r=c.getresponse(); out={'httpStatus':r.status}; raw=r.read(65537)
 if method=='GET' and r.status==200 and len(raw)<=65536:
  try:
   status=json.loads(raw).get('status')
   if isinstance(status,str) and len(status)<=128: out['status']=status
  except (ValueError,AttributeError): pass
 print(json.dumps(out)); c.close()
except (OSError,http.client.HTTPException): print(json.dumps({'httpStatus':None}))
'''
    result = subprocess.run([args.nsenter_bin, '--target', str(doc['State']['Pid']), '--net',
                             sys.executable, '-I', '-B', '-S', '-c', code, str(args.readiness_port), method, path],
                            capture_output=True, timeout=5)
    if result.returncode != 0:
        return {'httpStatus': None}
    return json.loads(result.stdout)


def readiness(doc, args):
    return [http_observation(doc, args, 'POST', path)['httpStatus']
            for path in (args.summary_path, args.incidents_path)]


def apply_plan(plan, approved, engine, args, mac, report, recollect=collect, ready=readiness):
    need(digest(plan) == approved, 'FRESH_PLAN_HASH_MISMATCH')
    work = c.begin_attempt(args.journal_root, approved)
    report['privateEvidenceDirectory'] = str(work)
    c.record(work, 'plan.private.json', plan)
    old, req = plan['old'], plan['request']
    cid, name = old['Id'], old['Name']
    c.record(args.journal_root, 'container-' + cid + '.claim', {'approvedPlanSha256': approved})
    need(re.fullmatch('/[A-Za-z0-9_.-]{1,120}', name) is not None, 'BOUNDED_CONTAINER_NAME_REQUIRED')
    retained = name + '-before-incidents-' + approved[:16]
    names = {n for row in engine.api('GET', '/containers/json?all=true') for n in row['Names']}
    need(retained not in names, 'RETAINED_NAME_ALREADY_EXISTS')
    need(digest(recollect(engine, args, mac)) == approved, 'PLAN_CHANGED_BEFORE_STOP')
    c.record(work, 'stop-intent.private.json', {'containerId': cid})
    report.update(oldStopDispatched=True, runtimeChanged=None)
    engine.api('POST', '/containers/' + cid + '/stop?t=' + str(args.stop_timeout))
    stopped = engine.inspect(cid)
    if stopped['State']['Running'] is False and stopped['State']['Pid'] == 0:
        report['runtimeChanged'] = True
    need(not stopped['State']['Running'] and stopped['State']['Pid'] == 0 and
         stopped['State']['StartedAt'] == old['State']['StartedAt'] and
         all(stopped[k] == old[k] for k in ('Config', 'HostConfig', 'Path', 'Args')) and
         c.mounts(stopped) == c.mounts(old), 'STOPPED_FRAME_CHANGED')
    c.record(work, 'stopped.private.json', stopped)
    net = next(iter(old['NetworkSettings']['Networks']))
    c.record(work, 'detach-intent.private.json', {'containerId': cid, 'network': net})
    engine.api('POST', '/networks/' + quote(net, safe='') + '/disconnect', {'Container': cid, 'Force': False})
    c.detached(mac, old, engine.inspect(cid), name)
    c.record(work, 'detached.private.json', engine.inspect(cid))
    c.record(work, 'rename-intent.private.json', {'name': retained})
    engine.api('POST', '/containers/' + cid + '/rename?name=' + quote(retained[1:], safe=''))
    c.detached(mac, old, engine.inspect(cid), retained)
    c.record(work, 'create-intent.private.json', {'requestSha256': digest(req)})
    new = engine.api('POST', '/containers/create?name=' + quote(name[1:], safe=''), req)['Id']
    report['replacementContainerId'] = new
    c.record(work, 'created-id.private.json', {'containerId': new})
    current = engine.inspect(new)
    c.verify_replacement(old, req, current, False)
    c.record(work, 'created.private.json', current)
    c.record(work, 'start-intent.private.json', {'containerId': new})
    engine.api('POST', '/containers/' + new + '/start')
    deadline = time.monotonic() + args.readiness_timeout
    while True:
        current = engine.inspect(new)
        need(current['State']['Running'], 'APPLICATION_EXITED')
        statuses = ready(current, args)
        report['readinessHttpStatuses'] = statuses
        need(time.monotonic() <= deadline, 'READINESS_TIMEOUT')
        if statuses == [403, 403]:
            break
        need(time.monotonic() < deadline, 'READINESS_TIMEOUT')
        time.sleep(0.25)
    c.verify_replacement(old, req, current, True)
    need(c.process(current) == [old['Path']] + old['Args'], 'APPLICATION_ARGUMENTS_CHANGED')
    need(engine.image(current['Image'])['Id'] == args.candidate_image, 'FINAL_IMAGE_CHANGED')
    c.detached(mac, old, engine.inspect(cid), retained)
    need(transition_present(args.store), 'COLLECTOR_TRANSITION_TABLE_REQUIRED')
    # Informational only: any status or unreachable Actuator leaves 403/403 success intact.
    try:
        report['actuatorInformation'] = http_observation(current, args, 'GET', args.actuator_path)
    except (Exception, KeyboardInterrupt):
        report['actuatorInformation'] = {'httpStatus': None}
    c.record(work, 'replacement.private.json', current)
    report.update(status='GATEWAY_OWNER_INCIDENTS_READY', reason='IMAGE_ONLY_AND_403_403_VERIFIED',
                  imageId=current['Image'], oldRetainedStopped=True,
                  configAndHostConfigPreservedExceptImage=True, addressMacAliasesPreserved=True,
                  replacementLegacyMacPresentStringMatchingEndpoint=True)
    c.record(work, 'complete.private.json', report)


def arguments(argv):
    p = c.Parser(description=__doc__)
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--plan', action='store_true')
    mode.add_argument('--apply', action='store_true')
    p.add_argument('--plan-sha256')
    for key in ('container', 'expected-current-image', 'candidate-image', 'store-target', 'docker-socket',
                'nsenter-bin', 'manifest-sha256', 'summary-path', 'incidents-path', 'actuator-path'):
        p.add_argument('--' + key, required=True)
    for key in ('store', 'journal-root', 'bundle-manifest'):
        p.add_argument('--' + key, type=Path, required=True)
    for key in ('readiness-port', 'readiness-timeout', 'stop-timeout'):
        p.add_argument('--' + key, type=int, required=True)
    a = p.parse_args(argv)
    need(bool(a.plan_sha256) == a.apply and (not a.apply or re.fullmatch('[a-f0-9]{64}', a.plan_sha256)),
         'HUMAN_APPROVED_PLAN_HASH_REQUIRED')
    need(all(re.fullmatch('sha256:[a-f0-9]{64}', i) for i in (a.candidate_image, a.expected_current_image)) and
         a.candidate_image != a.expected_current_image and re.fullmatch('[a-f0-9]{64}', a.manifest_sha256),
         'EXACT_IMAGE_AND_MANIFEST_IDS_REQUIRED')
    need(all(getattr(a, k).is_absolute() for k in ('store', 'journal_root', 'bundle_manifest')) and
         all(getattr(a, k).startswith('/') for k in ('store_target', 'docker_socket', 'nsenter_bin',
                                                    'summary_path', 'incidents_path', 'actuator_path')) and
         a.summary_path != a.incidents_path and 1 <= a.readiness_port <= 65535 and
         1 <= a.readiness_timeout <= 1800 and 1 <= a.stop_timeout <= 60, 'BOUNDED_ABSOLUTE_PARAMETERS_REQUIRED')
    return a


def main(argv=None):
    report = {'schema': 'ouf.gateway-owner-incidents-result.v1', 'status': 'HELD', 'runtimeChanged': False,
              'oldStopDispatched': False, 'automaticRollback': False, 'automaticReplay': False,
              'credentialReads': 0, 'databaseWrites': 0}
    engine = args = plan = None
    try:
        args = arguments(argv)
        need(os.geteuid() == 0 and sys.flags.isolated, 'ISOLATED_ROOT_REQUIRED')
        if args.apply:
            need(not (args.journal_root / ('apply-' + args.plan_sha256)).exists(), 'EXISTING_ATTEMPT_DO_NOT_REPLAY')
        mac = mac_helper()
        engine = Engine(args.docker_socket)
        plan = collect(engine, args, mac)
        report.update(public_plan(plan))
        if args.apply:
            apply_plan(plan, args.plan_sha256, engine, args, mac, report)
        else:
            report.update(status='GATEWAY_OWNER_INCIDENTS_PLANNED', reason='HUMAN_HASH_APPROVAL_REQUIRED')
    except (Exception, KeyboardInterrupt) as exc:
        reason = str(exc) if isinstance(exc, RuntimeError) and re.fullmatch('[A-Z][A-Z0-9_]{0,100}', str(exc)) else type(exc).__name__
        report.update(status='HELD', reason=reason)
        if report['oldStopDispatched']:
            for label, cid in [('old', plan['old']['Id']), ('replacement', report.get('replacementContainerId') or args.container)]:
                try:
                    doc = engine.inspect(cid)
                    report[label + 'ObservedState'] = {'containerId': doc['Id'], 'running': doc['State']['Running'],
                                                       'networkCount': len(doc['NetworkSettings']['Networks'])}
                except Exception:
                    report[label + 'ObservedState'] = None
        if report.get('privateEvidenceDirectory'):
            try:
                c.record(Path(report['privateEvidenceDirectory']), 'failed.private.json', report)
            except Exception:
                pass
    print(json.dumps(report, sort_keys=True))
    return int(report['status'] == 'HELD')


if __name__ == '__main__':
    sys.exit(main())
