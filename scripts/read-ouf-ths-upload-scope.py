#!/usr/bin/env python3
"""Read the deployed Keycloak THS client mapping without exporting credentials."""
import getpass
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import urlencode
import warnings

PLAN = Path('/var/lib/ouf-storage-migration/cold-host-bound-20261107-v1/plan.private.json')
PLAN_SHA = 'f4cc75450360a1a30a7210b5ee8e492bc99c6737d98131537b87b65fa284cc3d'
CLIENT = 'a53bc77e-1b21-4a54-8f1a-b236fadb759a'
ACCOUNT = 'ouf-admin'
SUBJECT = 'b93d8cf6-cd14-4ee6-91d7-84cd76c4f500'
UPLOAD = 'ouf.managed-source.file.upload'
SCOPES = ('openid authorization.policy.admin ouf.managed-source.file.upload resolution.issue.read '
          'resolution.match.approve ouf.managed-source.preview ouf.managed-source.file.profile '
          'ouf.onboarding.quarantine.release')
DOCKER = ('/usr/bin/docker', '--host', 'unix:///run/docker.sock', '--config', '/nonexistent')


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def request(report, phase, path, *, form=None, token=None):
    conn = http.client.HTTPConnection('127.0.0.1', 8080, timeout=8)
    headers = {'Accept': 'application/json'}
    body = None
    if form is not None:
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
        body = urlencode(form)
    if token is not None:
        headers['Authorization'] = 'Bearer ' + token
    report['phase'] = phase
    try:
        conn.request('POST' if form is not None else 'GET', path, body, headers)
        response = conn.getresponse()
        report['httpStatus'] = response.status
        need(response.status == 200, 'KEYCLOAK_REQUEST_REJECTED')
        raw = response.read(262145)
        need(len(raw) <= 262144, 'KEYCLOAK_RESPONSE_LIMIT')
        return json.loads(raw)
    finally:
        conn.close()


def evaluate(report):
    password = sys.stdin.read(4097)
    need(0 < len(password) <= 4096, 'ADMIN_PASSWORD_REQUIRED')
    token = request(report, 'admin-login', '/realms/master/protocol/openid-connect/token',
                    form={'client_id': 'admin-cli', 'grant_type': 'password',
                          'username': 'oufadmin', 'password': password})['access_token']
    del password
    users = request(report, 'find-account', '/admin/realms/ouf/users?' +
                    urlencode({'username': ACCOUNT, 'exact': 'true', 'max': 2}), token=token)
    need(isinstance(users, list) and len(users) == 1 and users[0].get('username') == ACCOUNT
         and users[0].get('enabled') is True, 'EXACT_ENABLED_USER_REQUIRED')
    uid = users[0]['id']
    need(re.fullmatch('[a-f0-9-]{36}', uid), 'KEYCLOAK_USER_ID_INVALID')
    claims = request(report, 'evaluate-ths-client', '/admin/realms/ouf/clients/' + CLIENT +
                     '/evaluate-scopes/generate-example-access-token?' +
                     urlencode({'userId': uid, 'scope': SCOPES}), token=token)
    need(isinstance(claims, dict) and isinstance(claims.get('scope', ''), str),
         'KEYCLOAK_EXAMPLE_CLAIMS_REQUIRED')
    report.update(status='THS_KEYCLOAK_EXAMPLE_READ',
                  uploadScopeIncluded=UPLOAD in claims.get('scope', '').split(),
                  subjectMatchesOufAdmin=(claims.get('ouf_subject') or claims.get('sub')) == SUBJECT,
                  tenantMatches=claims.get('tenant_id') == 'ouf-lab',
                  actorHuman=claims.get('ouf_actor_type') == 'HUMAN')


def run(report):
    need(os.geteuid() == 0 and not sys.argv[1:], 'ROOT_AND_NO_ARGUMENTS_REQUIRED')
    with PLAN.open('rb') as stream:
        raw = stream.read(1048577)
    need(len(raw) <= 1048576 and hashlib.sha256(raw).hexdigest() == PLAN_SHA, 'RETAINED_PLAN_MISMATCH')
    cid = json.loads(raw)['roles']['keycloak']['containerId']
    need(re.fullmatch('[a-f0-9]{64}', cid), 'KEYCLOAK_CONTAINER_ID_INVALID')
    inspected = subprocess.run((*DOCKER, 'inspect', '-f', '{{.Name}} {{.State.Pid}}', cid),
                               capture_output=True, text=True, timeout=10, check=True)
    name, pid = inspected.stdout.split()
    need(name == '/ouf-keycloak' and re.fullmatch('[1-9][0-9]*', pid), 'KEYCLOAK_NOT_RUNNING')
    warnings.simplefilter('error', getpass.GetPassWarning)
    password = getpass.getpass('Password amministratore tecnico Keycloak oufadmin (nascosta): ')
    result = subprocess.run(('/usr/bin/nsenter', '--target', pid, '--net', sys.executable,
                             '-I', '-B', '-S', __file__, 'evaluate'),
                            input=password, capture_output=True, text=True, timeout=35)
    del password
    need(result.returncode in (0, 1) and len(result.stdout) <= 4096, 'KEYCLOAK_READ_FAILED')
    report.update(json.loads(result.stdout))


def main():
    report = {'status': 'HELD'}
    try:
        if sys.argv[1:] == ['evaluate']:
            evaluate(report)
        else:
            run(report)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError,
            getpass.GetPassWarning, EOFError, http.client.HTTPException) as error:
        reason = str(error)
        report['reason'] = reason if re.fullmatch('[A-Z_]{5,80}', reason) else type(error).__name__
    print(json.dumps(report, sort_keys=True))
    return int(report['status'] == 'HELD')


if __name__ == '__main__':
    raise SystemExit(main())
