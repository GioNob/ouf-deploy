#!/usr/bin/env python3
"""Bounded systemd metadata/static routing review for five known runtime sources.
No service mutation, Docker/IAM call, token grant, filesystem write or replay.
Source code is inspected as text, never executed. Runtime credential bodies are
not read. Report only unit states and source-path correspondence booleans.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import time

DRIVER = Path('/var/lib/ouf-storage-test-cold-stop-20261106.py')
DRIVER_SHA = 'b3b28645ed377459fbe577fe4eb5eb8fb351a0e2c0e3f7067d5745f6f83ad2b5'
UNIT = re.compile(r'ouf-[A-Za-z0-9_.@-]+\.(?:service|timer)')
KNOWN = ['ouf-gateway-policy-token', 'ouf-ingestion-policy-token', 'ouf-onboarding-identity-token', 'ouf-policy-token@semantic']
SAFE = ('Id', 'LoadState', 'ActiveState', 'SubState', 'UnitFileState', 'MainPID', 'Result')
PROPS = SAFE + ('Triggers', 'TriggeredBy', 'ExecStart', 'ReadWritePaths', 'TimersMonotonic')


def need(ok, reason):
    if not ok: raise ValueError(reason)


def command(argv, until):
    need(time.monotonic() < until, 'TOTAL_TIME_LIMIT')
    p = subprocess.Popen(['/usr/bin/systemctl', '--no-pager', *argv],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'SYSTEMD_PAGER': 'cat'}, start_new_session=True)
    data = bytearray()
    selector = selectors.DefaultSelector()
    selector.register(p.stdout, selectors.EVENT_READ)
    deadline = min(until, time.monotonic() + 10)
    try:
        while selector.get_map():
            need(time.monotonic() < deadline, 'SYSTEMCTL_READ_TIMEOUT')
            for key, _ in selector.select(min(0.2, max(0, deadline - time.monotonic()))):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                data.extend(chunk)
                need(len(data) <= 1 << 20, 'SYSTEMCTL_OUTPUT_LIMIT')
        rc = p.wait(timeout=max(0.01, deadline - time.monotonic()))
        need(rc == 0, 'SYSTEMCTL_READ_FAILED')
        return bytes(data).decode('utf-8')
    finally:
        selector.close()
        if p.poll() is None:
            os.killpg(p.pid, signal.SIGKILL)  # Metadata CLI only, never a service.
            p.wait(timeout=5)
        p.stdout.close()


def unit_names(raw):
    result = set()
    for line in raw.splitlines():
        fields = line.split()
        if fields and fields[0] == '\u25cf': fields.pop(0)
        if fields and UNIT.fullmatch(fields[0]): result.add(fields[0])
    need(len(result) <= 32, 'UNIT_COUNT_LIMIT')
    return result


def property_rows(raw):
    rows = []
    for block in raw.strip().split('\n\n'):
        values = {}
        for line in block.splitlines():
            key, separator, value = line.partition('=')
            need(bool(separator) and key in PROPS, 'UNEXPECTED_SYSTEMCTL_PROPERTY')
            values.setdefault(key, []).append(value)
        need(len(values.get('Id', [])) == 1 and UNIT.fullmatch(values['Id'][0]), 'UNIT_ID_CARDINALITY')
        rows.append(values)
    need(len(rows) <= 32 and len({x['Id'][0] for x in rows}) == len(rows), 'UNIT_RECORD_COUNT')
    return rows


def path_mentioned(text, source):
    # Exact literal path or its descendant; not a similar prefix.
    return re.search(r'(?<![A-Za-z0-9_./-])' + re.escape(source) + r'(?=$|[/\s\x22\x27;})])', text) is not None


def main():
    need(os.geteuid() == os.getegid() == 0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,
         'ROOT_ISOLATED_PYTHON_REQUIRED')
    for path in (Path('/'), Path('/var'), Path('/var/lib')):
        s = path.lstat()
        need(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022, 'PROGRAM_ANCESTRY')
    fd = os.open(DRIVER, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as f:
        s = os.fstat(f.fileno())
        need(stat.S_ISREG(s.st_mode) and s.st_uid == 0 and s.st_nlink == 1 and
             stat.S_IMODE(s.st_mode) == 0o600 and s.st_size == 15186, 'DRIVER_METADATA')
        raw = f.read(15187)
    need(hashlib.sha256(raw).hexdigest() == DRIVER_SHA, 'DRIVER_DIGEST')
    d = {'__name__': 'definitions_only', '__file__': str(DRIVER)}
    exec(compile(raw, str(DRIVER), 'exec'), d)
    h, _ = d['bootstrap']()
    plan_raw = h['protected'](d['LEGACY_AREA'] / 'plan.private.json', private=True)
    need(h['digest'](plan_raw) == d['PLAN_SHA'], 'PLAN_DIGEST')
    plan = h['decode'](plan_raw)
    sources = sorted(plan['runtimeSources'])
    need(len(sources) == 5 and all(h['digest'](x.encode()) in set().union(*h['REVIEWED_RUN_BINDINGS'].values()) for x in sources), 'EXACT_RUNTIME_SOURCES')
    until = time.monotonic() + 60
    patterns = ['ouf-*token*.service', 'ouf-*token*.timer']
    installed = unit_names(command(['list-unit-files', '--no-legend', *patterns], until))
    loaded = unit_names(command(['list-units', '--all', '--plain', '--no-legend', *patterns], until))
    historical = {base + ext for base in KNOWN for ext in ('.service', '.timer')}
    names = installed | loaded
    names = sorted(n for n in names if '@.' not in n)
    need(0 < len(names) <= 32, 'UNIT_COUNT_LIMIT')
    rows = property_rows(command(['show', *names, *['--property=' + k for k in PROPS]], until))
    reports, cache = [], {}
    for row in rows:
        report = {k: row[k][0] for k in SAFE if len(row.get(k, [])) == 1}
        report['repeatedProperties'] = sorted(k for k, v in row.items() if len(v) != 1)
        report['associatedUnits'] = sorted({n for k in ('Triggers', 'TriggeredBy') for v in row.get(k, []) for n in v.split() if UNIT.fullmatch(n)})
        start = '\n'.join(row.get('ExecStart', []))
        candidates = sorted(set(re.findall(r'(/[A-Za-z0-9_./-]+\.(?:py|sh))(?=[\s;\x22\x27}]|$)', start)))
        need(len(candidates) <= 4, 'SCRIPT_CANDIDATE_LIMIT')
        static = ''
        source_reads, unavailable = 0, 0
        for path in candidates:
            # No arbitrary reads outside the historical OUF code locations.
            if not path.startswith(('/opt/ouf/', '/var/lib/ouf-', '/var/lib/ouf/')):
                unavailable += 1
                continue
            if path not in cache:
                need(len(cache) < 16 and time.monotonic() < until, 'SOURCE_READ_LIMIT')
                try:
                    cache[path] = h['protected'](Path(path), limit=262144).decode('utf-8')
                except (h['Held'], OSError, UnicodeError):
                    cache[path] = None
            if cache[path] is None:
                unavailable += 1
            else:
                static += '\n' + cache[path]
                source_reads += 1
        report.update(scriptCandidates=len(candidates), protectedSourceReads=source_reads,
                      sourceReadsUnavailable=unavailable, sourceCodeExecuted=False)
        report['runtimeSourceLinks'] = [
            {'sourcePathSha256': h['digest'](source.encode()),
             'execStartLiteral': path_mentioned(start, source),
             'readWritePathLiteral': path_mentioned('\n'.join(row.get('ReadWritePaths', [])), source),
             'protectedScriptLiteral': path_mentioned(static, source)}
            for source in sources if any(path_mentioned(text, source) for text in
                (start, static, '\n'.join(row.get('ReadWritePaths', []))))]
        report['timerScheduleMetadataPresent'] = any(bool(v) for v in row.get('TimersMonotonic', []))
        reports.append(report)
    print(json.dumps({'schema': 'ouf.storage-runtime-writer-metadata.v1',
        'status': 'HOST_TOKEN_UNITS_AND_STATIC_ROUTING_OBSERVED',
        'units': reports, 'historicalUnitsNotObserved': sorted(historical - set(names)),
        'systemctlReadCommands': 3, 'sourceFilesRead': sum(v is not None for v in cache.values()),
        'sourcePathsExported': False, 'argumentsOrEnvironmentExported': False,
        'runtimeCredentialBodiesRead': 0, 'serviceMutations': 0, 'dockerRequests': 0, 'iamRequests': 0,
        'filesWritten': 0, 'namedUnitFilterProvesAllWriters': False, 'staticLiteralProvesEffectiveWriter': False,
        'automaticReplayAllowed': False, 'automaticRestartAllowed': False,
        'runtimeAuthorityIssued': False, 'acceptanceCreditAdded': 0}, sort_keys=True))


if __name__ == '__main__':
    try: main()
    except Exception as error:
        reason = str(error) if type(error).__name__ in ('Held', 'ValueError') else type(error).__name__
        print(json.dumps({'status': 'HELD', 'reason': reason, 'serviceMutations': 0,
            'runtimeCredentialBodiesRead': 0, 'filesWritten': 0, 'runtimeAuthorityIssued': False,
            'automaticReplayAllowed': False, 'acceptanceCreditAdded': 0}))
        sys.exit(2)
