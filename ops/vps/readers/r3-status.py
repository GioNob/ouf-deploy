"""Fixed, non-authoritative diagnostic snapshot; never verifies/changes authority."""
import runpy
import sys
from pathlib import Path

globals().update({k: v for k, v in runpy.run_path(str(Path(__file__).with_name('r3_common.py'))).items() if not k.startswith('__')})


def main():
    if len(sys.argv) != 1:
        raise ValueError('NO_ARGUMENTS')
    cfg = configuration()
    auth_root = Path(cfg['operation']['authorizationRoot'])
    numbers = [int(p.stem) for p in auth_root.glob('*.json') if re.fullmatch(r'[1-9][0-9]*', p.stem)]
    number = max(numbers)
    raw = read(auth_root / (str(number) + '.json'))
    auth = json.loads(raw)
    emit(step='authorization', sequence=number, decision=scalar(auth['decision']), sha256=hashlib.sha256(raw).hexdigest(), verified=False)
    for role, cid in candidates(cfg).items():
        base = Path(cfg['registryRoot']) / cid
        epoch = None
        try:
            pointer = document(base / 'current')
        except FileNotFoundError:
            pointer = None
        if pointer is not None:
            n = positive(str(pointer['epoch']))
            raw = read(epoch_base(cfg, cid, n) / 'adapter.json')
            if hashlib.sha256(raw).hexdigest() != pointer['journalSha256']:
                raise ValueError('EPOCH_POINTER_DRIFT')
            row = adapter_journal(raw, cid, n)
            detail = driver_denial_fields(row)
            live = False
            if row['state'] == 'STARTED' and row['bootId'] == read(PROC / 'sys/kernel/random/boot_id').decode().strip():
                try:
                    live = ticks(row['generation']['pid']) == row['generation']['startTicks']
                except FileNotFoundError:
                    pass
            epoch = dict(epoch=n, live=live, **fields(row, ('state', 'failure')), **detail)
            denials = []
            for e in (n, n - 1) if n > 1 else (n,):
                denials.extend(epoch_base(cfg, cid, e).glob('broker-denial-*.json'))
            if denials:
                epoch['lastDenial'] = fields(document(max(denials, key=lambda p: (p.stat().st_mtime_ns, str(p)))), ('reason',))
        meta = json.loads(command(['/usr/bin/docker', 'inspect', cid]))[0]
        emit(step='role', role=role, epoch=epoch, docker={
            'Status': scalar(meta['State']['Status']), 'Pid': meta['State']['Pid'],
            'RestartPolicy': fields(meta['HostConfig']['RestartPolicy'], ('Name', 'MaximumRetryCount'))})
    binding = cfg['leaseQuiesce']['configuration']
    sup = bound(binding)
    status = document(sup['statusPath'])
    emit(step='supervisor', **fields(status, ('state', 'reason', 'activationsLastHour')),
         epochs={r: scalar(status['epochs'][r]) for r in ROLES},
         updatedAt=status['updatedAt'] if recovery_integer(status.get('updatedAt'), 0) else None,
         leaseRecovery=lease_recovery(sup, status, binding['sha256']))
    emit(step='lease', **fields(document(sup['coordinator']['journalPath']), ('state', 'leaseAuthorized')))
    tables = json.loads(command(['/usr/sbin/nft', '-j', 'list', 'tables']))
    emit(step='tables', tables=sorted([[t['table']['family'], t['table']['name']]
         for t in tables['nftables'] if 'table' in t and t['table']['family'] in ('inet', 'bridge')
         and re.fullmatch(r'ouf_r3_[A-Za-z0-9_]+', t['table']['name'])]))
    return 0


if __name__ == '__main__':
    raise SystemExit(entry(main))
