"""Verify immutable cycle receipt against live service; never grants authority."""
def compare(cycle, unit, root):
    pid = unit.get('MainPID', '')
    checks = {
        'secondCycleActive': cycle.get('status') == 'LEASE_ACTIVE',
        'secondCycleCount': type(cycle.get('refreshCount')) is int and cycle['refreshCount'] >= 2,
        'serviceActive': unit.get('ActiveState') == 'active',
        'serviceRunning': unit.get('SubState') == 'running',
        'automaticRestartDisabled': unit.get('Restart') == 'no',
        'sameWorkerPid': isinstance(pid, str) and pid.isdecimal() and int(pid) == cycle.get('workerPid'),
        'exactWorkerProgram': str(root / 'activate.py') in unit.get('ExecStart', '')}
    if not all(checks.values()):
        error = ValueError('EXACT_ACTIVE_LEASE_WORKER_UNPROVEN')
        error.readback_checks = checks
        raise error
    return checks
