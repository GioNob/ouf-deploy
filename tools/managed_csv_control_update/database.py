"""Reuse the qualified native SQL transport with eight NEW scoped READ attempts."""
import hashlib
import os
from pathlib import Path
import signal
import stat
import subprocess
import time
import types

SQL_STAGES = ('VERIFY_CURRENT_ADMISSION', 'VERIFY_PRESTOP_STATE', 'VERIFY_PRESTART_STATE',
              'VERIFY_POSTSTART_STATE', 'VERIFY_BEFORE_MCP', 'VERIFY_FINAL_STATE', 'VERIFY_QUIESCED_BACKUP')


def bind(base):
    def observe(ports, stage, sample=None):
        ctx = ports.ctx; c = ctx.core; row = ports.execution.record(); i = row['nextStage']; query = ctx.fence.query(True)
        c.require(sample in ('BEFORE', 'AFTER') if stage == 'VERIFY_QUIESCED_BACKUP' else sample is None, 'EXACT_BACKUP_SQL_SAMPLE_REQUIRED')
        c.require(stage in SQL_STAGES and ports.stages[i] == stage and len(row['effects']) == i+1
                  and row['effects'][-1]['state'] == 'CLAIMED' and ctx.review['maintenanceSqlAuthorized'] is True
                  and ctx.review['operationalSqlHash'] == c.sha(query.encode()), 'NEW_CLAIMED_READ_ONLY_V36_SQL_AUTHORITY_REQUIRED')
        pgid = ctx.database_profile['postgresRuntimeBinding']['containerId']; pg = ports.container(pgid)
        base.check_postgres(ctx, pg); pin = ctx.p.process_pin(pg['State']['Pid'])
        c.require(pin == ctx.inputs['currentProcessPins']['peer-'+pgid[:16]], 'SAME_CAPTURED_POSTGRES_PROCESS_REQUIRED')
        base.check_docker(ctx); config = ctx.root/'empty-docker-config'
        if not config.exists():
            config.mkdir(mode=0o700); ctx.sync(ctx.root)
        meta = config.lstat()
        c.require(stat.S_ISDIR(meta.st_mode) and meta.st_uid == meta.st_gid == 0 and stat.S_IMODE(meta.st_mode) == 0o700
                  and not any(config.iterdir()), 'EMPTY_PRIVATE_SQL_DOCKER_CONFIG_REQUIRED')
        args = ctx.fence.arguments(ctx.database_profile, config, query)
        ports.reserve('sqlSessions'); ctx.evidence('operational-sql-dispatch-claim', {'stage': stage, 'sample': sample,
                     'sqlSha256': c.sha(query.encode()), 'attemptNotCompletion': True})
        ctx.gate.check(); ctx.check_sources(); started = time.monotonic(); paths = []; streams = []; proc = None
        label = (stage+('-'+sample if sample else '')).lower()
        try:
            for suffix in ('stdout', 'stderr'):
                path = ctx.root/(label+'-'+suffix+'.log'); paths.append(path)
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
                os.fchmod(fd, 0o400); streams.append(os.fdopen(fd, 'wb'))
            proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=streams[0], stderr=streams[1], cwd='/',
                                    env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}, start_new_session=True)
            while proc.poll() is None:
                ctx.gate.check(); ctx.watch.ensure_alive(ctx)
                c.require(time.monotonic()-started < 20 and all(path.stat().st_size <= 262144 for path in paths), 'FINITE_BOUNDED_V36_SQL_REQUIRED')
                time.sleep(.05)
        finally:
            if proc is not None and proc.poll() is None:
                os.killpg(proc.pid, signal.SIGKILL); proc.wait(timeout=3)
            for stream in streams:
                stream.flush(); os.fsync(stream.fileno()); stream.close()
            ctx.sync(ctx.root)
        def receipt(path):
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                before = os.fstat(fd)
                c.require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0 and before.st_nlink == 1
                          and stat.S_IMODE(before.st_mode) == 0o400 and before.st_size <= 262144, 'PRIVATE_SQL_RECEIPT_CUSTODY_REQUIRED')
                raw = os.read(fd, 262145)
                c.require(len(raw) == before.st_size and ctx.p.frame(before) == ctx.p.frame(os.fstat(fd)) == ctx.p.frame(path.lstat()), 'SQL_RECEIPT_CHANGED')
                return raw
            finally:
                os.close(fd)
        raw, error = receipt(paths[0]), receipt(paths[1])
        ctx.evidence('operational-sql-receipt', {'stage': stage, 'sample': sample, 'returnCode': proc.returncode,
                     'stdoutSha256': c.sha(raw), 'stderrSha256': c.sha(error)})
        c.require(proc.returncode == 0 and 0 < len(raw) <= 131072, 'READ_ONLY_V36_SQL_RESULT_REQUIRED')
        facts = ctx.p.decode(raw); baseline = getattr(ctx, 'operational_baseline', None)
        proof = ctx.fence.validate(facts, ctx.database_profile, ctx.migrations, baseline, after=True)
        if baseline is None:
            c.require(stage == 'VERIFY_CURRENT_ADMISSION', 'INITIAL_V36_STATE_BASELINE_REQUIRED'); ctx.operational_baseline = facts
        else:
            c.require(stage != 'VERIFY_CURRENT_ADMISSION', 'NO_OPERATIONAL_BASELINE_RESET')
        after = ports.container(pgid); base.check_postgres(ctx, after)
        c.require(ctx.p.process_pin(after['State']['Pid']) == pin, 'POSTGRES_CHANGED_DURING_V36_SQL')
        ctx.evidence('operational-state-proof', {'stage': stage, 'sample': sample, **proof})
        return proof

    return types.SimpleNamespace(retained_transport=base.retained_transport, check_docker=base.check_docker,
                                 check_postgres=base.check_postgres, observe=observe)
