"""Finite recovery time excludes verified healthy intervals; no budget reset."""
from bounded_recovery import Recovery, number, require


class LeaseRecovery(Recovery):
    PROFILE = 'ouf.lease-cumulative-recovery-time.v1'

    def initial(self):
        return {**super().initial(), 'timeAccountingProfile': self.PROFILE,
                'healthyWallSeconds': 0, 'healthyMonotonicSeconds': 0, 'publicationCount': 0}

    def validate_time_accounting(self, row):
        require(row.get('timeAccountingProfile') == self.PROFILE
                and number(row.get('healthyWallSeconds'))
                and number(row.get('healthyMonotonicSeconds')),
                'DURABLE_RECOVERY_TIME_ACCOUNTING_REQUIRED')

    def _step(self, *, cancelled=False):
        self.validate_time_accounting(self.journal.read())
        return super()._step(cancelled=cancelled)

    def remaining(self, row):
        self.validate_time_accounting(row)
        wall, mono = self.now()
        healthy_wall = row['healthyWallSeconds']
        healthy_mono = row['healthyMonotonicSeconds']
        if row['state'] == 'ACTIVE':
            # This interval is closed durably on every subsequent transition.
            healthy_wall += max(0, wall - row['lastWall'])
            healthy_mono += max(0, mono - row['lastMonotonic'])
        wall_elapsed = wall - row['startedWall']
        mono_elapsed = mono - row['startedMonotonic']
        require(healthy_wall <= wall_elapsed and healthy_mono <= mono_elapsed,
                'RECOVERY_TIME_ACCOUNTING_UNPROVEN')
        return min(self.policy.max_elapsed - (wall_elapsed - healthy_wall),
                   self.policy.max_elapsed - (mono_elapsed - healthy_mono))

    def save(self, previous, state, reason, **values):
        self.validate_time_accounting(previous)
        wall, mono = self.now()
        healthy_wall = previous['healthyWallSeconds']
        healthy_mono = previous['healthyMonotonicSeconds']
        if previous['state'] == 'ACTIVE':
            healthy_wall += max(0, wall - previous['lastWall'])
            healthy_mono += max(0, mono - previous['lastMonotonic'])
        values.update(healthyWallSeconds=healthy_wall, healthyMonotonicSeconds=healthy_mono)
        count = previous.get('publicationCount', 0)
        require(type(count) is int and count >= 0, 'LEASE_PUBLICATION_COUNT_UNPROVEN')
        values['publicationCount'] = count + (1 if state == 'ACTIVE' and reason in {'RECOVERED', 'RENEWED'} else 0)
        return super().save(previous, state, reason, **values)
