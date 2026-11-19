"""One exact READ ONLY V36 query; compare the entire fresh baseline unchanged."""
def bind(base):
    class Fence:
        TABLES = base.TABLES
        JOB = base.JOB
        ASSET = base.ASSET
        def query(self, after=False):
            base.require(type(after) is bool, 'EXACT_V36_QUERY_SELECTOR_REQUIRED')
            return base.query(True)

        def validate(self, facts, profile, migrations, baseline=None, after=False):
            proof = base.validate(facts, profile, migrations, baseline=None, after=True)
            proof.pop('additiveV36AndZeroNewBudgetsProven', None)
            if baseline is not None:
                base.require(facts == baseline, 'V36_STATE_HISTORY_COUNTERS_OR_TRIGGERS_CHANGED')
            return {**proof, 'entireV36SnapshotHash': base.digest(facts), 'installedSchemaVersion': 36, 'databaseMigrationsPerformed': 0,
                    'entireV36SnapshotUnchanged': baseline is not None, 'zeroBudgetsAndEventsProven': True}

        def arguments(self, profile, empty_config, sql):
            base.require(sql == base.query(True), 'ONLY_EXACT_READ_ONLY_V36_QUERY_ALLOWED')
            return base.arguments(profile, empty_config, sql)

    return Fence()
