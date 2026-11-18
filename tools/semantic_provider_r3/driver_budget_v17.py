"""Installation budget for the source-pinned R3 v17 driver and preparer."""
from tools.semantic_provider_operation.authorization import require


INVALID = 'R3_DRIVER_BUDGET_INVALID'
MIN_SECONDS, MAX_SECONDS = 5, 15


def seconds(value):
    require(set(value) == {'driverBudgetSeconds'}, INVALID)
    budget = value['driverBudgetSeconds']
    require(type(budget) is int and MIN_SECONDS <= budget <= MAX_SECONDS, INVALID)
    return budget


def sources_v17(sources, source_map):
    """Keep the broker's exact module set and edit only the emitted bytes."""
    out = dict(sources)

    def edit(target, old, new):
        path = source_map[target]
        old, new = old.encode('ascii'), new.encode('ascii')
        require(out[path].count(old) == 1, 'R3_V17_SOURCE_CONTRACT_DRIFT')
        out[path] = out[path].replace(old, new)

    for target, budget in (
        ('tools/semantic_provider_admission_v2/preparer_v2.py', 't["budgetSeconds"]'),
        ('tools/semantic_provider_admission_v2/driver_v7.py', 'value["budgetSeconds"]'),
        ('tools/semantic_provider_preexec_native.py', 'budget'),
    ):
        edit(target, f'1 <= {budget} <= 5', f'{MIN_SECONDS} <= {budget} <= {MAX_SECONDS}')
    edit('tools/semantic_provider_preexec_native.py',
         'large. Trusted commands have a five-second maximum; stderr is discarded.',
         'large. Commands use the remaining driver budget; stderr is discarded.')
    return out
