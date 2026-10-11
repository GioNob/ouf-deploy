"""Reviewed delta: all nft commands within an attempt share its deadline."""
from contextlib import contextmanager
from nft_seconds_backend import NftBackend


class DeadlineNftBackend(NftBackend):
    active_deadline = None

    @contextmanager
    def within(self, deadline):
        if self.active_deadline is not None:
            raise RuntimeError('NESTED_NFT_DEADLINE_UNPROVEN')
        self.active_deadline = deadline
        try:
            yield
        finally:
            # Revocation outside the failed attempt keeps its separate bounded
            # command budget; expired admission cannot prevent narrowing.
            self.active_deadline = None

    def run(self, arguments, raw=None, timeout=None):
        budget = self.budget if timeout is None else min(timeout, self.budget)
        if self.active_deadline is not None:
            remaining = self.active_deadline - self.clock()
            if remaining <= 0:
                raise RuntimeError('NFT_ATTEMPT_DEADLINE_UNPROVEN')
            budget = min(budget, remaining)
        return super().run(arguments, raw, timeout=budget)
