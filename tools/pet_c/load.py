"""Driver R-043 asincrono: una popolazione di workflow, una o più ondate."""

import asyncio
import random
import time
from dataclasses import asdict, dataclass
from fractions import Fraction
from typing import Protocol

from .manifest import canonical, digest


CLASSES = ("start", "poll", "wait", "retry", "status", "renewal")


@dataclass(frozen=True)
class Action:
    workflow: int
    subject: str
    tenant: int
    operation: str
    wave: int


class Transport(Protocol):
    async def execute(self, action: Action) -> int:
        """Eseguire l'azione nel contesto del workflow e restituire il codice HTTP."""


class FakeTransport:
    async def execute(self, action):
        await asyncio.sleep(0)
        return 200


def schedule(manifest, waves=1):
    """Ripartizione ai maggiori resti per ondata, spareggio nell'ordine CLASSES."""
    load = manifest["load"]
    n = load["workflows"]
    if type(waves) is not int or waves < 1:
        raise ValueError("INVALID_WAVES")
    exact = [Fraction(str(load["mix"][k])) * n for k in CLASSES]
    counts = [int(v) for v in exact]
    order = sorted(range(len(counts)), key=lambda i: exact[i] - counts[i], reverse=True)
    for i in order[:n - sum(counts)]:
        counts[i] += 1
    operations = [k for k, count in zip(CLASSES, counts) for _ in range(count)]
    rng = random.Random(load["seed"])
    subjects = [digest(canonical([manifest["runId"], "pet-subject", i]))
                for i in range(load["subjects"])]
    result = []
    for wave in range(waves):
        rng.shuffle(operations)
        result.append([Action(i, subjects[i % len(subjects)], i % load["tenants"], op, wave)
                       for i, op in enumerate(operations)])
    return result


async def execute(calendar, transport, emit, clock=time.monotonic):
    """Barriera tra ondate; fino a N workflow concorrenti senza creare N thread."""
    async def one(action):
        common = asdict(action)
        start = clock()
        emit(dict(common, kind="actionStart", t=start))
        try:
            code = await transport.execute(action)
            if type(code) is not int or not 100 <= code <= 599:
                raise ValueError("INVALID_TRANSPORT_CODE")
            outcome = "ok" if 200 <= code < 300 else "error"
        except TimeoutError:
            code, outcome = 0, "timeout"
        except Exception:
            code, outcome = 0, "error"
        end = clock()
        emit(dict(common, kind="actionEnd", t=end, code=code, outcome=outcome, duration=end-start))

    for wave in calendar:
        await asyncio.gather(*(one(action) for action in wave))
