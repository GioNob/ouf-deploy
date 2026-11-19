"""R-022 changes to the composed v21 closure, before its single digest seal."""
from tools.semantic_provider_operation.authorization import require
from .lease_observability_overlay_v18 import ADAPTIVE, CONTINUOUS, JOURNAL, RECOVERY, SUPERVISOR
from .dns_parallel_overlay_v22 import apply_dns, EVENT_FIELDS, INDEX_LIMITS


DRIFT = 'R3_V22_SOURCE_CONTRACT_DRIFT'
POLICY = RECOVERY + 'lease_renewal_v18.py'


def sources_v22(sources, source_map):
    out = dict(sources)

    def edit(target, old, new):
        path = source_map[target]
        raw = out[path]
        eol = b'\r\n' if b'\r\n' in raw else b'\n'
        before, after = (s.encode('ascii').replace(b'\n', eol) for s in (old, new))
        require(raw.count(before) == 1, DRIFT)
        out[path] = raw.replace(before, after)

    edit(POLICY, '"renewalMarginSeconds", "lockWaitSeconds",',
         '"dnsTimeoutSeconds", "immediateMinimumSeconds", "renewalMarginSeconds", "lockWaitSeconds",')
    edit(POLICY, 'if not (integer(value["renewalMarginSeconds"]',
         'if not (integer(value["dnsTimeoutSeconds"], 3, 30)\n'
         '            and integer(value["immediateMinimumSeconds"], 1, 300)\n'
         '            and integer(value["renewalMarginSeconds"]')
    edit(POLICY, 'def retry_reserve(profile):', '''def dns_profile(owner, renewal):
    validate(renewal)
    return {**owner["dns"], "timeoutSeconds": renewal["dnsTimeoutSeconds"]}


def retry_reserve(profile):''')
    edit(POLICY, 'if not (required <= margin <= attempt + COMMIT_SECONDS',
         'minimum = value["immediateMinimumSeconds"]\n'
         '    if not (dns == value["dnsTimeoutSeconds"] and required + 2 <= minimum < margin\n'
         '            and margin <= attempt + COMMIT_SECONDS')
    edit(SUPERVISOR, '    c = cfg["coordinator"]\n    require(owner',
         '    c = cfg["coordinator"]\n    policy = loaded["lease_renewal_v18"]\n'
         '    renewal = cfg["leaseRenewal"]\n    try:\n'
         '        profile = policy.dns_profile(owner, renewal)\n'
         '    except ValueError as error:\n        raise Denied(str(error)) from None\n    require(owner')
    edit(SUPERVISOR, 'canonical({**owner["dns"], "timeoutSeconds": 10})', 'canonical(profile)')
    edit(SUPERVISOR, '    policy = loaded["lease_renewal_v18"]\n    renewal = cfg["leaseRenewal"]\n'
         '    profile = {**owner["dns"], "timeoutSeconds": 10}\n', '')
    edit(SUPERVISOR, 'LeaseOwner(owner["kernel"], {**owner["dns"], "timeoutSeconds": 10}, backend)',
         'LeaseOwner(owner["kernel"], profile, backend)')
    # Both independently loaded DNS aliases use one admission registry in this process.
    edit(SUPERVISOR, '    c = cfg["coordinator"]\n    policy =',
         '    loaded["dns"]._workers = installed["semantic_provider_dns"]._workers\n'
         '    loaded["dns"]._workers_lock = installed["semantic_provider_dns"]._workers_lock\n'
         '    c = cfg["coordinator"]\n    policy =')

    edit(ADAPTIVE, "require(remaining >= reserve, 'LEASE_READ_WINDOW_EXHAUSTED')",
         "require(remaining >= policy['immediateMinimumSeconds'], 'LEASE_READ_WINDOW_EXHAUSTED')")
    edit(CONTINUOUS, "            if expires - started < self.c.renewal['renewalMarginSeconds']:\n"
         "                raise Temporary('DNS_WINDOW_TOO_SHORT')\n", '')
    # Select the lane at actual renewal entry. The scope and attempt limits
    # can shorten the original lease deadline, even in the immediate band.
    edit(CONTINUOUS, "            reserve = retry_reserve(self.c.owner.profile)",
         "            now = self.r.now()[1]\n"
         "            immediate = expires - now < self.c.renewal['renewalMarginSeconds']\n"
         "            minimum = self.c.renewal['immediateMinimumSeconds']\n"
         "            if immediate and deadline - now < minimum - COMMIT_SECONDS:\n"
         "                raise Temporary('DNS_WINDOW_TOO_SHORT')\n"
         "            reserve = retry_reserve(self.c.owner.profile)")
    edit(CONTINUOUS, "if index >= len(delays) or row['attempts'] >= self.r.policy.max_attempts:",
         "if (immediate or error.code == 'COMMON_LOCK_TIMEOUT' or index >= len(delays)\n"
         "                            or row['attempts'] >= self.r.policy.max_attempts):")
    _publication(out, source_map, edit)
    edit(JOURNAL, "    'tick': '',", EVENT_FIELDS + "    'tick': '',")
    edit(JOURNAL, "TIMING_LIMITS = {'flow':", "TIMING_LIMITS = {" + INDEX_LIMITS + "'flow':")
    edit(JOURNAL, "return type(value) is int and 0 <= value <= TIMING_LIMITS[kind]",
         "lower = 1 if kind == 'attempt' else 0\n"
         "    return type(value) is int and lower <= value <= TIMING_LIMITS[kind]")
    apply_dns(out, source_map, edit)
    return out


def _publication(out, source_map, edit):
    edit(CONTINUOUS, 'class Supervisor:', '''class RenewalCancelled(Exception):
    pass


class PublicationAmbiguous(Exception):
    pass


class Supervisor:''')
    edit(CONTINUOUS, 'def publish_renewal(self, evidence, deadline, expected):',
         'def publish_renewal(self, evidence, deadline, expected, stop=None):')
    edit(CONTINUOUS, 'adapter.publish_renewal(evidence, deadline, expected)',
         'adapter.publish_renewal(evidence, deadline, expected, stop)')
    # Mark ambiguity starting at the first attempted journal CAS, including
    # nominally permanent readback failures and zero-TTL errors after apply.
    source = out[source_map[CONTINUOUS]].decode('ascii').replace('\r\n', '\n')
    first = '        with backend.within(deadline), self.incident.lock(self.c.hold_until(lock_deadline)):'
    last = '            return fingerprint(ready)'
    require(source.count(first) == source.count(last) == 1 and source.index(first) < source.index(last), DRIFT)
    body = source[source.index(first):source.index(last) + len(last)]
    pending = '            self.c.publish(previous, pending)'
    ready = '            self.c.publish(pending, ready)'
    require(body.count(pending) == body.count(ready) == 1, DRIFT)
    guarded = body.replace(pending, """            if stop is not None and stop.is_set():
                raise RenewalCancelled
            if self.clock() >= deadline:
                raise BeforeLeaseMutation('DNS_WINDOW_TOO_SHORT')
            mutating = True
""" + pending)
    guarded = guarded.replace(ready, """            if stop is not None and stop.is_set():
                raise RenewalCancelled
            if self.clock() >= deadline:
                raise Temporary('DNS_WINDOW_TOO_SHORT')
""" + ready)
    guarded = guarded.replace(last, "            if self.clock() >= deadline:\n"
                              "                raise Temporary('DNS_WINDOW_TOO_SHORT')\n" + last)
    edit(CONTINUOUS, body, '        mutating = False\n        try:\n'
         + '\n'.join('    ' + line for line in guarded.splitlines())
         + '\n        except Exception as error:\n'
         '            if not mutating:\n                raise\n'
         "            self.incident.failed(error, 'PUBLICATION_OUTCOME_AMBIGUOUS')\n"
         '            raise PublicationAmbiguous from error')
    edit(CONTINUOUS, '        except Temporary as error:\n            incident.failed(error)',
         "        except RenewalCancelled:\n            self.active_here = False\n"
         "            return self.r.pause(row, 'CANCELLED', 'CANCELLED_BY_OWNER')\n"
         "        except PublicationAmbiguous:\n            self.active_here = False\n"
         "            return self.r.pause(row, 'RECONCILE_REQUIRED', 'PUBLICATION_OUTCOME_AMBIGUOUS')\n"
         '        except Temporary as error:\n            incident.failed(error)')
