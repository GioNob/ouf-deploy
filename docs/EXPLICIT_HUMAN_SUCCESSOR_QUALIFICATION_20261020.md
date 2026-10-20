# Expired READY HUMAN successor: qualification candidate

This separate pre-runtime package handles an expired, unambiguous READY session
without replaying the completed Owner7/publication7 actions or the old login
recovery claim. The current installation's retained count is 278/288; these
numbers are reviewed history inputs, never reusable installation defaults.

The current Matrix1.7/Blueprint0.3 baseline and repository AGENTS govern this
work: development authorization does not grant runtime HUMAN/THS authority;
expired authority cannot be extended automatically. This candidate introduces
no call from the existing native executor and does not change its 114 sources.

## Contract

The public review selects one retained root-custodied private journal, its exact
binding, source closure and completed owner plan/result history. It requires an
expired READY window on both recorded clocks and an expired recorded bearer.
It neither opens the predecessor bearer file nor copies credentials. Journal
content remains private; credential values and credential hashes are not
printed. Every installation identity, path, issuer and scope comes from the
reviewed input. No host discovery or issuer fallback is permitted.

Only a fresh, explicit terminal decision can initialize one separate finite
7200-second session. The fixed predecessor claim is consumed before directory
creation. A crash leaves the claim consumed and requires reconciliation. The
predecessor journal and cumulative maximum are retained; the successor starts
at the actual retained count, never zero. Initialization itself sends no OAuth
request and issues no runtime authority.

Each explicit foreground step dispatches at most one HTTP request, reserving
its cumulative attempt before transport. Discovery, device start, one confirmed
poll and provider userinfo are separate steps. Every poll requires a current
confirmation bound to that exact durable challenge. There is no loop, sleep,
background login, automatic refresh or renewal. Explicit transient reads retain
bounded retry state; ambiguous authentication POST outcomes and permanent or
identity failures block. The minimum successful path consumes four attempts.

## Qualification and remaining gates

Local tests cover predecessor custody/history, unchanged cumulative limits,
one-use claims and crash retention, no credential copying, explicit poll
confirmation, provider revocation, missing scopes, changed provider principal,
counter/window drift and a real verified-TLS synthetic provider using the
existing transport. The resulting READY journal is exercised with the concrete
native read-only HUMAN reader. The CI workflow runs the same finite fixtures on
Python3.12 and3.13.5 in root custody.

These are synthetic qualification fixtures, not target IAM authentication,
THS approval, DB admission, runtime rollout or release acceptance. The package
currently has no operator launcher or approved target review; it must not be
used on the VPS until sealed delivery and explicit consent are qualified.
Technical phases remain8/8; functional milestones remain4/6; G3 stays open.

CI success, VPS readiness and CSV end-to-end acceptance are distinct evidence
classes. The operator reports roughly30% first-pass VPS success after CI from
experience. This is not a measured OUF statistic and is not used as an automatic
effort multiplier. Diagnose target failures without resetting state or replaying
consumed claims; record target diagnosis and corrections separately from CI.
