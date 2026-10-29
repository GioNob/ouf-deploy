#!/usr/bin/env bash
# Successful custody scope is consumed. Preserve outputs; do not replay.
printf '%s\n' 'CUSTODY_CAPTURE_SCOPE_CONSUMED_NO_REPLAY' >&2
exit 1
