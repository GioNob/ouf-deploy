"""D-053.3 overlay for the sealed R3 runtime and epoch reader/writer contract."""
from tools.semantic_provider_operation.authorization import require


RUNTIME = 'tools/semantic_runtime_v52/semantic_provider_docker_runtime_v52.py'
EPOCHS = 'tools/semantic_provider_operation/epochs.py'


DRIVER_CAPTURE = '''class DriverDenied(Denied):
    def __init__(self, reason, phase, code):
        super().__init__(reason)
        self.detail = {'phase': phase, 'code': code}


DRIVER_OUTPUT_LIMIT = 16384
DRIVER_DENIAL = re.compile(rb'SEMANTIC_PREEXEC_HOOK=DENIED ([A-Z0-9_]{1,80})\\n')


def driver_denial(returncode, stderr, output_ok):
    if returncode > 0 and output_ok and len(stderr) <= DRIVER_OUTPUT_LIMIT:
        match = DRIVER_DENIAL.fullmatch(stderr)
        if match:
            return match[1].decode('ascii')
    return None


def driver_result(args, phase, state, timeout):
    """Drain child output within the old budget, retaining only bounded stderr."""
    with selectors.DefaultSelector() as events:
        deadline = time.monotonic() + timeout
        with subprocess.Popen(args, stdin=subprocess.PIPE if state is not None else subprocess.DEVNULL,
                              stdout=subprocess.PIPE if phase == 'start' else subprocess.DEVNULL,
                              stderr=subprocess.PIPE, env=ENV) as child:
            try:
                if child.stdin is not None:
                    input_bytes = memoryview(canonical(state))
                    os.set_blocking(child.stdin.fileno(), False)
                    events.register(child.stdin, selectors.EVENT_WRITE)
                events.register(child.stderr, selectors.EVENT_READ)
                if child.stdout is not None:
                    events.register(child.stdout, selectors.EVENT_READ)
                stderr = bytearray()
                stdout_size = 0
                while events.get_map():
                    remaining = deadline - time.monotonic()
                    ready = events.select(remaining) if remaining > 0 else ()
                    if not ready:
                        raise subprocess.TimeoutExpired(phase, timeout)
                    for key, _ in ready:
                        if key.fileobj is child.stdin:
                            try:
                                input_bytes = input_bytes[os.write(key.fd, input_bytes[:4096]):]
                                if input_bytes:
                                    continue
                            except BrokenPipeError:
                                pass
                            events.unregister(child.stdin)
                            child.stdin.close()
                            continue
                        chunk = os.read(key.fd, 4096)
                        if not chunk:
                            events.unregister(key.fileobj)
                        elif key.fileobj is child.stderr:
                            stderr.extend(chunk[:DRIVER_OUTPUT_LIMIT + 1 - len(stderr)])
                        else:
                            stdout_size = min(DRIVER_OUTPUT_LIMIT + 1, stdout_size + len(chunk))
                returncode = child.wait(timeout=max(0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                raise subprocess.TimeoutExpired(phase, timeout) from None
            finally:
                if child.poll() is None:
                    child.kill()
    output_ok = stdout_size <= DRIVER_OUTPUT_LIMIT
    return returncode, output_ok, driver_denial(returncode, stderr, output_ok)


'''


def sources_v16(sources, source_map):
    """Patch only the emitted blobs, requiring each source anchor exactly once."""
    emitted = dict(sources)

    def edit(target, old, new):
        source = source_map[target]
        old, new = old.encode(), new.encode()
        raw = emitted[source]
        if b'\r\n' in raw and raw.count(b'\n') == raw.count(b'\r\n'):
            old, new = (value.replace(b'\n', b'\r\n') for value in (old, new))
        require(raw.count(old) == 1, 'R3_V16_SOURCE_CONTRACT_DRIFT')
        emitted[source] = raw.replace(old, new)

    edit(EPOCHS, 'journal ouf.semantic-docker-runtime-journal.v2', 'journal v2 or v3')
    edit(EPOCHS, 'JOURNAL_SCHEMA = "ouf.semantic-docker-runtime-journal.v2"',
         'LEGACY_JOURNAL_SCHEMA = "ouf.semantic-docker-runtime-journal.v2"\n'
         'JOURNAL_SCHEMA = "ouf.semantic-docker-runtime-journal.v3"')
    edit(EPOCHS, '    require(set(value) == JOURNAL_FIELDS and value["schema"] == JOURNAL_SCHEMA\n',
         '''    v3 = value.get("schema") == JOURNAL_SCHEMA
    expected_fields = JOURNAL_FIELDS | {"driverDenial"} if v3 else JOURNAL_FIELDS
    require(set(value) == expected_fields and (v3 or value["schema"] == LEGACY_JOURNAL_SCHEMA)
''')
    edit(EPOCHS, 'and value["containerId"] == cid and value["epoch"] == epoch,',
         'and value["containerId"] == cid and type(value["epoch"]) is int and value["epoch"] == epoch,')
    edit(EPOCHS, '    return value\n', '''    if v3:
        denial = value["driverDenial"]
        require(denial is None or (value["state"] == "FAILED" and type(denial) is dict
                and set(denial) == {"phase", "code"} and denial["phase"] in ("hook", "start")
                and type(denial["code"]) is str and FAILURE.fullmatch(denial["code"])),
                "EPOCH_DRIVER_DENIAL_INVALID")
    return value
''')

    edit(RUNTIME, 'import re\n', 'import re\nimport selectors\n')
    edit(RUNTIME, 'def inactive(config, cid, operation, root, argv):',
         DRIVER_CAPTURE + 'def inactive(config, cid, operation, root, argv):')
    edit(RUNTIME, "'openedAt': opened_at, 'failure': None}",
         "'openedAt': opened_at, 'failure': None, 'driverDenial': None}")
    edit(RUNTIME, '''                if state is None: capture(args, timeout=admission_remaining(deadline))
                else:
                    result = subprocess.run(args, input=canonical(state), stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL, timeout=admission_remaining(deadline, 10), env=ENV)
                    admission_remaining(deadline)
                    require(result.returncode == 0, 'OCI_ADMISSION_GATE_DENIED')''',
         '''                if mode in ('hook', 'start'):
                    reason = 'OCI_ADMISSION_GATE_DENIED' if mode == 'hook' else 'ADMISSION_OR_DRIVER_FAILED'
                    cap = 10 if mode == 'hook' else 20
                    returncode, output_ok, code = driver_result(args, mode, state, admission_remaining(deadline, cap))
                    if mode == 'hook' or code is not None: admission_remaining(deadline)
                    if code is not None:
                        raise DriverDenied(reason, mode, code)
                    require(returncode == 0 and output_ok, reason)
                else:
                    capture(args, timeout=admission_remaining(deadline))''')
    edit(RUNTIME, "                        publish('DELETING', failure=None)",
         "                        detail = {'driverDenial': None} if 'driverDenial' in record else {}\n"
         "                        publish('DELETING', failure=None, **detail)")
    edit(RUNTIME, '''                    started = parse(capture([config['runtimePath'], '--root', str(root), 'state', cid],
                                            timeout=admission_remaining(deadline)))''',
         '''                    try:
                        started = parse(capture([config['runtimePath'], '--root', str(root), 'state', cid],
                                                timeout=admission_remaining(deadline)))
                        require(type(started) is dict
                                and all(type(started.get(key)) is str for key in ('id', 'bundle', 'status'))
                                and type(started.get('pid')) is int, 'STARTED_RUNTIME_STATE_UNPROVEN')
                    except (Denied, OSError, ValueError, subprocess.SubprocessError):
                        admission_remaining(deadline)
                        raise Denied('STARTED_RUNTIME_STATE_UNPROVEN') from None''')
    edit(RUNTIME, "                try: publish_epoch(base, record, {**record, 'state': 'FAILED', 'failure': code}, epochs)",
         '''                value = {**record, 'state': 'FAILED', 'failure': code}
                if 'driverDenial' in value:
                    value['driverDenial'] = error.detail if isinstance(error, DriverDenied) else None
                try: publish_epoch(base, record, value, epochs)''')
    return emitted
