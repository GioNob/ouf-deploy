"""Bind supported caller configuration to the original process and signed request.

No credential is opened here. Properties are read by the existing governed
cohort reader; the mounted inode must be the very same file as that host read.
Unsupported Spring/JVM/CLI overrides fail closed rather than guessing precedence.
"""
import os
import re
from pathlib import PurePosixPath

from .core import require
INGESTION_CONFIG_TARGET = "/run/secrets/ingestion-summary.properties"


def ingestion_properties(actual, expected=None):
    from tools.chatbot_file_cohort.preparation import ingestion_properties as governed_reader
    return governed_reader(actual, expected)
from tools.semantic_live_route_diagnostic.reader import process_ticks

KEYS = ('oufingestionactivationgatewayurl', 'oufingestionactivationtokenfile')
ENV_KEYS = ('OUF_INGESTION_ACTIVATION_GATEWAY_URL', 'OUF_INGESTION_ACTIVATION_TOKEN_FILE')
SELECTORS = {'springconfiglocation', 'springconfigadditionallocation', 'springconfigimport'}
CHANNELS = {'JAVA_TOOL_OPTIONS', 'JDK_JAVA_OPTIONS', '_JAVA_OPTIONS', 'SPRING_APPLICATION_JSON'}


def canonical(value):
    return re.sub('[^a-z0-9]', '', value.lower())


def metadata(info):
    return [info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def configuration(actual, expected=None):
    config = actual['Config']; env = {}
    for item in config.get('Env') or []:
        name, sep, value = item.partition('=')
        require(sep and name not in env, 'UNIQUE_ORIGINAL_CALLER_CONFIGURATION_ENV_REQUIRED')
        env[name] = value
    require(not any(env.get(name) for name in CHANNELS), 'CALLER_CONFIGURATION_OVERLAY_REQUIRES_REVIEW')
    # Do not interpret a shell, JVM or Spring command line. Deny protected
    # overrides even when embedded in a shell argument or using relaxed names.
    args = (config.get('Entrypoint') or []) + (config.get('Cmd') or [])
    require(all(type(arg) is str for arg in args), 'EXACT_CALLER_COMMAND_ARGUMENTS_REQUIRED')
    protected = KEYS + ('springconfig', 'springapplicationjson', 'springprofiles')
    require(not any(any(key in canonical(arg) for key in protected) for arg in args),
            'CALLER_COMMAND_CONFIGURATION_OVERRIDE_REQUIRES_REVIEW')
    require(not any(value and (canonical(name).startswith(('springprofiles', 'springapplicationjson'))
            or (canonical(name).startswith('springconfig') and canonical(name) not in SELECTORS))
            for name, value in env.items()), 'CALLER_SPRING_CONFIGURATION_OVERLAY_REQUIRES_REVIEW')
    selected = {name: value for name, value in env.items() if value and canonical(name) in SELECTORS}
    activation = {name: value for name, value in env.items() if canonical(name) in KEYS}
    if not selected:
        require(set(activation) == set(ENV_KEYS) and all(activation.values()),
                'EXACT_ORIGINAL_CALLER_ENV_CONFIGURATION_REQUIRED')
        binding = {'mode': 'ENVIRONMENT', 'values': activation}
        if expected is not None:
            require(expected == binding, 'ORIGINAL_CALLER_CONFIGURATION_CHANGED')
        return activation[ENV_KEYS[0]], activation[ENV_KEYS[1]], binding
    require(not activation, 'AMBIGUOUS_CALLER_PROPERTIES_AND_ENVIRONMENT')
    require(expected is None or (type(expected) is dict and set(expected) == {'mode', 'selector', 'file'}
            and expected['mode'] == 'SPRING_PROPERTIES' and expected['selector'] == selected),
            'ORIGINAL_CALLER_PROPERTIES_PROFILE_CHANGED')
    parsed, file = ingestion_properties(actual, None if expected is None else expected['file'])
    require(all(type(parsed.get(key)) is str and parsed[key] for key in KEYS),
            'EXACT_ORIGINAL_CALLER_PROPERTIES_REQUIRED')
    pid = actual['State']['Pid']; ticks = process_ticks(pid); fds = []; names = []
    try:
        root = os.open('/proc/' + str(pid) + '/root', os.O_PATH | os.O_DIRECTORY); fds.append(root)
        current = root
        for part in PurePosixPath(INGESTION_CONFIG_TARGET).parts[1:-1]:
            child = os.open(part, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            names.append((current, part, metadata(os.fstat(child)))); fds.append(child); current = child
        leaf = PurePosixPath(INGESTION_CONFIG_TARGET).name
        mounted = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=current); fds.append(mounted)
        require(metadata(os.fstat(mounted)) == file['metadata'], 'SAME_PROCESS_MOUNTED_PROPERTIES_FILE_REQUIRED')
        # Reopen host via governed descriptor walk while the process view is
        # held: catches atomic replacement, including equal-content replacement.
        again, rebound = ingestion_properties(actual, file)
        require(again == parsed and rebound == file and process_ticks(pid) == ticks
                and metadata(os.fstat(mounted)) == metadata(os.stat(leaf, dir_fd=current, follow_symlinks=False)) == file['metadata']
                and all(metadata(os.stat(name, dir_fd=parent, follow_symlinks=False)) == pin for parent, name, pin in names),
                'CALLER_PROPERTIES_CHANGED_DURING_OBSERVATION')
        check = os.open('/proc/' + str(pid) + '/root', os.O_PATH | os.O_DIRECTORY); fds.append(check)
        require(metadata(os.fstat(check)) == metadata(os.fstat(root)), 'CALLER_PROCESS_ROOT_CHANGED')
    finally:
        for fd in reversed(fds): os.close(fd)
    return parsed[KEYS[0]], parsed[KEYS[1]], {'mode': 'SPRING_PROPERTIES', 'selector': selected, 'file': file}


def verify(actual, profile):
    origin, target, binding = configuration(actual, profile.get('callerConfiguration'))
    require(origin == profile['origin'] and target == profile['tokenTarget'],
            'SAME_CONFIGURED_INGESTION_GATEWAY_AND_TOKEN_REQUIRED')
    # Old immutable environment-only profiles remain valid. A properties profile
    # must explicitly bind the file into the signed original-request digest.
    require('callerConfiguration' in profile or binding['mode'] == 'ENVIRONMENT',
            'SIGNED_ORIGINAL_CALLER_PROPERTIES_BINDING_REQUIRED')
