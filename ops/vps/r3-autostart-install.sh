#!/bin/bash
# D-045 / task-61. Consegna LOCALE; nessun download. Non avvia il provider.
# Uso da checkout locale verificata: sudo bash ops/vps/r3-autostart-install.sh plan
#                              sudo bash ops/vps/r3-autostart-install.sh apply <planSha256>
set -euo pipefail
umask 077
# Claude fills this pin after review and commit (D-001).
C=0000000000000000000000000000000000000000
[[ "$C" =~ ^[0-9a-f]{40}$ && "$C" != 0000000000000000000000000000000000000000 ]] \
  || { echo 'runbook non ancora fissato a un commit' >&2; exit 2; }
SOURCE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
exec /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C OPENSSL_CONF=/dev/null \
  /usr/bin/python3.13 -I -B - "$C" "$SOURCE" "${1:-}" "${2:-}" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

PIN, SOURCE, MODE, REQUESTED = sys.argv[1:]
SOURCE = Path(SOURCE)
DEST = Path('/etc/ouf/semantic-provider-r3-autostart')
UNIT = Path('/etc/systemd/system/ouf-semantic-r3-autostart.service')
S = '/etc/ouf/deploy-snapshots'
PYTHON_SHA = '889c603f0d17cb54060951bcf4c4f9b8c9ebd9e52b392c70209bbb9755d797d9'
# BEGIN DELIVERY (same LF blobs as r3-operate.sh, plus the boot driver/entrypoint)
MANIFEST = {
    'ops/vps/r3-settings.json': '4b1aa5560a23657b92fe0a99915d747d02d272a0b765c5b719921f4007d5c150',
    'scripts/autostart-semantic-provider-r3.py': '0d280a2f0608a564f582f5f6058b4950ea12033b4c4b25f6a504076a54a03449',
    'scripts/install-semantic-provider-r3.py': 'd8c49b543bc73f1ea3b85f41d7196fea3ee614b934f1514d8488fcc8edfa0d76',
    'scripts/issue-semantic-provider-operation-authorization.py': '21bc0e9819fe11c78ef87ff76823e7a19ee23dd5cb1c00454ba844a0c9501f41',
    'scripts/migrate-semantic-lease-kernel.py': '7143499813c70c936e0c2792b2e19d44a3cd32cac072fd5b82312ae4dd923901',
    'scripts/operate-semantic-provider-r3.py': 'f1f1dca6447a2c69d4b7d08fe765cb10012da36e9dc07aff7c224a2db0d76926',
    'scripts/prepare-semantic-provider-b1-rootfs-v3.py': '29899e5ee25aa9e772f21fb62fb473706cdf2b8f921034efeccb3b284d350397',
    'scripts/prepare-semantic-provider-b1-rootfs.py': '8107d055fe0bfd8fe363506f39ffa006f157a292a54bbcbf4de11b011816178d',
    'scripts/restore-semantic-provider-r3.py': '1be4b6cd69f0c70959627f87502de307488ebca1862928b984b653e290e3fdd8',
    'scripts/semantic-provider-admission-preparer-v2.py': '7e041ddf4e7668861cc5ae111f6069f73eeda32be065622ee51381129a4f9b57',
    'scripts/semantic-provider-deployment-broker-v2.py': '6e97807d5fa010ec7bc670a49533a031dc8f1d5e2472d8569368adfdc15b2d7c',
    'scripts/semantic-provider-lease-supervisor-v2.py': '0311cd4c3515a68530605ee201ccb7cbbc46d5ab989427efd174e6a647826ec5',
    'scripts/semantic-provider-lease-supervisor-v3.py': '3cb4c858935df6538cb1c9934def0f40cc9ea7fc393931aeb38ab63633bbaf8b',
    'scripts/semantic-provider-preexec-hook-v2.py': '834b5b6ae60d0cd37269d2592b31db7dcca2c02639f774a169e030548767df03',
    'scripts/upgrade-semantic-provider-r3.py': 'd36753cd23b2c993a43e2b6b04062304b575567a13267a1d3247602df5b11639',
    'tools/semantic_acceptance_v51/__init__.py': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    'tools/semantic_acceptance_v51/issuance.py': 'd019d4558c529add5fb3a7b052df3d8b92843167d6093f966b0b9b02265a3cd4',
    'tools/semantic_authority_mandates/mandates.py': '86e70b8cc043c6b5b44b186601d098e71c46130039fe9d35d3c1529adfc09a79',
    'tools/semantic_b1_acceptance/__init__.py': 'b1cddc8e0de31b27e96120f5a55079f238ac683eddd31eb602d23a80a8f6880d',
    'tools/semantic_b1_acceptance/acceptance.py': '5179cf466af5e823a75caf68d3e3f772c3e3cc44d5f57f875e848ba02cd25708',
    'tools/semantic_b1b2_authority/__init__.py': '19342edb368bf1c6bf439c615fc2c2452c16a1742f858311a2d65fe9d752a8a7',
    'tools/semantic_b1b2_authority/authority.py': '04510e275622cde812da86599e5a191a0f7575650b32aa3208d1b6d47768c728',
    'tools/semantic_cohort_admission/cohort-draft/tools/materialize_semantic_shared_faces.py': '66986436206e9448e0bad58b651f4802a53e54eb179327c7050d963c22f33b62',
    'tools/semantic_cohort_admission/cohort-draft/tools/materialize_southbound_kernel.py': '98e3004300226fecd509a46c009585df14021927f20d4e5c82d8ff7a8a8180de',
    'tools/semantic_cohort_admission/cohort-draft/tools/materialize_southbound_kernel_v2.py': '5144360babceb42530f252efef66a0b9d1f682d4d5a6763c07b567ed661b1da6',
    'tools/semantic_cohort_admission/cohort-draft/tools/materialize_southbound_lease_refresh.py': '1c0d7f1243752fe216ef62eefbc2e3253b8f2503b518fafe11277e4d7721a084',
    'tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_deployment_admission.py': 'fccde9a325939b400a95dc5e8714755727ed57b476b01c82019a15ffac8f8df4',
    'tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_deployment_authentication.py': '29e1942733abc74e8eb21eb927427c3e6e39806b06492f1dc614bd0805e53013',
    'tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_deployment_consumption.py': '053e2e5031cd51adf957388296a808cd8ba824dbc2ab671143e756312d050aef',
    'tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_deployment_producer.py': '582371358c769f7724fb76bb17fd5e11530a09ab06c19a3a66351fc77d984776',
    'tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_deployment_protocol.py': '53f5629c3a57de622e51a05f9bf86b29f34328bf5756857afa458fb738f24e15',
    'tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_dns.py': 'c466172113d1ffe850bf2c69762113b55fbc65d9091c96dca98a74548fddf930',
    'tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_lease_coordination.py': 'e267e0f86637191b9830895930daa35afc10fec733b6957f427ab8a0ccddf587',
    'tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_lease_nft.py': '7a5f2b21c096228a3e4d298674e380f667c3004dd6d8ec19934a2302844c0f93',
    'tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_lease_owner.py': '92736eebeccf344e565186bce94d29c65ffe1d50638d57eae81486e7b26e884d',
    'tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_node_observation.py': '5a355a9904b6fc4bf665bb79c438e1cb9f3d11f8c2505b16df9834c046fde9c2',
    'tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_peer_bindings.py': '4d99b60459d7122b5126d8424fb6233a9f3de15858219cd9061131b23f45af8b',
    'tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_preexec.py': '53eb9b79efcdca0ffe93bb0c80a582a285caf9126fd97e930fa503b6106eb797',
    'tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_preexec_native.py': 'ef0b98c96879933480a26418edc2b971b21a116509ac87cbc39e3b2062e7a528',
    'tools/semantic_frame_compiler/compile_creation_frame_policy.py': '36ee627e524415002a98fede8d7e61ad22ae95b6fec6b6686c1e01d878be570d',
    'tools/semantic_frame_compiler/frame-observer-v2.py': '59368071f27a27be5d2501bf1128c617102133f5e0e670dc61f7c8a8f697e08a',
    'tools/semantic_frame_compiler/frame-observer.py': '122a1a44705892ba577d2e83467f39870627ffc16685f886757828611063b3fc',
    'tools/semantic_image_rootfs/prepare_provider_image_rootfs.py': 'cc2e238c37650f9fa77a2b3319160ef09aa61e1a5bd673e624ad5a9f0106eb32',
    'tools/semantic_lease_kernel_migration/__init__.py': 'f28e340dc4cbae36c07010190190d5a8479e5fef730965ba1c2b33dd36ad2496',
    'tools/semantic_lease_kernel_migration/boot_dispatcher.py': '6524076bbfeb54546df2ccb2e5b1d3ac051b919c8f75200b70dde1d958a9aa9b',
    'tools/semantic_lease_kernel_migration/boot_runner_v2.py': 'e6f968e939842fcf71c6b1632886eeb377df9b1ce57f390293b4bb34c1afe713',
    'tools/semantic_lease_kernel_migration/cli.py': '6ef7827768ecb52fcd542a403c50f1d3b19cfc6e847bbe8af0da4ac5d86cd67d',
    'tools/semantic_lease_kernel_migration/migration.py': 'cbcd08ac71d0221f60530125b52861e5a23a37896116c3224576b883ced45464',
    'tools/semantic_lease_kernel_migration/native.py': '1ab1a3568227f604f4d4c87a8aae8bb88476e96edfba8e0269846762cf622a22',
    'tools/semantic_lease_recovery/activation_core.py': '06d14a340db6d35a795115fd921f901e1cd0de74c06174562107270b08fc7c2a',
    'tools/semantic_lease_recovery/activation_core_v2.py': 'c8c7a6841b1427f677349a889e6cb4502ce5bb5a28f6a5b65d5e72fbc2ae1aeb',
    'tools/semantic_lease_recovery/adaptive_supervisor.py': '08a354cfbea6a31ed1ea21dd80ddab0d0f983e3a0143a6f656124cf843d5635c',
    'tools/semantic_lease_recovery/adaptive_supervisor_v2.py': '7a6be86794002e32b79a4c9c4ac0a0913eebe3f5585e9b24dcd62fe5613449ae',
    'tools/semantic_lease_recovery/bounded_recovery.py': 'ed126f33b17581ae784c82ce3f0ec8b16c266d5ad78481a1890385736bd61dfd',
    'tools/semantic_lease_recovery/continuous_supervisor.py': '8084748c0ffb5e009e8e59c4c5ecaaf08451fb2cc35540135e2db9a55d12ae0e',
    'tools/semantic_lease_recovery/continuous_supervisor_v2.py': 'c68a10ea6d340a29bf27098bd3b36afe4259fd6520898bde1182e4f5aff55c4e',
    'tools/semantic_lease_recovery/deadline_backend.py': '9918af051a94e1a345a1cb6b73069444e73fdec0918b5494f79b52f8bb2537a2',
    'tools/semantic_lease_recovery/dns.py': 'f1491cca148c488bbee8089dabcada0361781962d7b2858ad2fc4549cea3696f',
    'tools/semantic_lease_recovery/dns_v2.py': 'a0cb8191b0561b76128f5b12851e249d03a1c7d480576c7dbc85f981af01be70',
    'tools/semantic_lease_recovery/lease_owner_v2.py': 'ad95bd8766caaa644b4475cc092739eb767b047275fffa0f1dcf0756d6c93e6d',
    'tools/semantic_lease_recovery/lease_recovery_budget.py': 'c4a70c54823934e8d0ede9a5dff52ec93e896826b36445f21048c9519e2aeedf',
    'tools/semantic_lease_recovery/materialize_southbound_lease_refresh_v2.py': 'b40430dc2523afca8d4781590e20724013c936f32e1e5d7ab71483e5d52b1c62',
    'tools/semantic_lease_recovery/nft_seconds_backend.py': '04cd115c756158ce2c04f32608380d7a40f4577d85785dfe46571825876545c1',
    'tools/semantic_lease_recovery/readback_margin_compiler.py': '814b5321a5fe5772562f50aa17c34c99c2be741b6e2a9d26110a6b8991bdbf1d',
    'tools/semantic_lease_recovery/recovery_journal.py': '43a293ab9b4075401cfc139a6531f30fdae7277cbe096f10c0d460cd26ed291d',
    'tools/semantic_lease_recovery/resilient_lease_adapter.py': 'beb09ee948ac2f5a39777b7a10339d6085bae09a90d94e8d95ec3ef940ac1683',
    'tools/semantic_lease_recovery/resilient_lease_adapter_v2.py': '38e070b3638bf0736d2788f36cac51d3ca922f6878abf2f57b8cdf0bfa65b7eb',
    'tools/semantic_provider_admission_v2/__init__.py': 'bbae3553c950479a55a26ac71f7a4d79e32f69402967b0b39064cfadd4e41b31',
    'tools/semantic_provider_admission_v2/broker_v2.py': 'a87d1eda988736e6a8467edd96d343f627a3662acdaed06f539135a34afb1c37',
    'tools/semantic_provider_admission_v2/consumption_v2.py': '44a6ef8de7e7bafd6881104fe148fb984a2acc595685c3095530155bd82c22e4',
    'tools/semantic_provider_admission_v2/driver_v7.py': '27a3b0ec3c4d21a1faec9b15b1e5a5b7526472eddcf35f3462c77bcba8f8af58',
    'tools/semantic_provider_admission_v2/evidence_v2.py': 'd6f7c659f87705d164c1abdb5589586103abcfebd12bc65f88668130d010d723',
    'tools/semantic_provider_admission_v2/l2_binding.py': '27ecff88f1abe0dc08022770c6dbb2ed030908f2c8c20ed1b78ef5d3215cbaa7',
    'tools/semantic_provider_admission_v2/locking.py': '1a92011a1948ab82498fcc2fc92ee17b7cbf11f1858cbe7edc1dac606de0b564',
    'tools/semantic_provider_admission_v2/preparer_v2.py': 'c417cd74f4a1712b93e19b145df959ac85d1e42a07484c729cfd18182dd579c7',
    'tools/semantic_provider_admission_v2/reauthorization_v2.py': '53fb58772280116845a47351bdbce802dfd26169175cb36e3e9c11421df6b39c',
    'tools/semantic_provider_operation/__init__.py': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    'tools/semantic_provider_operation/authorization.py': '8f5dd2fd86efb7add1bdb5325b6428db41cc539b7b00a3b33efa4d692ab958fc',
    'tools/semantic_provider_operation/epochs.py': 'b5188406c935079b35f2a81ba670df9578d6ef97a5d7308cbb9cf502a72635bb',
    'tools/semantic_provider_operation/lease_supervisor.py': '71e477e4acaa6a3b49e9d1ff58752d045538426cd415f2edccfd3987a0b7d966',
    'tools/semantic_provider_operation/lease_supervisor_v2.py': '06f7fb2744a1ac3d4b94ef20aa04801e9625f9ca920dfe8fcd421e11456d0de4',
    'tools/semantic_provider_r3/__init__.py': '44f7a91396fbd53e601cc981747063d61ac3c8733fd69595808694d9250a61e6',
    'tools/semantic_provider_r3/autostart.py': '6a9907fcbfd8f1c0f29da399a08aadca0a9d6e26e7c72fc8e85005ed1acca270',
    'tools/semantic_provider_r3/compose.py': 'b6cf4d645abf6f5cad26122cd0d7c6d391589c8db3897ee4f12d934c8635b102',
    'tools/semantic_provider_r3/identity_overlay_v13.py': '397addeffebf9e77958daf8ad3f621d3cc4fbab10a6374dc76b58179e41c9baa',
    'tools/semantic_provider_r3/identity_provider_v13.py': '3bdcf7688ffac5c485abfc5893a3f6a3ff5777aab136138ee7488e3a2bd747bf',
    'tools/semantic_provider_r3/install_common.py': '0d28d8f23fdfb6c05a866275a8bb0f7dc2505926d305acd53bb3b9b8ca843695',
    'tools/semantic_provider_r3/operate.py': '019bb1b66d243acfdc071410d3219e448c70b84dba623636efbed85ff0362d8a',
    'tools/semantic_provider_r3/read_identity_provider_v13.py': '7aa1a9067f59d1fb15341d6567bd88af8eac4bbd0b027df6751235190297d4e7',
    'tools/semantic_provider_r3/upgrade.py': 'bc18eee17996d2cb0533d132ec40789c43244187d2edb2d2ca59f48ff850c754',
    'tools/semantic_provider_r3/volatile_restore.py': '8a8ccc3750f241809d35d949a71ec844d2fdc8e9d7c056bb392cfc1a58b3b0f0',
    'tools/semantic_runtime_v51_install/__init__.py': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    'tools/semantic_runtime_v51_install/common.py': 'f2351bec00dbb4234b28ce5de79d000600cc1adba95cce4fc1d1a11484aa22bb',
    'tools/semantic_runtime_v52/semantic_provider_docker_runtime_v52.py': '117c9c86bb173742e4da7051d18bdef68526d3a8172cf231c41a27d2ea815911',
    'tools/semantic_stopped_rootfs/rootfs_difference_report.py': 'cb7b14165da33fcec227f5c9394cb5e640980b4c9be97a6289b9bbc801de8115',
    'tools/semantic_stopped_rootfs/rootfs_image_equivalence.py': '5c4fcb28a979ca2d83bcf0bdbbb7d03599170875e30b56de63874891cb79e028',
    'tools/semantic_stopped_rootfs/stopped_rootfs_comparison.py': 'fbdf94a8946a2de0504055586a00e25cf6cad0dacd9fa214cc405e49e276e3e5',
    'tools/semantic_transaction_profiles/assemble_provider_profiles.py': '890dff15e3826175ef01467a812cdd523e8ea5d50a306ad8727f866475ab9734',
    'tools/semantic_transaction_profiles/authenticate_provider_transaction.py': 'b47e245abab2bb55ccd172c5e3f8da2a0b167e89c588811159f87cc4d929f258',
    'tools/semantic_transaction_profiles/guarded_runtime_switch.py': '1492237e1c1ce85da5c9220ea3f6f024b24dc4d217ff5bf6e5b43c14fff225bd',
    'tools/semantic_transaction_profiles/publish_provider_transaction.py': '7777f33432bbfadd56f89fd2ed0122ce1c14e41d797498d94fa7bdb3324d0080',
}
# END DELIVERY
UNIT_SOURCE = 'ops/vps/systemd/ouf-semantic-r3-autostart.service'
UNIT_SHA = 'f73540e8c1fb8ee07f41a589d4089b17d53f4b292632951cc0dfc6b6c3ae30ff'

def require(ok, reason):
    if not ok:
        raise RuntimeError(reason)

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('ascii')

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def custody(path, directory=False):
    path = Path(path)
    for item in [*reversed(path.parents), path]:
        info = item.lstat()
        is_dir = item != path or directory
        require((stat.S_ISDIR(info.st_mode) if is_dir else stat.S_ISREG(info.st_mode))
                and info.st_uid == info.st_gid == 0 and not info.st_mode & 0o022
                and (is_dir or info.st_nlink == 1), 'R3_AUTOSTART_INSTALL_CUSTODY_REQUIRED')

def bound(path, expected=None):
    custody(path)
    digest = sha(Path(path).read_bytes())
    require(expected is None or digest == expected, 'R3_AUTOSTART_INSTALL_BINDING_DRIFT')
    return {'path': str(path), 'sha256': digest}

def command(args):
    return subprocess.check_output(args, stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)

def write(path, raw, mode):
    with open(path, 'xb') as stream:
        os.chmod(path, mode)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())

def install():
    require(sys.platform == 'linux' and os.geteuid() == os.getegid() == 0, 'ROOT_CUSTODY_REQUIRED')
    require(MODE in ('plan', 'apply') and (MODE != 'apply' or re.fullmatch('[0-9a-f]{64}', REQUESTED))
            and (MODE != 'plan' or not REQUESTED), 'uso: plan | apply <planSha256>')
    require(command(['/usr/bin/git', '-C', str(SOURCE), 'rev-parse', 'HEAD']).decode().strip() == PIN,
            'R3_AUTOSTART_INSTALL_COMMIT_DRIFT')
    bound('/usr/bin/python3.13', PYTHON_SHA)
    custody(DEST.parent, directory=True)
    custody(UNIT.parent, directory=True)
    require(not os.path.lexists(DEST) and not os.path.lexists(UNIT), 'R3_AUTOSTART_INSTALL_ALREADY_PRESENT')
    payload = {}
    for name, expected in {**MANIFEST, UNIT_SOURCE: UNIT_SHA}.items():
        raw = (SOURCE / name).read_bytes()
        require(sha(raw) == expected, 'R3_AUTOSTART_INSTALL_DELIVERY_DRIFT')
        # Both the reviewed manifest AND the pinned commit must agree.
        require(command(['/usr/bin/git', '-C', str(SOURCE), 'show', PIN + ':' + name]) == raw,
                'R3_AUTOSTART_INSTALL_PIN_DRIFT')
        payload[name] = raw
    cfg = {
        'schema': 'ouf.semantic-provider-r3-autostart.v1',
        'bindings': {
            'docker': bound('/usr/bin/docker', '7f5b38163f9c5367f4b42d905c0505877eafa4c20abe49430c85a770aefacf40'),
            'nft': bound('/usr/sbin/nft', '57bdb96c8a48844ddd6dd469c267cda951b9a466be93d254c928891ed8c3b7f0'),
            'systemctl': bound('/usr/bin/systemctl'),
            'wrapper': bound('/usr/local/sbin/ouf-semantic-admitted-v2'),
        },
        'dockerSocket': 'unix:///var/run/docker.sock',
        'installRoot': S + '/semantic-provider-r3-install-v1',
        'volatileRestore': {
            'result': '/var/lib/ouf-storage-migration/semantic-provider-b1-rootfs-20261116-mountpoint-0711/result.json',
            'sha256': '49a82a05f7f935e63b76cfacdda742f928c112a1de2a61353436ef1cdac3f2b8',
            'source': S + '/semantic-provider-v2-offline-rootfs-s3BU0nDX/source',
        },
        'outputRoot': S, 'attempts': 3, 'waitSeconds': [30, 90, 180],
    }
    custody(cfg['installRoot'], directory=True)
    custody(cfg['outputRoot'], directory=True)
    custody(cfg['volatileRestore']['source'], directory=True)
    bound(cfg['volatileRestore']['result'], cfg['volatileRestore']['sha256'])
    raw_cfg = canonical(cfg)
    plan = {'schema': 'ouf.semantic-provider-r3-autostart-install.v1', 'commit': PIN,
            'source': str(SOURCE), 'destination': str(DEST), 'unit': str(UNIT),
            'files': MANIFEST, 'unitSha256': UNIT_SHA, 'configuration': cfg,
            'configurationSha256': sha(raw_cfg), 'daemonReload': True, 'enable': True,
            'start': False, 'destinationsAbsent': True}
    digest = sha(canonical(plan))
    if MODE == 'plan':
        print(canonical({**plan, 'status': 'PLAN_READY', 'planSha256': digest}).decode())
        return
    require(REQUESTED == digest, 'R3_AUTOSTART_INSTALL_PLAN_CHANGED')
    # Exclusive creation: preserve any partial install for review, never overwrite.
    DEST.mkdir(mode=0o700)
    delivery = DEST / 'source'
    delivery.mkdir(mode=0o700)
    for name in sorted(MANIFEST):
        target = delivery / name
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        write(target, payload[name], 0o600)
    write(DEST / 'config.json', raw_cfg, 0o600)
    write(UNIT, payload[UNIT_SOURCE], 0o644)
    installed = {str(delivery / name): bound(delivery / name, expected)['sha256']
                 for name, expected in MANIFEST.items()}
    installed[str(DEST / 'config.json')] = bound(DEST / 'config.json', sha(raw_cfg))['sha256']
    installed[str(UNIT)] = bound(UNIT, UNIT_SHA)['sha256']
    systemctl = cfg['bindings']['systemctl']
    for args in (['daemon-reload'], ['enable', UNIT.name]):
        bound(systemctl['path'], systemctl['sha256'])
        command([systemctl['path'], *args])
        bound(systemctl['path'], systemctl['sha256'])
    report = {'schema': plan['schema'], 'status': 'R3_AUTOSTART_INSTALLED_ENABLED',
              'planSha256': digest, 'installedSha256': installed, 'providerStarted': False}
    write(DEST / 'installation-result.json', canonical(report), 0o600)
    print(canonical(report).decode())

try:
    install()
except Exception as error:
    print(json.dumps({'status': 'HELD', 'reason': str(error) if type(error) is RuntimeError
                      else 'R3_AUTOSTART_INSTALL_FAILED'}), file=sys.stderr)
    sys.exit(1)
PY
