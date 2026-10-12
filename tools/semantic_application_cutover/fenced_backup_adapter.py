"""Executor-owned backup phase using the qualified one-use native primitive.

Sealed checkpoints still own authority, command/container custody and producer
quiescence. No target defaults, replay, reopen, restore or migration. Missing
receipts remain UNKNOWN even when an archive or closed database is observed.
"""
import hashlib, json, os, re, stat
from pathlib import Path
from database_gate import Psql, digest, durable, literal, require
from fenced_backup import fenced_backup
from database_channel_scope import verify_admin


class FencedBackupAdapter:
    def __init__(self, admin, intent, checkpoint, transition_context_hash, evidence_store=None):
        require(type(admin) is Psql and callable(checkpoint), 'SEALED_BACKUP_CHANNEL_AND_CHECKPOINT_REQUIRED')
        self.admin, self.checkpoint = admin, checkpoint
        self.evidence_store=evidence_store
        self.intent = json.loads(json.dumps(intent, allow_nan=False))
        require(set(self.intent) == {'containerId','user','database','databaseOid','directory','maxArchiveBytes'}, 'EXACT_BACKUP_INTENT_REQUIRED')
        require(re.fullmatch('[0-9a-f]{64}',self.intent['containerId']) is not None, 'EXACT_DATABASE_CONTAINER_REQUIRED')
        require(type(self.intent['databaseOid']) is int and self.intent['databaseOid'] > 0, 'EXACT_DATABASE_OID_REQUIRED')
        require(type(self.intent['maxArchiveBytes']) is int and 100 < self.intent['maxArchiveBytes'] <= 16*1024**3, 'BOUNDED_ARCHIVE_REQUIRED')
        self.root = Path(self.intent['directory'])
        require(self.root.is_absolute(), 'ABSOLUTE_PRIVATE_BACKUP_DIRECTORY_REQUIRED')
        self.intent_hash = digest(self.intent)
        require(type(transition_context_hash) is str and re.fullmatch('[0-9a-f]{64}',transition_context_hash) is not None,'EXACT_BACKUP_TRANSITION_CONTEXT_REQUIRED')
        self.context = {'schema':'ouf.semantic-cutover-backup-context.v1','transitionContextHash':transition_context_hash,'intentHash':self.intent_hash}

    def exact(self, intent):
        require(digest(intent) == self.intent_hash, 'IMMUTABLE_BACKUP_INTENT_REQUIRED')
        s = self.root.lstat()
        require(stat.S_ISDIR(s.st_mode) and s.st_uid == os.geteuid() and stat.S_IMODE(s.st_mode) == 0o700, 'PRIVATE_BACKUP_DIRECTORY_REQUIRED')
        # The sealed checkpoint additionally verifies command binary/socket and
        # ancestor custody. A channel for another container cannot be substituted.
        verify_admin(self.admin,self.intent['containerId'],self.intent['user'],self.intent['database'])

    def apply(self, intent):
        self.exact(intent)
        self.checkpoint('BEFORE_FENCED_BACKUP_PRIMITIVE')
        require(not any(os.path.lexists(self.root/name) for name in ('backup-phase-binding.json','backup-claim.json','gate-claim.json','backup-receipt.json','gate-receipt.json','semantic.dump','semantic.dump.partial','dump.stderr.private','backup-denial.json','gate-denial.json','admission-closed.json')), 'NEW_TRANSITION_REQUIRES_UNUSED_BACKUP_EVIDENCE_DIRECTORY')
        # Published before the one-use backup primitive. Reconciliation cannot
        # adopt a receipt from another context or an earlier backup directory.
        durable(self.root/'backup-phase-binding.json',self.context)
        fenced_backup(self.admin,self.intent['containerId'],self.intent['user'],self.intent['database'],self.intent['databaseOid'],self.root,checkpoint=self.checkpoint)

    def private(self, name, limit, parse=False):
        path = self.root / name
        fd = os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and before.st_nlink == 1
                    and stat.S_IMODE(before.st_mode) == 0o600 and 0 < before.st_size <= limit, 'PRIVATE_BACKUP_FILE_CUSTODY_REQUIRED')
            h = hashlib.sha256(); chunks=[]; count=0
            while True:
                chunk=os.read(fd,65536)
                if not chunk: break
                count += len(chunk); require(count <= limit, 'BACKUP_FILE_GREW_BEYOND_BOUND')
                h.update(chunk)
                if parse: chunks.append(chunk)
            after=os.fstat(fd); following=path.lstat()
            pin=lambda s:(s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
            require(pin(before)==pin(after)==pin(following) and count == before.st_size, 'BACKUP_FILE_CHANGED_DURING_READ')
            return (json.loads(b''.join(chunks)) if parse else None), h.hexdigest(), count
        finally: os.close(fd)

    def snapshot(self):
        context,ch,_=self.private('backup-phase-binding.json',262144,True)
        require(context==self.context,'BACKUP_RECEIPT_BELONGS_TO_ANOTHER_TRANSITION')
        backup,bh,_=self.private('backup-receipt.json',262144,True)
        gate,gh,_=self.private('gate-receipt.json',262144,True)
        _,ah,size=self.private('semantic.dump',self.intent['maxArchiveBytes'])
        scope=digest({'name':self.intent['database'],'oid':self.intent['databaseOid']})
        require(gate.get('schema')=='ouf.discovery.database-gate.v1' and gate.get('status')=='WRITERS_FENCED'
                and gate.get('databaseScopeHash')==scope and gate.get('newConnectionsDenied') is True
                and gate.get('otherSessionsAbsent') is True and gate.get('automaticReopen') is False
                and gate.get('restorePerformed') is False and gate.get('migrationPerformed') is False, 'EXACT_COMPLETED_GATE_RECEIPT_REQUIRED')
        require(backup.get('schema')=='ouf.discovery.fenced-backup.v1' and backup.get('status')=='PRIVATE_FENCED_SNAPSHOT_PAYLOAD_VALIDATED'
                and backup.get('gateReceiptHash')==digest(gate) and backup.get('archiveSha256')==ah
                and backup.get('archiveBytes')==size and size>100 and backup.get('archivePayloadParsed') is True
                and backup.get('databaseAdmissionRemainsClosed') is True and backup.get('allOtherSessionsAbsentAtGate') is True
                and backup.get('restorePerformed') is False and backup.get('migrationPerformed') is False
                and backup.get('targetAuthorityGranted') is False, 'EXACT_COMPLETE_BACKUP_RECEIPT_REQUIRED')
        database=self.intent['database']; oid=self.intent['databaseOid']
        state=self.admin.query("SELECT json_build_object('oid',oid::bigint,'closed',NOT datallowconn,'prepared',(SELECT count(*) FROM pg_prepared_xacts WHERE database="+literal(database)+"),'sessions',(SELECT count(*) FROM pg_stat_activity WHERE datid="+str(oid)+")) FROM pg_database WHERE datname="+literal(database),"SELECT pg_stat_clear_snapshot();")
        require(state=={'oid':oid,'closed':True,'prepared':0,'sessions':0}, 'CURRENT_DATABASE_FENCE_UNPROVEN')
        return {'schema':'ouf.semantic-fenced-backup-executor-evidence.v1','transitionContextHash':self.context['transitionContextHash'],'intentHash':self.intent_hash,
                'databaseContainerId':self.intent['containerId'],'backupPhaseBindingFileHash':ch,'backupReceiptFileHash':bh,'gateReceiptFileHash':gh,'archiveSha256':ah,'archiveBytes':size,'databaseScopeHash':scope,'currentDatabaseState':state}

    def observe(self, intent):
        self.exact(intent)
        self.checkpoint('BEFORE_FENCED_BACKUP_RECONCILIATION')
        try:
            before=self.snapshot(); after=self.snapshot()
        except FileNotFoundError:
            return 'UNKNOWN', {'completeBackupEvidenceAbsent':True,'absenceDoesNotProveNoEffect':True,'automaticReopen':False}
        require(before==after, 'BACKUP_EVIDENCE_CHANGED_DURING_RECONCILIATION')
        self.checkpoint('AFTER_FENCED_BACKUP_RECONCILIATION')
        if self.evidence_store is not None:self.evidence_store.publish('FENCED_BACKUP',before)
        return 'APPLIED', before
