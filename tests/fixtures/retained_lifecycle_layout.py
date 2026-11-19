"""Target-shaped declarations: 25 RO, 4 RW, 33 nodes, shared owner sidecars.

Files, atomic rotation and SQLite writer are real; no application admission is
modeled as successful. The capture producer itself generates the candidate.
"""
import os, sqlite3
from pathlib import Path


def layout(root,*,gid=0):
    root=Path(root);folder=root/'lifecycle-files';folder.mkdir(mode=0o700)
    def regular(name,body=b'SYNTHETIC_STATIC_PRIVATE_VALUE'):
        path=folder/name;path.write_bytes(body);path.chmod(0o600);return path
    def bind(source,target,readonly=True):
        return {'Type':'bind','Source':str(source),'Destination':target,'RW':not readonly}
    def token(name):
        path=folder/name;path.mkdir(mode=0o750);os.chown(path,0,gid)
        leaf=path/'token';leaf.write_bytes(b'SYNTHETIC_LIVE_TOKEN_OLD');leaf.chmod(0o440);os.chown(leaf,0,gid)
        return path
    auth={name:token(name+'-auth') for name in ('gateway','ingestion','onboarding','onboarding-identity','udp')}
    store=folder/'gateway-store';store.mkdir(mode=0o750);os.chown(store,0,gid)
    database=store/'gateway-operations.sqlite'
    with sqlite3.connect(database) as db:
        db.execute('pragma journal_mode=WAL');db.execute('create table fixture(value integer)');db.execute('insert into fixture values(0)')
    db.close();database.chmod(0o640);os.chown(database,0,gid)
    keys={name:regular(name) for name in ('caddy-config','gateway-key','gateway-properties',
        'ingestion-key','ingestion-properties','authorization-owner-key','onboarding-minio-access-key',
        'onboarding-minio-secret-key','onboarding-ths.yaml','udp-key','udp-properties','minio-password','postgres-password')}
    secret=lambda name:bind(keys[name],'/run/secrets/'+name)
    mounts={
        'caddy':[bind(keys['caddy-config'],'/etc/caddy/Caddyfile')],
        'gateway-owner':[bind(auth['gateway'],'/run/ouf-gateway-auth'),secret('gateway-key'),secret('gateway-properties'),bind(store,'/var/lib/ouf-gateway-operations')],
        'ingestion':[bind(auth['ingestion'],'/run/ouf-ingestion-auth'),secret('ingestion-key'),secret('ingestion-properties')],
        'onboarding':[bind(auth['onboarding'],'/run/ouf-onboarding-auth'),bind(auth['onboarding-identity'],'/run/ouf-onboarding-identity')]+[secret(n) for n in ('authorization-owner-key','onboarding-minio-access-key','onboarding-minio-secret-key','onboarding-ths.yaml')],
        'udp':[bind(auth['udp'],'/run/ouf-udp-auth'),secret('udp-key'),secret('udp-properties')],
        'minio':[secret('minio-password')],'postgres':[secret('postgres-password')],'keycloak':[]}
    for role in ('ingestion','udp'):mounts[role+'-evidence-read']=[dict(row) for row in mounts[role]]
    for role,target,name in [('caddy','/config','caddy-config-data'),('caddy','/data','caddy-data'),('minio','/data','minio-data'),('postgres','/var/lib/postgresql/data','postgres-data')]:
        path=folder/name;path.mkdir(mode=0o700);(path/'private-data').write_text('SYNTHETIC_MUTABLE_DATA')
        mounts[role].append(bind(path,target,False))
    return mounts,auth,database,keys


def rotate(path):
    leaf=Path(path)/'token';temp=Path(path)/'.token-test'
    temp.write_bytes(b'SYNTHETIC_LIVE_TOKEN_NEW');temp.chmod(0o440);os.chown(temp,0,leaf.stat().st_gid);os.replace(temp,leaf)
