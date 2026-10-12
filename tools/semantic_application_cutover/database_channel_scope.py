"""Exact local admin-channel scope; command custody stays with the checkpoint."""
import re
from database_gate import Psql,identifier,require

def verify_admin(admin,container_id,user,database):
    require(type(admin) is Psql,'EXACT_LOCAL_DATABASE_ADMIN_CHANNEL_REQUIRED')
    identifier(user);identifier(database)
    require(type(container_id) is str and re.fullmatch('[0-9a-f]{64}',container_id) is not None,'EXACT_DATABASE_CONTAINER_REQUIRED')
    args=admin.process.args;prefix=['docker','--config',admin.temp.name,'exec','-i',container_id,'env']
    require(type(args) is list and args[:7]==prefix and len(args)==19
            and re.fullmatch('PGAPPNAME=ouf-cutover-[a-z0-9-]{1,40}',args[7]) is not None
            and args[8:]==['psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1','-U',user,'-d',admin.database], 'EXACT_DATABASE_ADMIN_CHANNEL_SCOPE_REQUIRED')
    require(admin.database!=database,'OUTSIDE_DATABASE_ADMIN_REQUIRED')
