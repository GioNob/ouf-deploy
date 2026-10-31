"""One physical psql session, two read-only transactions, no transaction in waits.

The signed profile preserves the existing cumulative SQL session ceiling of six.
psql has no reconnect path; each transaction is durably claimed before submission.
"""
import hashlib,os,select,signal,subprocess,time

class ReadOnlySession:
    def __init__(self,ctx,ports):
        self.ctx,self.ports=ctx,ports;self.process=None;self.offset=0;self.completed=[]
    def start(self):
        c=self.ctx;p=self.ports
        p.require(self.process is None,'ONE_EXISTING_SQL_SESSION_ONLY')
        c.m.raw(c.profile['dockerExecutable']['path'],67108864,c.profile['dockerExecutable']['sha256'],private=False)
        argv=c.q.arguments(c.d,c.profile,c.root/'empty-docker-config')
        p.require(argv[-2]=='-c'and argv[-1]==c.q.query(c.d,c.profile['identity']['runtimeRole']),'EXACT_EXISTING_READ_ONLY_SQL_PROGRAM_REQUIRED')
        argv=argv[:-2];i=argv.index('exec');argv.insert(i+1,'-i')
        t=argv.index(c.profile['containerPrograms']['timeout']);p.require(argv[t+1:t+4]==['-s','KILL','15'],'EXACT_EXISTING_SQL_TIMEOUT_PROGRAM_REQUIRED')
        argv[t+3]=str(min(900,max(1,int(p.gate.remaining())))) # Whole session; statement limit stays 5s.
        argv.insert(t,'PGAPPNAME=ouf-v35-reconciliation')
        p.reserve('sqlSessions');row=p.record();p.execution.save(row,recoverySql={'state':'CLAIMED','transactions':[],'maximumSessions':1,'maximumSeconds':900})
        self.out=c.root/'one-session.out';self.err=c.root/'one-session.err'
        out=os.open(self.out,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
        err=os.open(self.err,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
        try:
            self.process=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=out,stderr=err,env={'LC_ALL':'C','PATH':'/usr/bin:/bin'},start_new_session=True,close_fds=True)
            os.set_blocking(self.process.stdin.fileno(),False)
        finally:os.close(out);os.close(err)
    def bounded(self,deadline):
        self.ports.gate.check()
        self.ports.require(time.monotonic()<deadline and self.process.poll()is None,'ONE_SESSION_SQL_OUTCOME_UNPROVEN')
        self.ports.require(self.out.stat().st_size<=1050624 and self.err.stat().st_size<=65536,'ONE_SESSION_SQL_OUTPUT_BOUND')
    def query(self,after=False):
        p=self.ports;c=self.ctx;name='AFTER'if after else'BEFORE'
        p.require(self.process is not None and self.completed==(['BEFORE']if after else[]),'ORDERED_TWO_READ_ONLY_TRANSACTIONS_ONLY')
        query=c.sql(after=after);expected=p.review['sqlQueryHashes']['after'if after else'before']
        p.require(hashlib.sha256(query.encode()).hexdigest()==expected and query.lstrip().startswith('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;')and query.rstrip().endswith('ROLLBACK;'),'EXACT_SIGNED_CLOSED_READ_ONLY_TRANSACTION_REQUIRED')
        row=p.record();state=dict(row['recoverySql']);tx=list(state['transactions']);tx.append({'kind':name,'state':'CLAIMED','queryHash':expected});state['transactions']=tx
        p.execution.save(row,recoverySql=state)
        marker=('OUF_V35_READ_COMPLETE_'+name).encode();data=(query+'\n\\echo '+marker.decode()+'\n').encode();deadline=time.monotonic()+min(20,max(.01,p.gate.remaining()-3))
        while data:
            self.bounded(deadline)
            if select.select([],[self.process.stdin.fileno()],[],.1)[1]:
                try:sent=os.write(self.process.stdin.fileno(),data);data=data[sent:]
                except BlockingIOError:pass
        while True:
            self.bounded(deadline)
            with self.out.open('rb')as stream:stream.seek(self.offset);raw=stream.read(524545)
            p.require(len(raw)<=524544,'ONE_TRANSACTION_SQL_OUTPUT_BOUND')
            if raw.endswith(marker+b'\n'):
                body=raw[:-len(marker)-1].strip();p.require(0<len(body)<=524288,'ONE_READ_ONLY_JSON_RESULT_REQUIRED')
                facts=c.m.decode(body);c.validate_sql(facts,after=after,before=c.before)
                self.offset+=len(raw);self.completed.append(name)
                row=p.record();state=dict(row['recoverySql']);tx=list(state['transactions']);tx[-1]={**tx[-1],'state':'APPLIED','resultHash':hashlib.sha256(body).hexdigest(),'transactionClosed':True};state['transactions']=tx
                p.execution.save(row,recoverySql=state);c.m.new_file(c.root,'database-'+name.lower()+'.json',body)
                return facts
            time.sleep(.05)
    def close(self,success=False):
        if self.process is None:return
        process=self.process;self.process=None
        try:
            process.stdin.close()
            try:code=process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=5);code=-signal.SIGKILL
            if success:
                self.ports.require(code==0 and self.completed==['BEFORE','AFTER'],'EXACT_TWO_TRANSACTIONS_ONE_SESSION_COMPLETION_REQUIRED')
                row=self.ports.record();self.ports.execution.save(row,recoverySql={**row['recoverySql'],'state':'APPLIED','sessionClosed':True})
        finally:
            if process.poll()is None:os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=5)
