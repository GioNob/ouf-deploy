// Package storagecopy implements an isolated synthetic copy rehearsal.
// It has no target CLI, runtime authority, cutover or source mutation path.
package storagecopy

import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "reflect"
 "strings"
 "syscall"
 "time"
)

const MaxObjects = 256
const MaxObjectBytes = 16 << 20
const MaxRequests = 10000
var ErrMissing = errors.New("OBJECT_MISSING")
var ErrCrash = errors.New("SYNTHETIC_PROCESS_INTERRUPTION")

type Transient struct { After time.Duration }
func (e Transient) Error() string { return "DEPENDENCY_TRANSIENT" }
type ID struct { Bucket string; Key string }
type Meta struct { Size int64; ETag string; Metadata map[string]string; Headers map[string]string; Tags map[string]string; LastModified time.Time }
type Item struct { ID ID; Meta Meta }
type Store interface {
 Identity() string
 Snapshot(context.Context, []string) (map[ID]Meta,error)
 Head(context.Context,ID) (Meta,error)
 Read(context.Context,ID,string) ([]byte,error)
 PutNew(context.Context,ID,[]byte,Meta) error
 SetCredit(func()error)
}
type Progress struct { Seq int; Attempt int; Started time.Time; Deadline time.Time; Next time.Time; Outcome string; Reason string; Intent string }
type Entry struct { Seq int; BodyHash string; MetaHash string; State string }
type Event struct { Previous string; Payload json.RawMessage; Digest string }
type Journal struct { Dir string; lock *os.File; Last map[string]string; Counts map[string]int }
func hash(raw []byte) string { h:=sha256.Sum256(raw);return hex.EncodeToString(h[:]) }
func code(s string) error {return errors.New(s)}
func encode(v any) []byte { b,e:=json.Marshal(v);if e!=nil{panic(e)};return b }
func privateFile(info os.FileInfo)bool{
 s,ok:=info.Sys().(*syscall.Stat_t);return ok&&info.Mode().IsRegular()&&info.Mode().Perm()==0600&&s.Uid==uint32(os.Geteuid())&&s.Nlink==1
}
func openJournal(dir string) (*Journal,error) {
 if !filepath.IsAbs(dir)||filepath.Clean(dir)!=dir{return nil,code("ABSOLUTE_PRIVATE_SCOPE_REQUIRED")}
 for p:=filepath.Dir(dir);;p=filepath.Dir(p){s,e:=os.Lstat(p);if e!=nil||!s.IsDir()||s.Mode().Perm()&0022!=0{return nil,code("PROTECTED_SCOPE_ANCESTRY_REQUIRED")};if p=="/"{break}}
 fresh:=false
 if e:=os.Mkdir(dir,0700);e==nil{fresh=true}else if !os.IsExist(e){return nil,e}
 s,e:=os.Lstat(dir);if e!=nil||!s.IsDir()||s.Mode().Perm()!=0700||s.Sys().(*syscall.Stat_t).Uid!=uint32(os.Geteuid()){return nil,code("PRIVATE_SCOPE_REQUIRED")}
 f,e:=os.OpenFile(filepath.Join(dir,"lock"),os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW,0600);if e!=nil{return nil,e}
 info,e:=f.Stat();if e!=nil||!privateFile(info){f.Close();return nil,code("PRIVATE_LOCK_REQUIRED")}
 if e=syscall.Flock(int(f.Fd()),syscall.LOCK_EX|syscall.LOCK_NB);e!=nil{f.Close();return nil,code("COPY_SCOPE_BUSY")}
 j:=&Journal{Dir:dir,lock:f,Last:map[string]string{},Counts:map[string]int{}}
 if !fresh {if _,e=os.Lstat(filepath.Join(dir,"operation"));e!=nil{j.Close();return nil,code("EXISTING_SCOPE_WITHOUT_OPERATION_HELD")}}
 if fresh {parent,e:=os.Open(filepath.Dir(dir));if e!=nil{j.Close();return nil,e};e=parent.Sync();parent.Close();if e!=nil{j.Close();return nil,e}}
 return j,nil
}
func (j *Journal) Close(){if j.lock!=nil{syscall.Flock(int(j.lock.Fd()),syscall.LOCK_UN);j.lock.Close();j.lock=nil}}
func (j *Journal) load(name string,out any) error {
 p:=filepath.Join(j.Dir,name);f,e:=os.OpenFile(p,os.O_RDONLY|syscall.O_NOFOLLOW,0)
 if os.IsNotExist(e){return ErrMissing};if e!=nil{return e};defer f.Close();s,e:=f.Stat();if e!=nil||!privateFile(s)||s.Size()>8<<20{return code("PRIVATE_BOUNDED_JOURNAL_REQUIRED")}
 raw,e:=io.ReadAll(io.LimitReader(f,(8<<20)+1));if e!=nil{return e};after,e:=os.Lstat(p);if e!=nil||s.Size()!=int64(len(raw))||!os.SameFile(s,after)||!s.ModTime().Equal(after.ModTime()){return code("JOURNAL_CHANGED")}
 if len(raw)==0||raw[len(raw)-1]!='\n'{return code("INCOMPLETE_JOURNAL_HELD")}
 previous:="";count:=0
 for _,line:=range strings.Split(strings.TrimSuffix(string(raw),"\n"),"\n"){
  var event Event;if json.Unmarshal([]byte(line),&event)!=nil||event.Previous!=previous||event.Digest!=hash(append([]byte(previous),event.Payload...)){return code("JOURNAL_CHAIN_MISMATCH")}
  if json.Unmarshal(event.Payload,out)!=nil{return code("JOURNAL_PAYLOAD_INVALID")};count++;switch value:=out.(type){case *Progress:if value.Seq!=count-1||value.Attempt<0||value.Attempt>128{return code("JOURNAL_PROGRESS_SEQUENCE_INVALID")};case *Entry:if value.Seq!=count{return code("JOURNAL_ENTRY_SEQUENCE_INVALID")};case *int:if *value!=count{return code("JOURNAL_REQUEST_SEQUENCE_INVALID")}};previous=event.Digest
 }
 j.Last[name]=previous;j.Counts[name]=count;return nil
}
func (j *Journal) append(name string,value any)error{
 body:=encode(value);previous:=j.Last[name];event:=Event{Previous:previous,Payload:body,Digest:hash(append([]byte(previous),body...))};raw:=append(encode(event),'\n')
 p:=filepath.Join(j.Dir,name);f,e:=os.OpenFile(p,os.O_CREATE|os.O_APPEND|os.O_WRONLY|syscall.O_NOFOLLOW,0600);if e!=nil{return e}
 info,e:=f.Stat();if e!=nil||!privateFile(info)||info.Size()+int64(len(raw))>8<<20{f.Close();return code("PRIVATE_JOURNAL_LIMIT")}
 n,e:=f.Write(raw);if e==nil&&n!=len(raw){e=code("JOURNAL_SHORT_WRITE")};if e==nil{e=f.Sync()};f.Close();if e!=nil{return e}
 dir,e:=os.Open(j.Dir);if e!=nil{return e};e=dir.Sync();dir.Close();if e!=nil{return e}
 j.Last[name]=event.Digest;j.Counts[name]++;return nil
}
func (j *Journal) credit()error{
 name:="requests";var n int
 if _,ok:=j.Counts[name];!ok{if e:=j.load(name,&n);e!=nil&&!errors.Is(e,ErrMissing){return e}}
 n=j.Counts[name]+1;if n>MaxRequests{return code("CUMULATIVE_REQUEST_BUDGET_EXHAUSTED")};return j.append(name,n)
}
func identity(id ID)string{return hash(encode(id))}
func metaHash(m Meta)string {return hash(encode(struct{Size int64;Metadata,Headers,Tags map[string]string}{m.Size,m.Metadata,m.Headers,m.Tags}))}
func sameRepresentation(a,b Meta)bool{return a.Size==b.Size&&reflect.DeepEqual(a.Metadata,b.Metadata)&&reflect.DeepEqual(a.Headers,b.Headers)&&reflect.DeepEqual(a.Tags,b.Tags)}
func plannedEqual(live,planned Meta)bool{
 if live.Size!=planned.Size||!reflect.DeepEqual(live.Metadata,planned.Metadata)||!reflect.DeepEqual(live.Tags,planned.Tags){return false}
 for k,v:=range planned.Headers{if live.Headers[k]!=v{return false}}
 return planned.LastModified.IsZero()||planned.LastModified.Equal(live.LastModified)
}
type Report struct { Status string; Verified int; CopiedThisAttempt int; ReconciledThisAttempt int; Attempt int; RequestsReserved int; TargetOperations int; RuntimeAuthorityIssued bool; MigrationReady bool }
type Engine struct { Source Store; Destination Store; Now func()time.Time; Hook func(string)error }
func (e *Engine) run(ctx context.Context,items []Item,scope string) (report Report,err error){
 // This entry is unexported and called only by synthetic fixtures in this module.
 if e.Now==nil{e.Now=time.Now};if len(items)==0||len(items)>MaxObjects{return report,code("BOUNDED_SYNTHETIC_PLAN_REQUIRED")}
 if e.Source.Identity()==e.Destination.Identity(){return report,code("INDEPENDENT_PROFILES_REQUIRED")}
 seen:=map[ID]bool{};bucketSet:=map[string]bool{};for _,it:=range items{
  if it.ID.Bucket==""||it.ID.Key==""||seen[it.ID]||it.Meta.Size<0||it.Meta.Size>MaxObjectBytes{return report,code("INVALID_SYNTHETIC_PLAN")};seen[it.ID]=true;bucketSet[it.ID.Bucket]=true
 }
 buckets:=[]string{};for b:=range bucketSet{buckets=append(buckets,b)}
 intent:=hash(encode(struct{Items []Item;Source,Destination string}{items,e.Source.Identity(),e.Destination.Identity()}))
 j,er:=openJournal(scope);if er!=nil{return report,er};defer j.Close()
 var state Progress;er=j.load("operation",&state)
 if errors.Is(er,ErrMissing){now:=e.Now().UTC();state=Progress{Started:now,Deadline:now.Add(24*time.Hour),Outcome:"PREPARED",Intent:intent};if er=j.append("operation",state);er!=nil{return report,er}}else if er!=nil{return report,er}
 if state.Intent!=intent{return report,code("CHANGED_PLAN_OR_PROFILE_HELD")}
 report.Attempt=state.Attempt;var reserved int;if x:=j.load("requests",&reserved);x!=nil&&!errors.Is(x,ErrMissing){return report,x};report.RequestsReserved=j.Counts["requests"]
 if state.Outcome=="VERIFIED"{report.Status="ALREADY_VERIFIED_NOT_RERUN";report.Verified=len(items);return report,nil}
 if state.Outcome=="HELD"||state.Outcome=="EXHAUSTED"{return report,code("COPY_RECONCILIATION_REQUIRED")}
 if e.Now().Before(state.Next){report.Status="PAUSED_BEFORE_RETRY_AFTER";return report,nil}
 if state.Attempt>=128||!e.Now().Before(state.Deadline){state.Outcome="EXHAUSTED";state.Seq++;j.append("operation",state);return report,code("CUMULATIVE_COPY_BUDGET_EXHAUSTED")}
 state.Attempt++;state.Seq++;state.Outcome="RUNNING";state.Next=time.Time{};if er=j.append("operation",state);er!=nil{return report,er};report.Attempt=state.Attempt
 defer func(){
  report.RequestsReserved=j.Counts["requests"]
  if err==nil{return};if errors.Is(err,ErrCrash){return}
  var transient Transient
  if errors.As(err,&transient){delays:=[]time.Duration{5*time.Second,15*time.Second,time.Minute,5*time.Minute,15*time.Minute};index:=state.Attempt-1;if index>=len(delays){index=len(delays)-1};delay:=delays[index];jitter:=time.Duration(intent[0]%21)*delay/100;delay+=jitter;if transient.After>delay{delay=transient.After};state.Next=e.Now().Add(delay);state.Outcome="PAUSED";state.Reason="DEPENDENCY_TRANSIENT";if !state.Next.Before(state.Deadline){state.Outcome="EXHAUSTED"};report.Status=state.Outcome}else{state.Outcome="HELD";state.Reason="PERMANENT_OR_INTEGRITY_OR_UNKNOWN";report.Status="HELD"}
  state.Seq++;if x:=j.append("operation",state);x!=nil{err=code("DURABLE_PAUSE_UNPROVEN")}
 }()
 e.Source.SetCredit(j.credit);e.Destination.SetCredit(j.credit)
 source,er:=e.Source.Snapshot(ctx,buckets);if er!=nil{return report,er};if len(source)!=len(items){return report,code("SOURCE_SET_CHANGED")}
 dest,er:=e.Destination.Snapshot(ctx,buckets);if er!=nil{return report,er};for id:=range dest{if !seen[id]{return report,code("UNEXPLAINED_DESTINATION_OBJECT")}}
 preflight:=map[ID]Meta{}
 for _,it:=range items{if _,ok:=source[it.ID];!ok{return report,code("SOURCE_SET_CHANGED")};head,x:=e.Source.Head(ctx,it.ID);if x!=nil{return report,x};if !plannedEqual(head,it.Meta){return report,code("SOURCE_METADATA_CHANGED")};preflight[it.ID]=head}
 for _,it:=range items{
  name:="object-"+identity(it.ID);var entry Entry;x:=j.load(name,&entry);hasEntry:=x==nil;if x!=nil&&!errors.Is(x,ErrMissing){return report,x}
  body,x:=e.Source.Read(ctx,it.ID,preflight[it.ID].ETag);if x!=nil{return report,x};if len(body)!=int(it.Meta.Size)||len(body)>MaxObjectBytes{return report,code("SOURCE_BODY_SIZE_CHANGED")}
  bodyHash:=hash(body);hint:=it.Meta.Metadata["ouf-content-hash"];hint=strings.TrimPrefix(hint,"sha256:");if hint!=""&&!strings.EqualFold(hint,bodyHash){return report,code("ADVERTISED_HASH_MISMATCH")}
  original,x:=e.Source.Head(ctx,it.ID);if x!=nil{return report,x};if (!sameRepresentation(original,preflight[it.ID])||!original.LastModified.Equal(preflight[it.ID].LastModified))||original.ETag!=preflight[it.ID].ETag{return report,code("SOURCE_CHANGED_DURING_READ")}
  fingerprint:=metaHash(original)
  if hasEntry&&(entry.BodyHash!=bodyHash||entry.MetaHash!=fingerprint){return report,code("PREPARED_SOURCE_CHANGED")}
  if !hasEntry{entry=Entry{Seq:1,BodyHash:bodyHash,MetaHash:fingerprint,State:"PREPARED"};if x=j.append(name,entry);x!=nil{return report,x}}
  existing,x:=e.Destination.Head(ctx,it.ID)
  if errors.Is(x,ErrMissing){
   if entry.State=="VERIFIED"{return report,code("VERIFIED_DESTINATION_DISAPPEARED")}
   if e.Hook!=nil{if x=e.Hook("BEFORE_PUT");x!=nil{return report,x}}
   if x=e.Destination.PutNew(ctx,it.ID,body,original);x!=nil{return report,x};report.CopiedThisAttempt++
   if e.Hook!=nil{if x=e.Hook("AFTER_PUT");x!=nil{return report,x}}
   existing,x=e.Destination.Head(ctx,it.ID)
  }else if x==nil{if !hasEntry{return report,code("UNOWNED_DESTINATION_HELD")};report.ReconciledThisAttempt++}
  if x!=nil{return report,x};if !sameRepresentation(existing,original){return report,code("DESTINATION_METADATA_MISMATCH")}
  copied,x:=e.Destination.Read(ctx,it.ID,existing.ETag);if x!=nil{return report,x};if hash(copied)!=bodyHash||len(copied)!=len(body){return report,code("DESTINATION_BODY_MISMATCH")}
  after,x:=e.Destination.Head(ctx,it.ID);if x!=nil{return report,x};if (!sameRepresentation(after,existing)||!after.LastModified.Equal(existing.LastModified))||after.ETag!=existing.ETag{return report,code("DESTINATION_CHANGED_DURING_VERIFICATION")}
  if e.Hook!=nil{if x=e.Hook("BEFORE_CHECKPOINT");x!=nil{return report,x}}
  entry.Seq++;entry.State="VERIFIED";if x=j.append(name,entry);x!=nil{return report,x};report.Verified++
 }
 after,er:=e.Source.Snapshot(ctx,buckets);if er!=nil{return report,er};if !reflect.DeepEqual(source,after){return report,code("SOURCE_CHANGED_AFTER_COPY")}
 for _,it:=range items{head,x:=e.Source.Head(ctx,it.ID);if x!=nil{return report,x};if (!sameRepresentation(head,preflight[it.ID])||!head.LastModified.Equal(preflight[it.ID].LastModified))||head.ETag!=preflight[it.ID].ETag{return report,code("SOURCE_CHANGED_AFTER_COPY")}}
 final,er:=e.Destination.Snapshot(ctx,buckets);if er!=nil{return report,er};if len(final)!=len(items){return report,code("DESTINATION_SET_MISMATCH")};for id:=range final{if !seen[id]{return report,code("UNEXPLAINED_DESTINATION_OBJECT")}}
 state.Seq++;state.Outcome="VERIFIED";state.Reason="";if er=j.append("operation",state);er!=nil{return report,er};report.Status="SYNTHETIC_COPY_VERIFIED_NOT_ADMITTED";return report,nil
}

func (e *Engine) String()string{return fmt.Sprintf("synthetic-only copy engine; no production entrypoint")}
