// Current G0 observation, separate from the immutable historical delivery scopes.
// This collector has no mutation, admission, retry, cutover or migration path.
package main

import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "net/http"
 "net/url"
 "os"
 "path/filepath"
 "reflect"
 "sort"
 "strings"
 "sync"
 "syscall"
 "time"

 "github.com/aws/aws-sdk-go-v2/aws"
 "github.com/aws/aws-sdk-go-v2/service/s3"
)

const g0MaxObjects=256
const g0MaxBody=int64(16<<20)
const g0MaxBodies=int64(64<<20)
const g0MaxWire=int64(128<<20)
const g0MaxRequests=3000
type g0Config struct {Schema string `json:"schema"`; OperationID string `json:"operationId"`; InstallationRef string `json:"installationRef"`; Connection Config `json:"connection"`}
type g0Proof struct {Bucket string `json:"bucket"`;Key string `json:"key"`;VersionID *string `json:"versionId"`;Bytes int64 `json:"bytes"`;SHA256 string `json:"sha256"`;ETag string `json:"etag"`;ObservationSHA256 string `json:"observationSha256"`}
type g0Receipt struct {
 Schema string `json:"schema"`;Status string `json:"status"`;Phase string `json:"phase"`;Reason string `json:"reason"`
 Started string `json:"started"`;Finished string `json:"finished"`;Requests int `json:"requestsReserved"`;WireBytes int64 `json:"wireBytesRead"`
 VerifiedBodies int `json:"verifiedBodies"`;VerifiedBytes int64 `json:"verifiedBytes"`;BodiesAttempted int `json:"bodiesAttempted"`
 Complete bool `json:"complete"`;SourceObservationsEqual bool `json:"sourceObservationsEqual"`
 PointInTimeSnapshotProven bool `json:"pointInTimeSnapshotProven"`;WriterInventoryComplete bool `json:"writerInventoryComplete"`
 AutomaticReplayAllowed bool `json:"automaticReplayAllowed"`;RuntimeAuthorityIssued bool `json:"runtimeAuthorityIssued"`;TargetWrites int `json:"targetWrites"`
}
func g0JSON(v any)[]byte {b,e:=json.Marshal(v);if e!=nil{panic(e)};return b}
func g0Hash(b []byte)string{h:=sha256.Sum256(b);return hex.EncodeToString(h[:])}
func g0Code(s string)error{return errors.New(s)}
func g0Name(s string)bool{if len(s)<1||len(s)>128{return false};for _,c:=range s{if !(c>='a'&&c<='z'||c>='A'&&c<='Z'||c>='0'&&c<='9'||c=='-'||c=='_'){return false}};return true}
// All writes are private local evidence, append/fsync before the external read.
func g0Append(dir,name string,value any)error{
 f,e:=os.OpenFile(filepath.Join(dir,name),os.O_WRONLY|os.O_APPEND|os.O_CREATE|syscall.O_NOFOLLOW,0600);if e!=nil{return e};defer f.Close()
 info,e:=f.Stat();if e!=nil||!info.Mode().IsRegular()||info.Mode().Perm()!=0600||info.Sys().(*syscall.Stat_t).Uid!=uint32(os.Geteuid())||info.Sys().(*syscall.Stat_t).Nlink!=1||info.Size()>4<<20{return g0Code("G0_PRIVATE_JOURNAL_HELD")}
 raw:=append(g0JSON(value),'\n');n,e:=f.Write(raw);if e!=nil{return e};if n!=len(raw){return io.ErrShortWrite};if e=f.Sync();e!=nil{return e}
 d,e:=os.Open(dir);if e!=nil{return e};defer d.Close();return d.Sync()
}
type g0Guard struct{mu sync.Mutex;next http.RoundTripper;scheme,host,dir string;requests int;wire int64}
func(g *g0Guard)RoundTrip(r *http.Request)(*http.Response,error){
 g.mu.Lock()
 if (r.Method!="GET"&&r.Method!="HEAD")||r.URL.Scheme!=g.scheme||r.URL.Host!=g.host||r.URL.User!=nil||r.URL.Fragment!=""{g.mu.Unlock();return nil,g0Code("G0_READ_ENDPOINT_ONLY")}
 if g.requests>=g0MaxRequests||g.wire>=g0MaxWire{g.mu.Unlock();return nil,g0Code("G0_CUMULATIVE_READ_BUDGET")}
 n:=g.requests+1
 if e:=g0Append(g.dir,"requests.private.jsonl",map[string]any{"sequence":n,"method":r.Method,"requestSha256":g0Hash([]byte(r.Method+" "+r.URL.RequestURI()))});e!=nil{g.mu.Unlock();return nil,e}
 g.requests=n;g.mu.Unlock()
 response,e:=g.next.RoundTrip(r);if e==nil{response.Body=&g0WireBody{source:response.Body,guard:g,remaining:g0MaxBody+1}}
 return response,e
}
type g0WireBody struct{source io.ReadCloser;guard *g0Guard;remaining int64}
func(b *g0WireBody)Read(p []byte)(int,error){
 b.guard.mu.Lock();defer b.guard.mu.Unlock()
 limit:=g0MaxWire-b.guard.wire;if b.remaining<limit{limit=b.remaining};if limit<=0{return 0,g0Code("G0_WIRE_BYTE_BUDGET")};if int64(len(p))>limit{p=p[:limit]}
 n,e:=b.source.Read(p);b.remaining-=int64(n);b.guard.wire+=int64(n);return n,e
}
func(b *g0WireBody)Close()error{return b.source.Close()}
func g0Client(c Config,dir string)(*s3.Client,*g0Guard,error){
 original,b,e:=client(c);if e!=nil{return nil,nil,e}
 transport:=b.transport.(*http.Transport);transport.DisableCompression=true;transport.DisableKeepAlives=true;transport.MaxResponseHeaderBytes=1<<20
 u,_:=url.Parse(c.Endpoint);g:=&g0Guard{next:transport,scheme:u.Scheme,host:u.Host,dir:dir}
 options:=original.Options();options.HTTPClient=&http.Client{Transport:g,Timeout:15*time.Second,CheckRedirect:func(*http.Request,[]*http.Request)error{return http.ErrUseLastResponse}};options.Retryer=aws.NopRetryer{}
 return s3.New(options),g,nil
}
func g0Snapshot(ctx context.Context,sdk *s3.Client,requests func()int)(map[string]any,[]Row,error){
 rows,features,e:=inventory(ctx,sdk);sum,se:=summary(rows,features);if e==nil{e=se}
 uploads:=[]map[string]any{};if e==nil{uploads,e=multipartInventory(ctx,sdk,features)}
 var incomplete int64;for _,u:=range uploads{incomplete+=u["bytes"].(int64)}
 if sum!=nil{sum["incompleteMultipartUploads"]=len(uploads);sum["incompleteMultipartBytes"]=incomplete}
 // SDK response metadata is non-semantic; normalise maps and ordering for comparison.
 sort.Slice(rows,func(i,j int)bool{return rows[i].Bucket+"\x00"+rows[i].Key+"\x00"+aws.ToString(rows[i].VersionID)<rows[j].Bucket+"\x00"+rows[j].Key+"\x00"+aws.ToString(rows[j].VersionID)})
 sort.Slice(features,func(i,j int)bool{return features[i]["bucket"].(string)<features[j]["bucket"].(string)})
 record:=map[string]any{"schema":"ouf.storage-private-inventory.v1","records":rows,"bucketFeatures":features,"multipartUploads":uploads,"summary":sum,"complete":e==nil,"requests":requests(),"objectBodiesRead":0,"targetWrites":0,"bucketFeaturesInventoried":e==nil,"bucketFeatureValuesComplete":e==nil&&sum!=nil&&sum["unsupportedBucketFeatures"]==0,"writerInventoryComplete":false}
 return record,rows,e
}
func g0Profile(record map[string]any,rows []Row)error{
 if len(rows)>g0MaxObjects{return g0Code("G0_OBJECT_BUDGET")};s:=record["summary"].(map[string]any)
 if s["namespaceGate"]!="PASS"{return g0Code("G0_NAMESPACE_HELD")}
 for _,key:=range []string{"versionedRecords","deleteMarkers","incompleteMultipartUploads"}{if s[key]!=0{return g0Code("G0_VERSION_OR_MULTIPART_PROFILE_HELD")}}
 for _,b:=range record["bucketFeatures"].([]map[string]any){entry:=b["versioning"].(map[string]any);value,ok:=entry["value"].(*s3.GetBucketVersioningOutput);if !ok||value.Status!=""{return g0Code("G0_VERSION_OR_MULTIPART_PROFILE_HELD")}}
 var total int64;for _,r:=range rows{if !r.IsLatest||r.DeleteMarker||r.Size<0||r.Size>g0MaxBody||(r.VersionID!=nil&&*r.VersionID!="null"){return g0Code("G0_BODY_PROFILE_HELD")};total+=r.Size;if total>g0MaxBodies{return g0Code("G0_BODY_BYTE_BUDGET")}}
 return nil
}
func g0Head(ctx context.Context,sdk *s3.Client,row Row)(map[string]any,error){
 h,e:=sdk.HeadObject(ctx,&s3.HeadObjectInput{Bucket:aws.String(row.Bucket),Key:aws.String(row.Key)});if e!=nil{return nil,e}
 if h.ContentLength==nil||*h.ContentLength!=row.Size||h.ETag==nil||*h.ETag==""||strings.HasPrefix(*h.ETag,"W/")||(h.VersionId!=nil&&*h.VersionId!="null"){return nil,g0Code("G0_SOURCE_HEAD_CHANGED")}
 tags,e:=sdk.GetObjectTagging(ctx,&s3.GetObjectTaggingInput{Bucket:aws.String(row.Bucket),Key:aws.String(row.Key)});if e!=nil{return nil,e}
 legacy:=map[string]any{"contentType":h.ContentType,"contentLength":h.ContentLength,"lastModified":h.LastModified,"cacheControl":h.CacheControl,"contentEncoding":h.ContentEncoding,"objectLockMode":h.ObjectLockMode,"retainUntilDate":h.ObjectLockRetainUntilDate,"legalHoldStatus":h.ObjectLockLegalHoldStatus,"serverSideEncryption":h.ServerSideEncryption,"kmsKeyId":h.SSEKMSKeyId}
 if string(g0JSON(legacy))!=string(g0JSON(row.Head))||string(g0JSON(h.Metadata))!=string(g0JSON(row.Metadata))||string(g0JSON(tags.TagSet))!=string(g0JSON(row.Tags)){return nil,g0Code("G0_SOURCE_REPRESENTATION_CHANGED")}
 return map[string]any{"etag":*h.ETag,"head":legacy,"metadata":h.Metadata,"tags":tags.TagSet,"contentDisposition":h.ContentDisposition,"expires":h.Expires,"versionId":h.VersionId},nil
}
func g0ReadBody(ctx context.Context,sdk *s3.Client,row Row,observed map[string]any)(g0Proof,error){
 proof:=g0Proof{Bucket:row.Bucket,Key:row.Key,VersionID:row.VersionID,ETag:observed["etag"].(string),ObservationSHA256:g0Hash(g0JSON(observed))}
 if row.Size<0||row.Size>g0MaxBody{return proof,g0Code("G0_BODY_BYTE_BUDGET")}
 response,e:=sdk.GetObject(ctx,&s3.GetObjectInput{Bucket:aws.String(row.Bucket),Key:aws.String(row.Key),IfMatch:aws.String(proof.ETag)});if e!=nil{return proof,e};defer response.Body.Close()
 if response.ContentLength==nil||*response.ContentLength!=row.Size||aws.ToString(response.ETag)!=proof.ETag||response.ContentRange!=nil||(response.VersionId!=nil&&*response.VersionId!="null"){return proof,g0Code("G0_CONDITIONAL_RESPONSE_MISMATCH")}
 h:=sha256.New();n,e:=io.Copy(h,io.LimitReader(response.Body,row.Size+1));if e!=nil||n!=row.Size{return proof,g0Code("G0_INCOMPLETE_OR_EXCESS_BODY")};proof.Bytes=n;proof.SHA256=hex.EncodeToString(h.Sum(nil))
 hint:=strings.TrimPrefix(strings.ToLower(row.Metadata["ouf-content-hash"]),"sha256:");if hint!=""&&hint!=proof.SHA256{return proof,g0Code("G0_ADVERTISED_HASH_MISMATCH")}
 after,e:=g0Head(ctx,sdk,row);if e!=nil{return proof,e};if !reflect.DeepEqual(g0JSON(after),g0JSON(observed)){return proof,g0Code("G0_SOURCE_CHANGED_AFTER_BODY")}
 return proof,nil
}
func collectG0(configPath,out string)(report g0Receipt,err error){
 report=g0Receipt{Schema:"ouf.storage-g0-body-collection-summary.v1",Status:"HELD",Phase:"CONFIG",Reason:"G0_UNPROVEN",Started:time.Now().UTC().Format(time.RFC3339Nano)}
 // Config is an input binding, never proof of runtime HUMAN approval.
 f,e:=os.OpenFile(configPath,os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK,0);if e!=nil{return report,g0Code("G0_BOUNDED_PRIVATE_CONFIG_REQUIRED")};defer f.Close()
 info,e:=f.Stat();if e!=nil||!info.Mode().IsRegular()||info.Mode().Perm()!=0600||info.Size()>16384||info.Sys().(*syscall.Stat_t).Uid!=uint32(os.Geteuid())||info.Sys().(*syscall.Stat_t).Nlink!=1{return report,g0Code("G0_BOUNDED_PRIVATE_CONFIG_REQUIRED")}
 raw,e:=io.ReadAll(io.LimitReader(f,16385));afterInfo,statError:=f.Stat();if e!=nil||statError!=nil||len(raw)>16384||int64(len(raw))!=info.Size()||!info.ModTime().Equal(afterInfo.ModTime()){return report,g0Code("G0_BOUNDED_PRIVATE_CONFIG_REQUIRED")}
 var c g0Config;d:=json.NewDecoder(strings.NewReader(string(raw)));d.DisallowUnknownFields();if d.Decode(&c)!=nil||d.Decode(new(any))!=io.EOF||c.Schema!="ouf.storage-g0-collection-input.v1"||!g0Name(c.OperationID)||!g0Name(c.InstallationRef){return report,g0Code("G0_EXACT_COLLECTION_INPUT_REQUIRED")}
 if !filepath.IsAbs(out)||filepath.Clean(out)!=out||filepath.Base(out)!=c.OperationID{return report,g0Code("G0_BOUND_NEW_SCOPE_REQUIRED")}
 if e=privateParents(filepath.Dir(out));e!=nil{return report,e};if e=os.Mkdir(out,0700);e!=nil{return report,g0Code("G0_SCOPE_ALREADY_CONSUMED_OR_UNAVAILABLE")}
 if e=writeNew(out,"claim.private.json",g0JSON(map[string]any{"schema":"ouf.storage-g0-claim.v1","operationId":c.OperationID,"installationRef":c.InstallationRef,"configSha256":g0Hash(raw),"maximumRequests":g0MaxRequests,"maximumBodyBytes":g0MaxBodies,"maximumWireBytes":g0MaxWire,"maximumSeconds":300,"automaticReplayAllowed":false,"runtimeAuthorityIssued":false}));e!=nil{return report,e}
 parent,e:=os.Open(filepath.Dir(out));if e!=nil{return report,e};e=parent.Sync();parent.Close();if e!=nil{return report,e}
 var guard *g0Guard
 defer func(){
  report.Finished=time.Now().UTC().Format(time.RFC3339Nano);if guard!=nil{report.Requests=guard.requests;report.WireBytes=guard.wire}
  if err==nil{report.Status="COMPLETE_OBSERVATION_NOT_SNAPSHOT_OR_ADMISSION";report.Reason="NONE";report.Complete=true}else if strings.HasPrefix(err.Error(),"G0_"){report.Reason=err.Error()}else{report.Reason="G0_SOURCE_READ_OR_IO_FAILED"}
  if e:=writeNew(out,"summary.json",g0JSON(report));e!=nil{err=g0Code("G0_SUMMARY_DURABILITY_UNPROVEN");report.Complete=false;report.Status="HELD";report.Reason=err.Error()}
 }()
 sdk,g,e:=g0Client(c.Connection,out);guard=g;if e!=nil{return report,e}
 ctx,cancel:=context.WithTimeout(context.Background(),300*time.Second);defer cancel();counts:=func()int{return guard.requests}
 report.Phase="INITIAL_INVENTORY";before,rows,e:=g0Snapshot(ctx,sdk,counts);if x:=writeNew(out,"inventory-before.private.json",g0JSON(before));x!=nil{return report,x};if e!=nil{return report,e};if e=g0Profile(before,rows);e!=nil{return report,e}
 proofs:=[]g0Proof{};observations:=map[string]map[string]any{};report.Phase="CONDITIONAL_BODIES"
 for _,row:=range rows{
  observed,e:=g0Head(ctx,sdk,row);if e!=nil{return report,e};report.BodiesAttempted++
  if e=g0Append(out,"bodies.private.jsonl",map[string]any{"state":"READ_RESERVED","bucket":row.Bucket,"key":row.Key,"size":row.Size,"observation":observed});e!=nil{return report,e}
  proof,e:=g0ReadBody(ctx,sdk,row,observed);if e!=nil{return report,e}
  if e=g0Append(out,"bodies.private.jsonl",map[string]any{"state":"VERIFIED_AT_READ","proof":proof});e!=nil{return report,e}
  proofs=append(proofs,proof);observations[row.Bucket+"\x00"+row.Key]=observed;report.VerifiedBodies++;report.VerifiedBytes+=proof.Bytes
 }
 report.Phase="FINAL_INVENTORY";after,endRows,e:=g0Snapshot(ctx,sdk,counts);if x:=writeNew(out,"inventory-after.private.json",g0JSON(after));x!=nil{return report,x};if e!=nil{return report,e}
 for _,key:=range []string{"records","bucketFeatures","multipartUploads","summary"}{if string(g0JSON(before[key]))!=string(g0JSON(after[key])){return report,g0Code("G0_SOURCE_SET_OR_FEATURE_DRIFT")}}
 for _,row:=range endRows{observed,e:=g0Head(ctx,sdk,row);if e!=nil{return report,e};if string(g0JSON(observed))!=string(g0JSON(observations[row.Bucket+"\x00"+row.Key])){return report,g0Code("G0_FINAL_SOURCE_OBSERVATION_DRIFT")}}
 if e=writeNew(out,"collection.private.json",g0JSON(map[string]any{"schema":"ouf.storage-g0-body-collection.v1","operationId":c.OperationID,"installationRef":c.InstallationRef,"configSha256":g0Hash(raw),"inventoryBeforeSha256":g0Hash(g0JSON(before)),"inventoryAfterSha256":g0Hash(g0JSON(after)),"objects":proofs,"complete":true,"sourceObservationsEqual":true,"pointInTimeSnapshotProven":false,"writerInventoryComplete":false,"runtimeAuthorityIssued":false}));e!=nil{return report,e}
 report.SourceObservationsEqual=true;report.Phase="SEALED";return report,nil
}
func g0Main(){if len(os.Args)!=4{fmt.Fprintln(os.Stderr,"G0_CONFIG_AND_BOUND_NEW_SCOPE_REQUIRED");os.Exit(2)};r,e:=collectG0(os.Args[2],os.Args[3]);fmt.Println(string(g0JSON(r)));if e!=nil{os.Exit(1)};os.Exit(0)}
