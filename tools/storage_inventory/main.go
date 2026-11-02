// Read-only S3 inventory. No object bodies, mutation API or default credential chain.
// This program is preparation for a reviewed target delivery, not a runtime authority.
package main

import (
 "context"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "net"
 "net/http"
 "net/url"
 "os"
 "path/filepath"
 "strings"
 "sync"
 "time"

 "github.com/aws/aws-sdk-go-v2/aws"
 "github.com/aws/aws-sdk-go-v2/credentials"
 "github.com/aws/aws-sdk-go-v2/service/s3"
)

type Config struct {Endpoint string `json:"endpoint"`; Region string `json:"region"`; AccessKeyFile string `json:"accessKeyFile"`; SecretKeyFile string `json:"secretKeyFile"`; AllowLoopbackHTTP bool `json:"allowLoopbackHttp"`}
type Budget struct {mu sync.Mutex; requests int; transport http.RoundTripper}
func (b *Budget) RoundTrip(r *http.Request)(*http.Response,error){
 b.mu.Lock();defer b.mu.Unlock()
 if r.Method!="GET" && r.Method!="HEAD" {return nil,errors.New("MUTATION_DENIED")}
 if b.requests>=10000{return nil,errors.New("READ_BUDGET_EXHAUSTED")};b.requests++
 return b.transport.RoundTrip(r)
}
func endpoint(raw string,allowLoopback bool) error {
 u,e:=url.Parse(raw);if e!=nil||u.Host==""||u.User!=nil||u.RawQuery!=""||u.Fragment!=""||u.Path!="" {return errors.New("INVALID_ENDPOINT")}
 if u.Scheme=="https"{return nil}
 if u.Scheme=="http" && allowLoopback {ip:=net.ParseIP(u.Hostname());if ip!=nil&&ip.IsLoopback(){return nil}}
 return errors.New("TLS_REQUIRED_EXCEPT_EXPLICIT_LOOPBACK")
}
func secret(path string)(string,error){
 s,e:=os.Lstat(path);if e!=nil||!s.Mode().IsRegular()||s.Mode().Perm()&0077!=0||s.Size()<1||s.Size()>4096{return "",errors.New("PRIVATE_SECRET_FILE_REQUIRED")}
 f,e:=os.Open(path);if e!=nil{return "",e};defer f.Close();actual,e:=f.Stat();if e!=nil||!os.SameFile(s,actual){return "",errors.New("SECRET_CHANGED")}
 b,e:=io.ReadAll(io.LimitReader(f,4097));if e!=nil||len(b)>4096{return "",errors.New("SECRET_LIMIT")};v:=strings.TrimSpace(string(b));if v==""||strings.ContainsAny(v,"\r\n"){return "",errors.New("INVALID_SECRET")};return v,nil
}
func client(c Config)(*s3.Client,*Budget,error){
 if e:=endpoint(c.Endpoint,c.AllowLoopbackHTTP);e!=nil{return nil,nil,e}
 if c.Region==""{return nil,nil,errors.New("EXPLICIT_REGION_REQUIRED")}
 a,e:=secret(c.AccessKeyFile);if e!=nil{return nil,nil,e};s,e:=secret(c.SecretKeyFile);if e!=nil{return nil,nil,e}
 transport:=http.DefaultTransport.(*http.Transport).Clone();transport.Proxy=nil
 transport.DialContext=(&net.Dialer{Timeout:5*time.Second}).DialContext;transport.TLSHandshakeTimeout=5*time.Second;transport.ResponseHeaderTimeout=10*time.Second
 b:=&Budget{transport:transport};h:=&http.Client{Transport:b,Timeout:15*time.Second,CheckRedirect:func(*http.Request,[]*http.Request)error{return http.ErrUseLastResponse}}
 sdk:=s3.New(s3.Options{Region:c.Region,BaseEndpoint:aws.String(c.Endpoint),UsePathStyle:true,Credentials:credentials.NewStaticCredentialsProvider(a,s,""),HTTPClient:h,Retryer:aws.NopRetryer{}})
 return sdk,b,nil
}
type Row struct {Bucket string `json:"bucket"`;Key string `json:"key"`;VersionID *string `json:"versionId"`;IsLatest bool `json:"isLatest"`;DeleteMarker bool `json:"deleteMarker"`;Size int64 `json:"size"`;SHA256 *string `json:"sha256"`;MetadataSHA256 *string `json:"metadataSha256"`;Metadata map[string]string `json:"metadata,omitempty"`}
func inventory(ctx context.Context,sdk *s3.Client)([]Row,error){
 rows:=[]Row{};seenBuckets:=map[string]bool{};token:=(*string)(nil)
 for {
  buckets,e:=sdk.ListBuckets(ctx,&s3.ListBucketsInput{ContinuationToken:token});if e!=nil{return rows,e}
  for _,bucket:=range buckets.Buckets{
   name:=aws.ToString(bucket.Name);if name==""||seenBuckets[name]{return rows,errors.New("DUPLICATE_BUCKET")};seenBuckets[name]=true
   pages:=s3.NewListObjectVersionsPaginator(sdk,&s3.ListObjectVersionsInput{Bucket:bucket.Name,MaxKeys:aws.Int32(1000)})
   markers:=map[string]bool{}
   for pages.HasMorePages(){
    page,e:=pages.NextPage(ctx);if e!=nil{return rows,e}
    for _,o:=range page.Versions{
     if len(rows)>=25000{return rows,errors.New("OBJECT_BUDGET_EXHAUSTED")}
     head,e:=sdk.HeadObject(ctx,&s3.HeadObjectInput{Bucket:bucket.Name,Key:o.Key,VersionId:o.VersionId});if e!=nil{return rows,e}
     rows=append(rows,Row{Bucket:name,Key:aws.ToString(o.Key),VersionID:o.VersionId,IsLatest:aws.ToBool(o.IsLatest),Size:aws.ToInt64(o.Size),Metadata:head.Metadata})
    }
    for _,o:=range page.DeleteMarkers{if len(rows)>=25000{return rows,errors.New("OBJECT_BUDGET_EXHAUSTED")};rows=append(rows,Row{Bucket:name,Key:aws.ToString(o.Key),VersionID:o.VersionId,IsLatest:aws.ToBool(o.IsLatest),DeleteMarker:true})}
    if aws.ToBool(page.IsTruncated){marker:=aws.ToString(page.NextKeyMarker)+"\x00"+aws.ToString(page.NextVersionIdMarker);if markers[marker]||marker=="\x00"{return rows,errors.New("NONPROGRESSING_VERSION_PAGINATION")};markers[marker]=true}
   }
  }
  if buckets.ContinuationToken==nil||aws.ToString(buckets.ContinuationToken)==""{break};if token!=nil&&*token==*buckets.ContinuationToken{return rows,errors.New("NONPROGRESSING_BUCKET_PAGINATION")};token=buckets.ContinuationToken
 }
 return rows,nil
}
func execute(configPath,out string) error {
 raw,e:=os.ReadFile(configPath);if e!=nil||len(raw)>16384{return errors.New("BOUNDED_CONFIG_REQUIRED")};var c Config;d:=json.NewDecoder(strings.NewReader(string(raw)));d.DisallowUnknownFields();if d.Decode(&c)!=nil{return errors.New("INVALID_CONFIG")}
 // New output scope is a permanent no-replay claim, including partial failures.
 if !filepath.IsAbs(out){return errors.New("ABSOLUTE_OUTPUT_REQUIRED")};if e=os.Mkdir(out,0700);e!=nil{return errors.New("NEW_PRIVATE_SCOPE_REQUIRED")}
 claim:=[]byte("{\"schema\":\"ouf.storage-inventory-claim.v1\",\"automaticReplayAllowed\":false}\n");if e=os.WriteFile(filepath.Join(out,"claim.json"),claim,0600);e!=nil{return e}
 sdk,budget,e:=client(c);if e!=nil{return e};ctx,cancel:=context.WithTimeout(context.Background(),300*time.Second);defer cancel()
 rows,readError:=inventory(ctx,sdk)
 record:=map[string]any{"schema":"ouf.storage-private-inventory.v1","records":rows,"complete":readError==nil,"requests":budget.requests,"objectBodiesRead":0,"targetWrites":0,"bucketFeaturesInventoried":false,"writerInventoryComplete":false}
 bytes,e:=json.Marshal(record);if e!=nil||len(bytes)>64*1024*1024{return errors.New("PRIVATE_OUTPUT_BUDGET")}
 f,e:=os.OpenFile(filepath.Join(out,"inventory.private.json"),os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600);if e!=nil{return e};if _,e=f.Write(bytes);e==nil{e=f.Sync()};f.Close();if e!=nil{return e}
 fmt.Printf("{\"complete\":%t,\"records\":%d,\"requests\":%d,\"objectBodiesRead\":0,\"targetWrites\":0}\n",readError==nil,len(rows),budget.requests)
 if readError!=nil{return errors.New("INVENTORY_INCOMPLETE_PRIVATE_DETAIL_NOT_PRINTED")};return nil
}
func main(){if len(os.Args)!=3{fmt.Fprintln(os.Stderr,"PRIVATE_CONFIG_AND_NEW_OUTPUT_SCOPE_REQUIRED");os.Exit(2)};if execute(os.Args[1],os.Args[2])!=nil{fmt.Fprintln(os.Stderr,"INVENTORY_STOP_PRIVATE_INPUTS_NOT_PRINTED");os.Exit(1)}}
