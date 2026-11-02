package storagecopy

import (
 "bytes"
 "context"
 "crypto/tls"
 "crypto/x509"
 "errors"
 "io"
 "net"
 "net/http"
 "net/url"
 "strconv"
 "time"

 "github.com/aws/aws-sdk-go-v2/aws"
 "github.com/aws/aws-sdk-go-v2/credentials"
 "github.com/aws/aws-sdk-go-v2/service/s3"
 "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type requestGate struct { next http.RoundTripper; host string; allowed map[ID]bool; buckets map[string]bool; write bool; credit func()error; retryAfter time.Duration }
func (b *requestGate) RoundTrip(r *http.Request)(*http.Response,error){
 if r.URL.Scheme!="https"||r.URL.Host!=b.host||r.URL.User!=nil||r.URL.Fragment!=""{return nil,code("LAB_ENDPOINT_ESCAPE_DENIED")}
 q:=r.URL.Query();for name:=range q{if name!="tagging"&&name!="versions"&&name!="versioning"&&name!="x-id"&&name!="max-keys"&&name!="key-marker"&&name!="version-id-marker"&&name!="encoding-type"{return nil,code("S3_QUERY_NOT_IN_LAB_SCOPE")}}
 object:=false;for id:=range b.allowed{if r.URL.Path=="/"+id.Bucket+"/"+id.Key{object=true;break}}
 bucket:=false;for name:=range b.buckets{if r.URL.Path=="/"+name{bucket=true;break}}
 if !(object&&(r.Method=="GET"||r.Method=="HEAD"||r.Method=="PUT"&&b.write&&!q.Has("tagging")&&!q.Has("versions")&&!q.Has("versioning")&&r.Header.Get("If-None-Match")=="*")||bucket&&r.Method=="GET"&&(q.Has("versions")||q.Has("versioning"))){return nil,code("SOURCE_MUTATION_OR_OUT_OF_SCOPE_REQUEST_DENIED")}
 if b.credit==nil{return nil,code("DURABLE_REQUEST_RESERVATION_REQUIRED")};if e:=b.credit();e!=nil{return nil,e}
 b.retryAfter=0;response,e:=b.next.RoundTrip(r)
 if e==nil&&response.StatusCode>=429{raw:=response.Header.Get("Retry-After");if n,x:=strconv.Atoi(raw);x==nil&&n>0{b.retryAfter=time.Duration(n)*time.Second}else if when,x:=http.ParseTime(raw);x==nil&&when.After(time.Now()){b.retryAfter=time.Until(when)}}
 return response,e
}
type s3Store struct { sdk *s3.Client; gate *requestGate; id string; write bool }
func newLoopbackS3(endpoint,region,key,secret string,ca []byte,items []Item,write bool)(*s3Store,error){
 u,e:=url.Parse(endpoint);if e!=nil||u.Scheme!="https"||u.User!=nil||u.RawQuery!=""||u.Fragment!=""||u.Path!=""||net.ParseIP(u.Hostname())==nil||!net.ParseIP(u.Hostname()).IsLoopback()||u.Port()==""||region==""||key==""||secret==""{return nil,code("EXPLICIT_SYNTHETIC_LOOPBACK_TLS_PROFILE_REQUIRED")}
 roots:=x509.NewCertPool();if !roots.AppendCertsFromPEM(ca){return nil,code("EXPLICIT_LAB_CA_REQUIRED")}
 transport:=http.DefaultTransport.(*http.Transport).Clone();transport.Proxy=nil;transport.DisableCompression=true
 transport.TLSClientConfig=&tls.Config{RootCAs:roots,MinVersion:tls.VersionTLS12};transport.DialContext=(&net.Dialer{Timeout:5*time.Second}).DialContext;transport.TLSHandshakeTimeout=5*time.Second;transport.ResponseHeaderTimeout=10*time.Second
 gate:=&requestGate{next:transport,host:u.Host,allowed:map[ID]bool{},buckets:map[string]bool{},write:write};for _,it:=range items{gate.allowed[it.ID]=true;gate.buckets[it.ID.Bucket]=true}
 client:=&http.Client{Transport:gate,Timeout:15*time.Second,CheckRedirect:func(*http.Request,[]*http.Request)error{return http.ErrUseLastResponse}}
 sdk:=s3.New(s3.Options{Region:region,BaseEndpoint:aws.String(endpoint),UsePathStyle:true,Credentials:credentials.NewStaticCredentialsProvider(key,secret,""),HTTPClient:client,Retryer:aws.NopRetryer{}})
 return &s3Store{sdk:sdk,gate:gate,id:hash(encode([]string{endpoint,region,hash(ca)})),write:write},nil
}
func (s *s3Store) Identity()string{return s.id}
func (s *s3Store) SetCredit(f func()error){s.gate.credit=f}
func (s *s3Store) failure(err error)error{
 if err==nil{return nil};var api interface{ErrorCode()string};if errors.As(err,&api){switch api.ErrorCode(){case "NoSuchKey","NotFound","NoSuchVersion":return ErrMissing}}
 var status interface{HTTPStatusCode()int};if errors.As(err,&status){switch status.HTTPStatusCode(){case 429,500,502,503,504:return Transient{After:s.gate.retryAfter};case 404:return ErrMissing}}
 var timeout net.Error;if errors.As(err,&timeout)&&timeout.Timeout(){return Transient{}}
 return code("S3_PERMANENT_OR_UNKNOWN_FAILURE")
}
func (s *s3Store) Snapshot(ctx context.Context,buckets []string)(map[ID]Meta,error){
 found:=map[ID]Meta{}
 for _,bucket:=range buckets{
  version,e:=s.sdk.GetBucketVersioning(ctx,&s3.GetBucketVersioningInput{Bucket:aws.String(bucket)});if e!=nil{return nil,s.failure(e)}
  if version.Status==types.BucketVersioningStatusEnabled||s.write&&version.Status!=""{return nil,code("VERSIONED_DESTINATION_OR_SOURCE_REQUIRES_SEPARATE_COPY_ENGINE")}
  paginator:=s3.NewListObjectVersionsPaginator(s.sdk,&s3.ListObjectVersionsInput{Bucket:aws.String(bucket),MaxKeys:aws.Int32(1000)})
  pages:=0
  for paginator.HasMorePages(){pages++;if pages>100{return nil,code("BOUNDED_SNAPSHOT_PAGES_REQUIRED")};page,e:=paginator.NextPage(ctx);if e!=nil{return nil,s.failure(e)}
   if len(page.DeleteMarkers)>0{return nil,code("DELETE_MARKER_HISTORY_REQUIRES_SEPARATE_COPY_ENGINE")}
   for _,row:=range page.Versions{id:=ID{bucket,aws.ToString(row.Key)};if _,ok:=found[id];ok||!aws.ToBool(row.IsLatest)||(aws.ToString(row.VersionId)!=""&&aws.ToString(row.VersionId)!="null")||len(found)>=MaxObjects{return nil,code("VERSION_HISTORY_OR_SNAPSHOT_BUDGET_HELD")}
    found[id]=Meta{Size:aws.ToInt64(row.Size),ETag:aws.ToString(row.ETag),LastModified:aws.ToTime(row.LastModified)}
   }
  }
 }
 return found,nil
}
func (s *s3Store) Head(ctx context.Context,id ID)(Meta,error){
 head,e:=s.sdk.HeadObject(ctx,&s3.HeadObjectInput{Bucket:aws.String(id.Bucket),Key:aws.String(id.Key)});if e!=nil{return Meta{},s.failure(e)}
 if head.ServerSideEncryption!=""||head.SSEKMSKeyId!=nil||head.ObjectLockMode!=""||head.ObjectLockLegalHoldStatus==types.ObjectLockLegalHoldStatusOn||head.ObjectLockRetainUntilDate!=nil{return Meta{},code("ENCRYPTION_OR_RETENTION_REQUIRES_SEPARATE_COPY_PROFILE")}
 tags,e:=s.sdk.GetObjectTagging(ctx,&s3.GetObjectTaggingInput{Bucket:aws.String(id.Bucket),Key:aws.String(id.Key)});if e!=nil{return Meta{},s.failure(e)}
 m:=Meta{Size:aws.ToInt64(head.ContentLength),ETag:aws.ToString(head.ETag),Metadata:map[string]string{},Headers:map[string]string{},Tags:map[string]string{},LastModified:aws.ToTime(head.LastModified)}
 for k,v:=range head.Metadata{m.Metadata[k]=v};for _,tag:=range tags.TagSet{key:=aws.ToString(tag.Key);if _,ok:=m.Tags[key];ok{return Meta{},code("DUPLICATE_OBJECT_TAG")};m.Tags[key]=aws.ToString(tag.Value)}
 for k,v:=range map[string]*string{"contentType":head.ContentType,"cacheControl":head.CacheControl,"contentEncoding":head.ContentEncoding,"contentDisposition":head.ContentDisposition}{if v!=nil{m.Headers[k]=*v}}
 if head.Expires!=nil{m.Headers["expires"]=head.Expires.UTC().Format(http.TimeFormat)}
 return m,nil
}
func (s *s3Store) Read(ctx context.Context,id ID,etag string)([]byte,error){
 if etag==""{return nil,code("FRESH_SOURCE_ETAG_REQUIRED")}
 result,e:=s.sdk.GetObject(ctx,&s3.GetObjectInput{Bucket:aws.String(id.Bucket),Key:aws.String(id.Key),IfMatch:aws.String(etag)});if e!=nil{return nil,s.failure(e)};defer result.Body.Close()
 if aws.ToInt64(result.ContentLength)>MaxObjectBytes{return nil,code("OBJECT_BODY_BUDGET")};raw,e:=io.ReadAll(io.LimitReader(result.Body,MaxObjectBytes+1));if e!=nil{return nil,s.failure(e)};if len(raw)>MaxObjectBytes{return nil,code("OBJECT_BODY_BUDGET")};return raw,nil
}
func (s *s3Store) PutNew(ctx context.Context,id ID,raw []byte,m Meta)error{
 if !s.write||len(raw)>MaxObjectBytes{return code("SOURCE_MUTATION_OR_BODY_BUDGET_DENIED")}
 tags:=url.Values{};for k,v:=range m.Tags{tags.Set(k,v)}
 input:=&s3.PutObjectInput{Bucket:aws.String(id.Bucket),Key:aws.String(id.Key),Body:bytes.NewReader(raw),ContentLength:aws.Int64(int64(len(raw))),Metadata:m.Metadata,IfNoneMatch:aws.String("*")}
 for k,target:=range map[string]**string{"contentType":&input.ContentType,"cacheControl":&input.CacheControl,"contentEncoding":&input.ContentEncoding,"contentDisposition":&input.ContentDisposition}{if v,ok:=m.Headers[k];ok{*target=aws.String(v)}}
 if raw,ok:=m.Headers["expires"];ok{when,e:=http.ParseTime(raw);if e!=nil{return code("ORIGINAL_EXPIRES_HEADER_INVALID")};input.Expires=&when}
 if len(tags)>0{input.Tagging=aws.String(tags.Encode())};_,e:=s.sdk.PutObject(ctx,input);return s.failure(e)
}

// Compile-time wire probes avoid accidental local fallbacks or JSON credential paths.
var _ Store=(*s3Store)(nil)
