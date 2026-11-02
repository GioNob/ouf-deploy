// Read-only S3 inventory. No object bodies, mutation API or default credential chain.
// This program is preparation for a reviewed target delivery, not a runtime authority.
package main

import (
 "context"
 "crypto/tls"
 "crypto/x509"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "net"
 "net/http"
 "net/url"
 "os"
 "path/filepath"
 "runtime"
 "strings"
 "sync"
 "syscall"
 "time"

 "github.com/aws/aws-sdk-go-v2/aws"
 "github.com/aws/aws-sdk-go-v2/credentials"
 "github.com/aws/aws-sdk-go-v2/service/s3"
)

type Config struct {Endpoint string `json:"endpoint"`; Region string `json:"region"`; AccessKeyFile string `json:"accessKeyFile"`; SecretKeyFile string `json:"secretKeyFile"`; AllowLoopbackHTTP bool `json:"allowLoopbackHttp"`; CACertificateFile string `json:"caCertificateFile"`; AccessKeyFD *int `json:"accessKeyFd"`; SecretKeyFD *int `json:"secretKeyFd"`}
type Budget struct {mu sync.Mutex; requests int; transport http.RoundTripper; scheme string; host string}
func (b *Budget) RoundTrip(r *http.Request)(*http.Response,error){
 b.mu.Lock();defer b.mu.Unlock()
 if r.Method!="GET" && r.Method!="HEAD" {return nil,errors.New("MUTATION_DENIED")}
 if b.host!=""&&(r.URL.Host!=b.host||r.URL.Scheme!=b.scheme||r.URL.User!=nil){return nil,errors.New("ENDPOINT_ESCAPE_DENIED")}
 if b.requests>=10000{return nil,errors.New("READ_BUDGET_EXHAUSTED")};b.requests++
 response,e:=b.transport.RoundTrip(r)
 if e==nil {response.Body=&boundedBody{Reader:io.LimitReader(response.Body,4*1024*1024),closer:response.Body}}
 return response,e
}
type boundedBody struct{io.Reader;closer io.Closer}
func (b *boundedBody)Close()error{return b.closer.Close()}
func endpoint(raw string,allowLoopback bool) error {
 u,e:=url.Parse(raw);if e!=nil||u.Host==""||u.User!=nil||u.RawQuery!=""||u.Fragment!=""||u.Path!="" {return errors.New("INVALID_ENDPOINT")}
 if u.Scheme=="https"{return nil}
 if u.Scheme=="http" && allowLoopback {ip:=net.ParseIP(u.Hostname());if ip!=nil&&ip.IsLoopback(){return nil}}
 return errors.New("TLS_REQUIRED_EXCEPT_EXPLICIT_LOOPBACK")
}
func secret(path string)(string,error){
 s,e:=os.Lstat(path);if e!=nil||!s.Mode().IsRegular()||s.Mode().Perm()&0077!=0||s.Size()<1||s.Size()>4096{return "",errors.New("PRIVATE_SECRET_FILE_REQUIRED")}
 owner,ok:=s.Sys().(*syscall.Stat_t);if !ok||owner.Uid!=uint32(os.Geteuid()){return "",errors.New("SECRET_OWNER_MISMATCH")}
 f,e:=os.Open(path);if e!=nil{return "",e};defer f.Close();actual,e:=f.Stat();if e!=nil||!os.SameFile(s,actual){return "",errors.New("SECRET_CHANGED")}
 b,e:=io.ReadAll(io.LimitReader(f,4097));if e!=nil||len(b)>4096{return "",errors.New("SECRET_LIMIT")};v:=strings.TrimSpace(string(b));if v==""||strings.ContainsAny(v,"\r\n"){return "",errors.New("INVALID_SECRET")};return v,nil
}
// Linux F_GET_SEALS validates anonymous immutable credential descriptors supplied by a reviewed launcher.
// This path never copies a credential to a filesystem file.
func sealedSecret(fd int)(string,error){
 if runtime.GOOS!="linux"||runtime.GOARCH!="amd64"||fd<3{return "",errors.New("SEALED_CREDENTIAL_FD_REQUIRED")}
 seals,_,errno:=syscall.Syscall(syscall.SYS_FCNTL,uintptr(fd),1034,0)
 if errno!=0||seals&15!=15{return "",errors.New("IMMUTABLE_CREDENTIAL_FD_REQUIRED")}
 f:=os.NewFile(uintptr(fd),"sealed-credential");if f==nil{return "",errors.New("CREDENTIAL_FD_MISSING")};defer f.Close()
 info,e:=f.Stat();if e!=nil||!info.Mode().IsRegular()||info.Mode().Perm()!=0600||info.Size()<1||info.Size()>4096{return "",errors.New("SEALED_CREDENTIAL_METADATA")}
 owner,ok:=info.Sys().(*syscall.Stat_t);if !ok||owner.Uid!=uint32(os.Geteuid()){return "",errors.New("SEALED_CREDENTIAL_OWNER")}
 if _,e=f.Seek(0,0);e!=nil{return "",e};raw,e:=io.ReadAll(io.LimitReader(f,4097));if e!=nil||len(raw)>4096{return "",errors.New("SEALED_CREDENTIAL_SIZE")}
 value:=strings.TrimSpace(string(raw));if value==""||strings.ContainsAny(value,"\r\n"){return "",errors.New("INVALID_SEALED_CREDENTIAL")};return value,nil
}
func credentialPair(c Config)(string,string,error){
 if c.AccessKeyFD!=nil&&c.SecretKeyFD!=nil&&c.AccessKeyFile==""&&c.SecretKeyFile==""{
  a,e:=sealedSecret(*c.AccessKeyFD);if e!=nil{return "","",e};s,e:=sealedSecret(*c.SecretKeyFD);return a,s,e
 }
 if c.AccessKeyFD!=nil||c.SecretKeyFD!=nil||c.AccessKeyFile==""||c.SecretKeyFile==""{return "","",errors.New("EXACTLY_ONE_CREDENTIAL_BINDING_REQUIRED")}
 a,e:=secret(c.AccessKeyFile);if e!=nil{return "","",e};s,e:=secret(c.SecretKeyFile);return a,s,e
}
func client(c Config)(*s3.Client,*Budget,error){
 if e:=endpoint(c.Endpoint,c.AllowLoopbackHTTP);e!=nil{return nil,nil,e}
 if c.Region==""{return nil,nil,errors.New("EXPLICIT_REGION_REQUIRED")}
 a,s,e:=credentialPair(c);if e!=nil{return nil,nil,e}
 transport:=http.DefaultTransport.(*http.Transport).Clone();transport.Proxy=nil
 transport.DialContext=(&net.Dialer{Timeout:5*time.Second}).DialContext;transport.TLSHandshakeTimeout=5*time.Second;transport.ResponseHeaderTimeout=10*time.Second
 if c.CACertificateFile!=""{info,e:=os.Lstat(c.CACertificateFile);if e!=nil||!info.Mode().IsRegular()||info.Size()>1048576{return nil,nil,errors.New("BOUNDED_CA_FILE_REQUIRED")};raw,e:=os.ReadFile(c.CACertificateFile);if e!=nil{return nil,nil,e};pool:=x509.NewCertPool();if !pool.AppendCertsFromPEM(raw){return nil,nil,errors.New("INVALID_CA")};transport.TLSClientConfig=&tls.Config{RootCAs:pool,MinVersion:tls.VersionTLS12}}
 parsed,_:=url.Parse(c.Endpoint);b:=&Budget{transport:transport,scheme:parsed.Scheme,host:parsed.Host};h:=&http.Client{Transport:b,Timeout:15*time.Second,CheckRedirect:func(*http.Request,[]*http.Request)error{return http.ErrUseLastResponse}}
 sdk:=s3.New(s3.Options{Region:c.Region,BaseEndpoint:aws.String(c.Endpoint),UsePathStyle:true,Credentials:credentials.NewStaticCredentialsProvider(a,s,""),HTTPClient:h,Retryer:aws.NopRetryer{}})
 return sdk,b,nil
}
type Row struct {Bucket string `json:"bucket"`;Key string `json:"key"`;VersionID *string `json:"versionId"`;IsLatest bool `json:"isLatest"`;DeleteMarker bool `json:"deleteMarker"`;Size int64 `json:"size"`;SHA256 *string `json:"sha256"`;MetadataSHA256 *string `json:"metadataSha256"`;Metadata map[string]string `json:"metadata,omitempty"`;Head map[string]any `json:"headMetadata,omitempty"`;Tags any `json:"tags,omitempty"`}
func inventory(ctx context.Context,sdk *s3.Client)([]Row,[]map[string]any,error){
 rows:=[]Row{};features:=[]map[string]any{};privateBytes:=0
 appendRow:=func(row Row)error{encoded,e:=json.Marshal(row);if e!=nil||len(encoded)>65536||privateBytes+len(encoded)>64*1024*1024{return errors.New("PRIVATE_INVENTORY_MEMORY_BUDGET")};privateBytes+=len(encoded);rows=append(rows,row);return nil};seenBuckets:=map[string]bool{};token:=(*string)(nil)
 for {
  buckets,e:=sdk.ListBuckets(ctx,&s3.ListBucketsInput{ContinuationToken:token});if e!=nil{return rows,features,e}
  for _,bucket:=range buckets.Buckets{
   name:=aws.ToString(bucket.Name);if name==""||seenBuckets[name]{return rows,features,errors.New("DUPLICATE_BUCKET")};seenBuckets[name]=true
   featureSet:=map[string]any{"bucket":name}
   readFeature:=func(name string,read func()(any,error))error{
    value,err:=read();if err==nil{raw,e:=json.Marshal(value);if e!=nil||len(raw)>1024*1024||privateBytes+len(raw)>64*1024*1024{return errors.New("BUCKET_FEATURE_BUDGET")};privateBytes+=len(raw);featureSet[name]=map[string]any{"status":"PRESENT","value":value};return nil}
    var api interface{ErrorCode()string};if errors.As(err,&api){
     code:=api.ErrorCode()
     for _,absent:=range []string{"NoSuchBucketPolicy","NoSuchLifecycleConfiguration","ReplicationConfigurationNotFoundError","ServerSideEncryptionConfigurationNotFoundError","ObjectLockConfigurationNotFoundError","NoSuchObjectLockConfiguration","NoSuchCORSConfiguration","NoSuchTagSet","NoSuchPublicAccessBlockConfiguration"}{if code==absent{featureSet[name]=map[string]any{"status":"ABSENT","code":code};return nil}}
     if code=="NotImplemented"{featureSet[name]=map[string]any{"status":"UNSUPPORTED","code":code};return nil}
    };return err
   }
   calls:=[]struct{name string;read func()(any,error)}{
    {"versioning",func()(any,error){return sdk.GetBucketVersioning(ctx,&s3.GetBucketVersioningInput{Bucket:bucket.Name})}},
    {"encryption",func()(any,error){return sdk.GetBucketEncryption(ctx,&s3.GetBucketEncryptionInput{Bucket:bucket.Name})}},
    {"policy",func()(any,error){return sdk.GetBucketPolicy(ctx,&s3.GetBucketPolicyInput{Bucket:bucket.Name})}},
    {"objectLock",func()(any,error){return sdk.GetObjectLockConfiguration(ctx,&s3.GetObjectLockConfigurationInput{Bucket:bucket.Name})}},
    {"lifecycle",func()(any,error){return sdk.GetBucketLifecycleConfiguration(ctx,&s3.GetBucketLifecycleConfigurationInput{Bucket:bucket.Name})}},
    {"replication",func()(any,error){return sdk.GetBucketReplication(ctx,&s3.GetBucketReplicationInput{Bucket:bucket.Name})}},
    {"notification",func()(any,error){return sdk.GetBucketNotificationConfiguration(ctx,&s3.GetBucketNotificationConfigurationInput{Bucket:bucket.Name})}},
    {"cors",func()(any,error){return sdk.GetBucketCors(ctx,&s3.GetBucketCorsInput{Bucket:bucket.Name})}},
    {"acl",func()(any,error){return sdk.GetBucketAcl(ctx,&s3.GetBucketAclInput{Bucket:bucket.Name})}},
    {"publicAccessBlock",func()(any,error){return sdk.GetPublicAccessBlock(ctx,&s3.GetPublicAccessBlockInput{Bucket:bucket.Name})}},
   }
   for _,call:=range calls{if e:=readFeature(call.name,call.read);e!=nil{features=append(features,featureSet);return rows,features,e}}
   features=append(features,featureSet)
   pages:=s3.NewListObjectVersionsPaginator(sdk,&s3.ListObjectVersionsInput{Bucket:bucket.Name,MaxKeys:aws.Int32(1000)})
   markers:=map[string]bool{}
   for pages.HasMorePages(){
    page,e:=pages.NextPage(ctx);if e!=nil{return rows,features,e}
    for _,o:=range page.Versions{
     if len(rows)>=25000{return rows,features,errors.New("OBJECT_BUDGET_EXHAUSTED")}
     head,e:=sdk.HeadObject(ctx,&s3.HeadObjectInput{Bucket:bucket.Name,Key:o.Key,VersionId:o.VersionId});if e!=nil{return rows,features,e}
     tags,e:=sdk.GetObjectTagging(ctx,&s3.GetObjectTaggingInput{Bucket:bucket.Name,Key:o.Key,VersionId:o.VersionId});if e!=nil{return rows,features,e}
     if e:=appendRow(Row{Bucket:name,Key:aws.ToString(o.Key),VersionID:o.VersionId,IsLatest:aws.ToBool(o.IsLatest),Size:aws.ToInt64(o.Size),Metadata:head.Metadata,Tags:tags.TagSet,Head:map[string]any{"contentType":head.ContentType,"contentLength":head.ContentLength,"lastModified":head.LastModified,"cacheControl":head.CacheControl,"contentEncoding":head.ContentEncoding,"objectLockMode":head.ObjectLockMode,"retainUntilDate":head.ObjectLockRetainUntilDate,"legalHoldStatus":head.ObjectLockLegalHoldStatus,"serverSideEncryption":head.ServerSideEncryption,"kmsKeyId":head.SSEKMSKeyId}});e!=nil{return rows,features,e}
    }
    for _,o:=range page.DeleteMarkers{if len(rows)>=25000{return rows,features,errors.New("OBJECT_BUDGET_EXHAUSTED")};if e:=appendRow(Row{Bucket:name,Key:aws.ToString(o.Key),VersionID:o.VersionId,IsLatest:aws.ToBool(o.IsLatest),DeleteMarker:true});e!=nil{return rows,features,e}}
    if aws.ToBool(page.IsTruncated){marker:=aws.ToString(page.NextKeyMarker)+"\x00"+aws.ToString(page.NextVersionIdMarker);if markers[marker]||marker=="\x00"{return rows,features,errors.New("NONPROGRESSING_VERSION_PAGINATION")};markers[marker]=true}
   }
  }
  if buckets.ContinuationToken==nil||aws.ToString(buckets.ContinuationToken)==""{break};if token!=nil&&*token==*buckets.ContinuationToken{return rows,features,errors.New("NONPROGRESSING_BUCKET_PAGINATION")};token=buckets.ContinuationToken
 }
 return rows,features,nil
}
func multipartInventory(ctx context.Context,sdk *s3.Client,buckets []map[string]any)([]map[string]any,error){
 result:=[]map[string]any{};seen:=map[string]bool{};partsCount:=0
 for _,b:=range buckets{
  bucket:=b["bucket"].(string);pages:=s3.NewListMultipartUploadsPaginator(sdk,&s3.ListMultipartUploadsInput{Bucket:aws.String(bucket),MaxUploads:aws.Int32(1000)})
  markers:=map[string]bool{}
  for pages.HasMorePages(){page,e:=pages.NextPage(ctx);if e!=nil{return result,e}
   for _,upload:=range page.Uploads{
    id:=bucket+"\x00"+aws.ToString(upload.Key)+"\x00"+aws.ToString(upload.UploadId);if seen[id]||len(result)>=25000{return result,errors.New("DUPLICATE_OR_UNBOUNDED_MULTIPART")};seen[id]=true
    partPages:=s3.NewListPartsPaginator(sdk,&s3.ListPartsInput{Bucket:aws.String(bucket),Key:upload.Key,UploadId:upload.UploadId,MaxParts:aws.Int32(1000)})
    parts:=[]map[string]any{};var bytes int64;partMarkers:=map[string]bool{}
    for partPages.HasMorePages(){partPage,e:=partPages.NextPage(ctx);if e!=nil{return result,e}
     for _,part:=range partPage.Parts{partsCount++;size:=aws.ToInt64(part.Size);if partsCount>25000||size<0||bytes>int64(9223372036854775807)-size{return result,errors.New("MULTIPART_PART_BUDGET")};bytes+=size;parts=append(parts,map[string]any{"partNumber":part.PartNumber,"size":part.Size,"etag":part.ETag})}
     if aws.ToBool(partPage.IsTruncated){marker:=aws.ToString(partPage.NextPartNumberMarker);if marker==""||partMarkers[marker]{return result,errors.New("NONPROGRESSING_PART_PAGINATION")};partMarkers[marker]=true}
    }
    result=append(result,map[string]any{"bucket":bucket,"key":upload.Key,"uploadId":upload.UploadId,"initiated":upload.Initiated,"bytes":bytes,"parts":parts})
   }
   if aws.ToBool(page.IsTruncated){marker:=aws.ToString(page.NextKeyMarker)+"\x00"+aws.ToString(page.NextUploadIdMarker);if marker=="\x00"||markers[marker]{return result,errors.New("NONPROGRESSING_MULTIPART_PAGINATION")};markers[marker]=true}
  }
 }
 return result,nil
}
func summary(rows []Row,features []map[string]any)(map[string]any,error){
 objects,versions,markers,hashes,collisions,unsafe,trailing:=0,0,0,0,0,0,0;var total int64;keys:=map[string]map[string]bool{};identities:=map[string]bool{};latest:=map[string]bool{}
 for _,r:=range rows{
  version:=aws.ToString(r.VersionID);id:=r.Bucket+"\x00"+r.Key+"\x00"+version
  if identities[id]||r.Key==""||r.Size<0{return nil,errors.New("INVALID_OR_DUPLICATE_OBJECT_IDENTITY")};identities[id]=true
  if r.IsLatest{identity:=r.Bucket+"\x00"+r.Key;if latest[identity]{return nil,errors.New("MULTIPLE_LATEST_VERSIONS")};latest[identity]=true}
  if keys[r.Bucket]==nil{keys[r.Bucket]=map[string]bool{}};keys[r.Bucket][r.Key]=true
  if version!=""&&version!="null"{versions++}
  if r.DeleteMarker{markers++}else{objects++;if r.Size>0&&total>int64(9223372036854775807)-r.Size{return nil,errors.New("BYTE_COUNT_OVERFLOW")};total+=r.Size;if r.Metadata["ouf-content-hash"]!=""{hashes++}}
 }
 for _,bucketKeys:=range keys{for key:=range bucketKeys{
  parts:=strings.Split(key,"/");bad:=strings.HasPrefix(key,"/")||strings.Contains(key,"//")||strings.ContainsAny(key,"\\\x00")
  for _,part:=range parts{if part=="."||part==".."{bad=true}}
  if bad{unsafe++};if strings.HasSuffix(key,"/"){trailing++}
  for i:=1;i<len(parts);i++{if bucketKeys[strings.Join(parts[:i],"/")]{collisions++;break}}
 }}
 unsupported,versionedBuckets,encryptedBuckets,lockedBuckets,replicatedBuckets,lifecycleBuckets,notifiedBuckets:=0,0,0,0,0,0,0
 for _,f:=range features{
  for _,item:=range f{if entry,ok:=item.(map[string]any);ok{switch value:=entry["value"].(type){
   case *s3.GetBucketVersioningOutput:if value.Status=="Enabled"{versionedBuckets++}
   case *s3.GetBucketEncryptionOutput:if value.ServerSideEncryptionConfiguration!=nil&&len(value.ServerSideEncryptionConfiguration.Rules)>0{encryptedBuckets++}
   case *s3.GetObjectLockConfigurationOutput:if value.ObjectLockConfiguration!=nil&&value.ObjectLockConfiguration.ObjectLockEnabled=="Enabled"{lockedBuckets++}
   case *s3.GetBucketReplicationOutput:if value.ReplicationConfiguration!=nil&&len(value.ReplicationConfiguration.Rules)>0{replicatedBuckets++}
   case *s3.GetBucketLifecycleConfigurationOutput:if len(value.Rules)>0{lifecycleBuckets++}
   case *s3.GetBucketNotificationConfigurationOutput:if len(value.LambdaFunctionConfigurations)+len(value.QueueConfigurations)+len(value.TopicConfigurations)>0||value.EventBridgeConfiguration!=nil{notifiedBuckets++}
  }}}
for _,v:=range f{if item,ok:=v.(map[string]any);ok&&item["status"]=="UNSUPPORTED"{unsupported++}}}
 gate:="PASS";if collisions+unsafe+trailing>0{gate="HELD"}
 return map[string]any{"buckets":len(features),"objectVersions":objects,"versionedRecords":versions,"deleteMarkers":markers,"bytesAcrossVersions":total,"objectsWithAdvertisedOufHash":hashes,"fileDirectoryCollisions":collisions,"unsafePathKeys":unsafe,"trailingSlashKeys":trailing,"namespaceGate":gate,"unsupportedBucketFeatures":unsupported,"versioningEnabledBuckets":versionedBuckets,"defaultEncryptedBuckets":encryptedBuckets,"objectLockEnabledBuckets":lockedBuckets,"replicatedBuckets":replicatedBuckets,"lifecycleBuckets":lifecycleBuckets,"notificationConfiguredBuckets":notifiedBuckets},nil
}
func privateParents(path string)error{
 for p:=filepath.Clean(path);;p=filepath.Dir(p){
  info,e:=os.Lstat(p);if e!=nil||!info.IsDir()||info.Mode()&os.ModeSymlink!=0{return errors.New("UNSAFE_OUTPUT_ANCESTRY")}
  owner,ok:=info.Sys().(*syscall.Stat_t);if !ok||(owner.Uid!=0&&owner.Uid!=uint32(os.Geteuid())){return errors.New("UNTRUSTED_OUTPUT_OWNER")}
  if info.Mode().Perm()&0022!=0 && info.Mode()&os.ModeSticky==0{return errors.New("WRITABLE_OUTPUT_ANCESTRY")}
  if p==filepath.Dir(p){break}
 };return nil
}
func writeNew(dir,name string,raw []byte)error{
 f,e:=os.OpenFile(filepath.Join(dir,name),os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW,0600);if e!=nil{return e}
 if _,e=f.Write(raw);e==nil{e=f.Sync()};f.Close();if e!=nil{return e}
 d,e:=os.Open(dir);if e!=nil{return e};defer d.Close();return d.Sync()
}
func execute(configPath,out string) error {
 configInfo,e:=os.Lstat(configPath);if e!=nil||!configInfo.Mode().IsRegular()||configInfo.Mode().Perm()&0077!=0||configInfo.Size()>16384{return errors.New("PRIVATE_CONFIG_REQUIRED")}
 raw,e:=os.ReadFile(configPath);if e!=nil||len(raw)>16384{return errors.New("BOUNDED_CONFIG_REQUIRED")};var c Config;d:=json.NewDecoder(strings.NewReader(string(raw)));d.DisallowUnknownFields();if d.Decode(&c)!=nil{return errors.New("INVALID_CONFIG")}
 // New output scope is a permanent no-replay claim, including partial failures.
 if !filepath.IsAbs(out){return errors.New("ABSOLUTE_OUTPUT_REQUIRED")};if e=privateParents(filepath.Dir(out));e!=nil{return e};if e=os.Mkdir(out,0700);e!=nil{return errors.New("NEW_PRIVATE_SCOPE_REQUIRED")}
 parent,e:=os.Open(filepath.Dir(out));if e!=nil{return e};e=parent.Sync();parent.Close();if e!=nil{return e}
 claim:=[]byte("{\"schema\":\"ouf.storage-inventory-claim.v1\",\"automaticReplayAllowed\":false}\n");if e=writeNew(out,"claim.json",claim);e!=nil{return e}
 sdk,budget,e:=client(c);if e!=nil{return e};ctx,cancel:=context.WithTimeout(context.Background(),300*time.Second);defer cancel()
 rows,features,readError:=inventory(ctx,sdk)
 publicSummary,summaryError:=summary(rows,features);if readError==nil{readError=summaryError}
 multipart:=[]map[string]any{}
 if readError==nil{multipart,readError=multipartInventory(ctx,sdk,features)}
 var incompleteBytes int64;for _,upload:=range multipart{size:=upload["bytes"].(int64);if size>0&&incompleteBytes>int64(9223372036854775807)-size{readError=errors.New("MULTIPART_TOTAL_OVERFLOW");break};incompleteBytes+=size}
 if publicSummary!=nil{publicSummary["incompleteMultipartUploads"]=len(multipart);publicSummary["incompleteMultipartBytes"]=incompleteBytes}
 record:=map[string]any{"summary":publicSummary,"schema":"ouf.storage-private-inventory.v1","records":rows,"complete":readError==nil,"requests":budget.requests,"objectBodiesRead":0,"targetWrites":0,"bucketFeaturesInventoried":readError==nil,"bucketFeatures":features,"multipartUploads":multipart,"writerInventoryComplete":false}
 if readError!=nil{failure:=map[string]string{"class":"INVENTORY_READ_FAILED"};var api interface{ErrorCode()string};if errors.As(readError,&api){failure["apiCode"]=api.ErrorCode()};var operation interface{Operation()string};if errors.As(readError,&operation){failure["operation"]=operation.Operation()};record["failure"]=failure}
 bytes,e:=json.Marshal(record);if e!=nil||len(bytes)>64*1024*1024{return errors.New("PRIVATE_OUTPUT_BUDGET")}
 if e=writeNew(out,"inventory.private.json",bytes);e!=nil{return e}
 public:=map[string]any{"complete":readError==nil,"records":len(rows),"requests":budget.requests,"objectBodiesRead":0,"targetWrites":0,"summary":publicSummary};publicJSON,_:=json.Marshal(public);fmt.Println(string(publicJSON))
 if readError!=nil{return errors.New("INVENTORY_INCOMPLETE_PRIVATE_DETAIL_NOT_PRINTED")};return nil
}
func main(){if len(os.Args)!=3{fmt.Fprintln(os.Stderr,"PRIVATE_CONFIG_AND_NEW_OUTPUT_SCOPE_REQUIRED");os.Exit(2)};if execute(os.Args[1],os.Args[2])!=nil{fmt.Fprintln(os.Stderr,"INVENTORY_STOP_PRIVATE_INPUTS_NOT_PRINTED");os.Exit(1)}}
