package storagecopy

import (
 "bytes"
 "compress/gzip"
 "context"
 "crypto/tls"
 "crypto/x509"
 "encoding/json"
 "encoding/pem"
 "errors"
 "fmt"
 "io"
 "net/http"
 "net/http/httptest"
 "net/http/httputil"
 "net/url"
 "os"
 "os/exec"
 "path/filepath"
 "strconv"
 "strings"
 "sync"
 "sync/atomic"
 "testing"
 "time"

 "github.com/aws/aws-sdk-go-v2/aws"
 "github.com/aws/aws-sdk-go-v2/credentials"
 "github.com/aws/aws-sdk-go-v2/service/s3"
 "github.com/aws/aws-sdk-go-v2/service/s3/types"
)
const sourceKey="synthetic-source-admin"
const sourceSecret="synthetic-source-secret-not-production"
const destinationKey="synthetic-destination-admin"
const destinationSecret="synthetic-destination-secret-not-production"
func lab(t *testing.T)(string,string,[]byte){t.Helper();if os.Getenv("OUF_COPY_LAB")!="1"||os.Getenv("GITHUB_ACTIONS")!="true"{t.Fatal("isolated synthetic fixture required")};ca,e:=os.ReadFile(os.Getenv("OUF_COPY_CA"));if e!=nil{t.Fatal(e)};return os.Getenv("OUF_COPY_SOURCE"),os.Getenv("OUF_COPY_DESTINATION"),ca}
func admin(t *testing.T,endpoint string,ca []byte,key,secret string)*s3.Client{t.Helper();roots:=x509.NewCertPool();if !roots.AppendCertsFromPEM(ca){t.Fatal("fixture CA")};tr:=http.DefaultTransport.(*http.Transport).Clone();tr.Proxy=nil;tr.DisableCompression=true;tr.TLSClientConfig=&tls.Config{RootCAs:roots,MinVersion:tls.VersionTLS12};return s3.New(s3.Options{Region:"us-east-1",BaseEndpoint:aws.String(endpoint),UsePathStyle:true,Credentials:credentials.NewStaticCredentialsProvider(key,secret,""),HTTPClient:&http.Client{Transport:tr,Timeout:15*time.Second},Retryer:aws.NopRetryer{}})}
func create(t *testing.T,c *s3.Client,bucket string){t.Helper();if _,e:=c.CreateBucket(context.Background(),&s3.CreateBucketInput{Bucket:aws.String(bucket)});e!=nil{t.Fatal(e)}}
func stores(t *testing.T,src,dst string,caSrc,caDst []byte,items []Item)(*s3Store,*s3Store){t.Helper();s,e:=newLoopbackS3(src,"us-east-1",sourceKey,sourceSecret,caSrc,items,false);if e!=nil{t.Fatal(e)};d,e:=newLoopbackS3(dst,"us-east-1",destinationKey,destinationSecret,caDst,items,true);if e!=nil{t.Fatal(e)};return s,d}
func makeSingle(t *testing.T,name string)([]Item,string,string,[]byte){t.Helper();src,dst,ca:=lab(t);a:=admin(t,src,ca,sourceKey,sourceSecret);b:=admin(t,dst,ca,destinationKey,destinationSecret);bucket:="lab-"+name;create(t,a,bucket);create(t,b,bucket);raw:=[]byte("synthetic only, never OUF data");_,e:=a.PutObject(context.Background(),&s3.PutObjectInput{Bucket:aws.String(bucket),Key:aws.String("data"),Body:bytes.NewReader(raw),ContentType:aws.String("application/octet-stream"),Metadata:map[string]string{"ouf-content-hash":"sha256:"+hash(raw)}});if e!=nil{t.Fatal(e)}
 items:=[]Item{{ID:ID{bucket,"data"}}};s,_:=stores(t,src,dst,ca,ca,items);s.SetCredit(func()error{return nil});m,e:=s.Head(context.Background(),items[0].ID);if e!=nil{t.Fatal(e)};items[0].Meta=m;return items,src,dst,ca}
func TestRealConditionalAtomicity(t *testing.T){_,dst,ca:=lab(t);client:=admin(t,dst,ca,destinationKey,destinationSecret);bucket:="lab-atomic-preconditions";create(t,client,bucket);start:=make(chan struct{});var successes,denials,other atomic.Int32;var wg sync.WaitGroup
 for i:=0;i<16;i++{wg.Add(1);go func(i int){defer wg.Done();<-start;_,e:=client.PutObject(context.Background(),&s3.PutObjectInput{Bucket:aws.String(bucket),Key:aws.String("one-winner"),Body:strings.NewReader(strconv.Itoa(i)),IfNoneMatch:aws.String("*")});if e==nil{successes.Add(1)}else{var status interface{HTTPStatusCode()int};if errors.As(e,&status)&&(status.HTTPStatusCode()==412||status.HTTPStatusCode()==409){denials.Add(1)}else{other.Add(1)}}}(i)}
 close(start);wg.Wait();if successes.Load()!=1||denials.Load()!=15||other.Load()!=0{t.Fatalf("CAS not qualified: success%d denial%d other%d",successes.Load(),denials.Load(),other.Load())};t.Log("one conditional winner, fifteen rejected; real isolated S3")
}
func TestRealCopy120FromExactInventoryCompilerWire(t *testing.T){src,dst,ca:=lab(t);source:=admin(t,src,ca,sourceKey,sourceSecret);dest:=admin(t,dst,ca,destinationKey,destinationSecret)
 buckets:=[]string{"lab-copy-a","lab-copy-b"};for _,b:=range buckets{create(t,source,b);create(t,dest,b)}
 expected:=map[ID][]byte{}
 for i:=0;i<120;i++{size:=1000;if i==119{size=84743};body:=bytes.Repeat([]byte{byte(i)},size);key:=fmt.Sprintf("object-%03d",i);if i==0{key="private/è%2F?+#"};id:=ID{buckets[i/60],key};metadata:=map[string]string{};if i<110{metadata["ouf-content-hash"]="sha256:"+hash(body)};_,e:=source.PutObject(context.Background(),&s3.PutObjectInput{Bucket:aws.String(id.Bucket),Key:aws.String(id.Key),Body:bytes.NewReader(body),Metadata:metadata,ContentType:aws.String("application/octet-stream")});if e!=nil{t.Fatal(e)};expected[id]=body}
 root:=t.TempDir();put:=func(name string,raw []byte)string{p:=filepath.Join(root,name);if e:=os.WriteFile(p,raw,0600);e!=nil{t.Fatal(e)};return p}
 access:=put("synthetic-access",[]byte(sourceKey));secret:=put("synthetic-secret",[]byte(sourceSecret));config:=put("inventory-config",encode(map[string]any{"endpoint":src,"region":"us-east-1","accessKeyFile":access,"secretKeyFile":secret,"caCertificateFile":os.Getenv("OUF_COPY_CA")}));inventory:=filepath.Join(root,"inventory")
 cmd:=exec.Command(os.Getenv("OUF_COPY_INVENTORY_BINARY"),config,inventory);if output,e:=cmd.CombinedOutput();e!=nil{t.Fatalf("synthetic inventory %v %s",e,output)}
 plan:=filepath.Join(root,"private-plan.json");script:="import importlib.util,json,sys;spec=importlib.util.spec_from_file_location('compiler',sys.argv[1]);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);p,r=m.compile_plan(json.load(open(sys.argv[2])));assert r['records']==120 and r['objectsWithoutAdvertisedHash']==10;open(sys.argv[3],'wb').write(m.canonical(p))"
 cmd=exec.Command("python3","-I","-B","-S","-c",script,os.Getenv("OUF_COPY_COMPILER"),filepath.Join(inventory,"inventory.private.json"),plan);if output,e:=cmd.CombinedOutput();e!=nil{t.Fatalf("compiler wire %v %s",e,output)}
 raw,e:=os.ReadFile(plan);if e!=nil{t.Fatal(e)};items,e:=itemsFromPrivatePlan(raw);if e!=nil{t.Fatal(e)};s,d:=stores(t,src,dst,ca,ca,items)
 report,e:=(&Engine{Source:s,Destination:d}).run(context.Background(),items,filepath.Join(root,"copy-ledger"));if e!=nil||report.Verified!=120||report.CopiedThisAttempt!=120{t.Fatalf("real copy %v %+v",e,report)}
 var bytesVerified int;for id,want:=range expected{got,e:=dest.GetObject(context.Background(),&s3.GetObjectInput{Bucket:aws.String(id.Bucket),Key:aws.String(id.Key)});if e!=nil{t.Fatal(e)};body,e:=io.ReadAll(got.Body);got.Body.Close();if e!=nil||!bytes.Equal(body,want){t.Fatal("independent full body parity")};bytesVerified+=len(body)};if bytesVerified!=203743{t.Fatal(bytesVerified)}
 t.Log("120 synthetic records / 203743 bytes / ten absent advertised hashes; exact existing inventory and compiler wire; all destination bodies independently reread")
}
func proxyFor(t *testing.T,ambiguous bool)(*httptest.Server,[]byte,*atomic.Int32){t.Helper();target,e:=url.Parse(os.Getenv("OUF_COPY_DEST_HTTP"));if e!=nil{t.Fatal(e)};proxy:=httputil.NewSingleHostReverseProxy(target);counter:=&atomic.Int32{}
 proxy.ModifyResponse=func(r *http.Response)error{if r.Request.Method=="PUT"&&!r.Request.URL.Query().Has("tagging"){n:=counter.Add(1);if ambiguous&&n==1&&r.StatusCode>=200&&r.StatusCode<300{r.Body.Close();body:=[]byte("<Error><Code>ServiceUnavailable</Code><Message>Synthetic ambiguous response</Message></Error>");r.StatusCode=503;r.Body=io.NopCloser(bytes.NewReader(body));r.ContentLength=int64(len(body));r.Header=http.Header{"Content-Type":[]string{"application/xml"},"Retry-After":[]string{"3600"}}}};return nil}
 server:=httptest.NewTLSServer(proxy);t.Cleanup(server.Close);ca:=pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:server.Certificate().Raw});return server,ca,counter}
type childConfig struct{Items []Item;Source,Destination,CA,DestinationCA,Scope,Point string}
func TestProcessCrashChild(t *testing.T){if os.Getenv("OUF_COPY_CRASH_CHILD")!="1"{return};raw,e:=os.ReadFile(os.Getenv("OUF_COPY_CHILD_CONFIG"));if e!=nil{t.Fatal(e)};var c childConfig;if json.Unmarshal(raw,&c)!=nil{t.Fatal("synthetic child config")};ca,e:=os.ReadFile(c.CA);if e!=nil{t.Fatal(e)};destCA,e:=os.ReadFile(c.DestinationCA);if e!=nil{t.Fatal(e)};s,d:=stores(t,c.Source,c.Destination,ca,destCA,c.Items);_,e=(&Engine{Source:s,Destination:d,Hook:func(point string)error{if point==c.Point{os.Exit(86)};return nil}}).run(context.Background(),c.Items,c.Scope);t.Fatal("crash point not reached",e)}
func TestRealProcessCrashResumeNoSecondPut(t *testing.T){for _,point:=range []string{"BEFORE_PUT","AFTER_PUT","BEFORE_CHECKPOINT"}{t.Run(point,func(t *testing.T){items,src,_,ca:=makeSingle(t,strings.ToLower(strings.ReplaceAll(point,"_","-")));proxy,destCA,counter:=proxyFor(t,false);root:=t.TempDir();caPath:=filepath.Join(root,"proxy-ca.pem");os.WriteFile(caPath,destCA,0600);scope:=filepath.Join(root,"copy-ledger");cfg:=filepath.Join(root,"synthetic-config");os.WriteFile(cfg,encode(childConfig{items,src,proxy.URL,os.Getenv("OUF_COPY_CA"),caPath,scope,point}),0600);binary,e:=os.Executable();if e!=nil{t.Fatal(e)}
 cmd:=exec.Command(binary,"-test.run=^TestProcessCrashChild$");cmd.Env=append(os.Environ(),"OUF_COPY_CRASH_CHILD=1","OUF_COPY_CHILD_CONFIG="+cfg);output,e:=cmd.CombinedOutput();var exit *exec.ExitError;if !errors.As(e,&exit)||exit.ExitCode()!=86{t.Fatalf("child exit %v %s",e,output)}
 s,d:=stores(t,src,proxy.URL,ca,destCA,items);r,e:=(&Engine{Source:s,Destination:d}).run(context.Background(),items,scope);if e!=nil||r.Verified!=1||counter.Load()!=1{t.Fatalf("process resume %v %+v puts%d",e,r,counter.Load())}})}}
func TestRealAmbiguous503RespectsRetryAfterAndReconciles(t *testing.T){items,src,_,ca:=makeSingle(t,"ambiguous-503");proxy,destCA,counter:=proxyFor(t,true);s,d:=stores(t,src,proxy.URL,ca,destCA,items);now:=time.Now().UTC();engine:=&Engine{Source:s,Destination:d,Now:func()time.Time{return now}};scope:=filepath.Join(t.TempDir(),"copy-ledger");r,e:=engine.run(context.Background(),items,scope);var transient Transient;if !errors.As(e,&transient)||r.Status!="PAUSED"||counter.Load()!=1{t.Fatalf("ambiguous pause %v %+v puts%d",e,r,counter.Load())};now=now.Add(time.Minute);r,e=engine.run(context.Background(),items,scope);if e!=nil||r.Status!="PAUSED_BEFORE_RETRY_AFTER"||counter.Load()!=1{t.Fatal("early retry")};now=now.Add(time.Hour);r,e=engine.run(context.Background(),items,scope);if e!=nil||r.Verified!=1||r.CopiedThisAttempt!=0||counter.Load()!=1{t.Fatalf("ambiguous reconcile %v %+v puts%d",e,r,counter.Load())}}
func TestRealTagsAndEncodingPreserved(t *testing.T){items,src,dst,ca:=makeSingle(t,"metadata-tags");source:=admin(t,src,ca,sourceKey,sourceSecret);id:=items[0].ID;var buffer bytes.Buffer;z:=gzip.NewWriter(&buffer);z.Write([]byte("synthetic compressed fixture"));z.Close();raw:=buffer.Bytes();_,e:=source.PutObject(context.Background(),&s3.PutObjectInput{Bucket:aws.String(id.Bucket),Key:aws.String(id.Key),Body:bytes.NewReader(raw),Metadata:map[string]string{"ouf-content-hash":hash(raw),"fixture":"retained"},ContentType:aws.String("text/csv"),ContentEncoding:aws.String("gzip"),CacheControl:aws.String("private,max-age=0"),Tagging:aws.String(url.Values{"a&b":[]string{"é%+value"}}.Encode())});if e!=nil{t.Fatal(e)};s,d:=stores(t,src,dst,ca,ca,items);s.SetCredit(func()error{return nil});m,e:=s.Head(context.Background(),id);if e!=nil{t.Fatal(e)};items[0].Meta=m;s,d=stores(t,src,dst,ca,ca,items);r,e:=(&Engine{Source:s,Destination:d}).run(context.Background(),items,filepath.Join(t.TempDir(),"copy"));if e!=nil||r.Verified!=1{t.Fatalf("metadata parity %v %+v",e,r)}}
func TestRealSourceIfMatchAndVersionedDestinationDenials(t *testing.T){items,src,dst,ca:=makeSingle(t,"source-ifmatch");s,d:=stores(t,src,dst,ca,ca,items);s.SetCredit(func()error{return nil});old:=items[0].Meta.ETag;source:=admin(t,src,ca,sourceKey,sourceSecret);source.PutObject(context.Background(),&s3.PutObjectInput{Bucket:aws.String(items[0].ID.Bucket),Key:aws.String(items[0].ID.Key),Body:strings.NewReader("new body")});if _,e:=s.Read(context.Background(),items[0].ID,old);e==nil{t.Fatal("stale source read admitted")}
 destination:=admin(t,dst,ca,destinationKey,destinationSecret);_,e:=destination.PutBucketVersioning(context.Background(),&s3.PutBucketVersioningInput{Bucket:aws.String(items[0].ID.Bucket),VersioningConfiguration:&types.VersioningConfiguration{Status:types.BucketVersioningStatusEnabled}});if e!=nil{t.Fatal(e)};d.SetCredit(func()error{return nil});if _,e=d.Snapshot(context.Background(),[]string{items[0].ID.Bucket});e==nil{t.Fatal("versioned copy accepted without separate engine")}}
