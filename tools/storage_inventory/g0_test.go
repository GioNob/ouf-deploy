package main

import (
 "bytes"
 "context"
 "encoding/json"
 "io"
 "net/http"
 "net/http/httptest"
 "net/url"
 "os"
 "path/filepath"
 "strings"
 "testing"

 "github.com/aws/aws-sdk-go-v2/aws"
 "github.com/aws/aws-sdk-go-v2/credentials"
 "github.com/aws/aws-sdk-go-v2/service/s3"
)
type g0RoundTripFunc func(*http.Request)(*http.Response,error)
func(f g0RoundTripFunc)RoundTrip(r *http.Request)(*http.Response,error){return f(r)}
func TestG0WriteAheadAndReadOnly(t *testing.T){
 dir:=t.TempDir();calls:=0;g:=&g0Guard{dir:dir,scheme:"https",host:"127.0.0.1:443"}
 g.next=g0RoundTripFunc(func(r *http.Request)(*http.Response,error){calls++;raw,e:=os.ReadFile(filepath.Join(dir,"requests.private.jsonl"));if e!=nil||!bytes.Contains(raw,[]byte(`"sequence":1`)){t.Fatal("request issued before durable reservation")};return &http.Response{StatusCode:200,Body:io.NopCloser(strings.NewReader("x"))},nil})
 for _,target:=range []string{"https://127.0.0.1:443/a","https://other.invalid/a"}{r,_:=http.NewRequest("PUT",target,nil);if _,e:=g.RoundTrip(r);e==nil{t.Fatal("mutation accepted")}}
 r,_:=http.NewRequest("GET","https://other.invalid/a",nil);if _,e:=g.RoundTrip(r);e==nil{t.Fatal("escape accepted")}
 if calls!=0||g.requests!=0{t.Fatal("denied request sent")};r,_=http.NewRequest("GET","https://127.0.0.1:443/a",nil);response,e:=g.RoundTrip(r);if e!=nil{t.Fatal(e)};io.ReadAll(response.Body);response.Body.Close();if calls!=1||g.requests!=1||g.wire!=1{t.Fatal("counters")}
 g.requests=g0MaxRequests;if _,e=g.RoundTrip(r);e==nil||calls!=1{t.Fatal("budget renewed")}
}
func TestG0WireLimit(t *testing.T){g:=&g0Guard{wire:g0MaxWire-1};b:=&g0WireBody{source:io.NopCloser(strings.NewReader("ab")),guard:g,remaining:10};raw,e:=io.ReadAll(b);if string(raw)!="a"||e==nil||g.wire!=g0MaxWire{t.Fatal("wire budget bypass")}}
func TestG0ConditionalBodyFailures(t *testing.T){
 cases:=[]struct{name,etag,body,rangeHeader,hash string;length int;expected string}{
  {"wrong-etag","\"other\"","abc","","",3,"G0_CONDITIONAL_RESPONSE_MISMATCH"},
  {"wrong-size","\"exact\"","abc","","",4,"G0_CONDITIONAL_RESPONSE_MISMATCH"},
  {"partial-response","\"exact\"","abc","bytes 0-2/3","",3,"G0_CONDITIONAL_RESPONSE_MISMATCH"},
  {"truncated-body","\"exact\"","a","","",3,"G0_INCOMPLETE_OR_EXCESS_BODY"},
  {"advertised-hash","\"exact\"","abc","",strings.Repeat("0",64),3,"G0_ADVERTISED_HASH_MISMATCH"},
 }
 for _,c:=range cases{t.Run(c.name,func(t *testing.T){
  called:=0;transport:=g0RoundTripFunc(func(r *http.Request)(*http.Response,error){called++;if r.Method!="GET"||r.Header.Get("If-Match")!="\"exact\""{t.Fatal("missing condition")};h:=http.Header{"Etag":[]string{c.etag},"Content-Length":[]string{fmtInt(c.length)}};if c.rangeHeader!=""{h.Set("Content-Range",c.rangeHeader)};return &http.Response{StatusCode:200,Header:h,Body:io.NopCloser(strings.NewReader(c.body)),ContentLength:int64(c.length),Request:r},nil})
  sdk:=s3.New(s3.Options{Region:"us-east-1",BaseEndpoint:aws.String("https://127.0.0.1:443"),UsePathStyle:true,Credentials:credentials.NewStaticCredentialsProvider("synthetic","synthetic",""),HTTPClient:&http.Client{Transport:transport},Retryer:aws.NopRetryer{}})
  row:=Row{Bucket:"synthetic",Key:"key",Size:3,Metadata:map[string]string{"ouf-content-hash":c.hash}}
  _,e:=g0ReadBody(context.Background(),sdk,row,map[string]any{"etag":"\"exact\""});if e==nil||e.Error()!=c.expected||called!=1{t.Fatalf("wrong denial %v calls=%d",e,called)}
 })}
}
func fmtInt(n int)string{b,_:=json.Marshal(n);return string(b)}
func TestG0FailureConsumesScopeAndRedacts(t *testing.T){
 dir:=t.TempDir();config:=filepath.Join(dir,"config.json");out:=filepath.Join(dir,"one-operation")
 c:=g0Config{Schema:"ouf.storage-g0-collection-input.v1",OperationID:"one-operation",InstallationRef:"synthetic-installation",Connection:Config{Endpoint:"https://127.0.0.1:443",Region:"us-east-1",AccessKeyFile:filepath.Join(dir,"missing-secret"),SecretKeyFile:filepath.Join(dir,"missing-secret")}}
 os.WriteFile(config,g0JSON(c),0600);r,e:=collectG0(config,out);if e==nil||r.Complete{t.Fatal("missing credentials accepted")};if _,e=os.Stat(filepath.Join(out,"summary.json"));e!=nil{t.Fatal("missing partial receipt")}
 r,e=collectG0(config,out);if e==nil||e.Error()!="G0_SCOPE_ALREADY_CONSUMED_OR_UNAVAILABLE"||r.Requests!=0{t.Fatal("scope replay")};raw,_:=os.ReadFile(filepath.Join(out,"summary.json"));if bytes.Contains(raw,[]byte("missing-secret")){t.Fatal("private detail leaked")}
}
func TestG0ConfigSymlinkDenied(t *testing.T){d:=t.TempDir();p:=filepath.Join(d,"config");os.WriteFile(p,[]byte(`{}`),0600);os.Symlink(p,p+"-link");if _,e:=collectG0(p+"-link",filepath.Join(d,"scope"));e==nil{t.Fatal("symlink accepted")}}
func TestG0JournalFailurePreventsNetwork(t *testing.T){dir:=t.TempDir();os.Symlink("/dev/null",filepath.Join(dir,"requests.private.jsonl"));called:=false;g:=&g0Guard{dir:dir,scheme:"https",host:"127.0.0.1",next:g0RoundTripFunc(func(*http.Request)(*http.Response,error){called=true;return nil,nil})};r:=httptest.NewRequest("GET","https://127.0.0.1/a",nil);if _,e:=g.RoundTrip(r);e==nil||called{t.Fatal("unreserved request")}}
func TestG0NoAutomaticRetryOn503(t *testing.T){
 dir:=t.TempDir();a,s:=filepath.Join(dir,"access"),filepath.Join(dir,"secret");os.WriteFile(a,[]byte("synthetic"),0600);os.WriteFile(s,[]byte("synthetic"),0600);calls:=0
 server:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){calls++;w.Header().Set("Retry-After","120");w.WriteHeader(503);io.WriteString(w,`<Error><Code>SlowDown</Code></Error>`)}));defer server.Close();u,_:=url.Parse(server.URL);_ = u
 sdk,g,e:=g0Client(Config{Endpoint:server.URL,AllowLoopbackHTTP:true,Region:"us-east-1",AccessKeyFile:a,SecretKeyFile:s},dir);if e!=nil{t.Fatal(e)}
 _,e=sdk.ListBuckets(context.Background(),&s3.ListBucketsInput{});if e==nil||calls!=1||g.requests!=1{t.Fatal("automatic retry or false success")}
}
