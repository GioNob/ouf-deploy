package main

import (
 "bytes"
 "context"
 "encoding/json"
 "net/http"
 "os"
 "os/exec"
 "path/filepath"
 "strings"
 "testing"
 "time"

 "github.com/aws/aws-sdk-go-v2/aws"
 "github.com/aws/aws-sdk-go-v2/service/s3"
 "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

func TestG0NativeMinio(t *testing.T){
 endpoint:=os.Getenv("OUF_G0_NATIVE_ENDPOINT");if endpoint==""{t.Skip("explicit disposable native fixture only")}
 root:=os.Getenv("OUF_G0_NATIVE_WORK");binary:=os.Getenv("OUF_G0_BINARY");if root==""||binary==""{t.Fatal("native bindings")}
 dir:=filepath.Join(root,"native-private");if e:=os.Mkdir(dir,0700);e!=nil{t.Fatal(e)}
 a,s:=filepath.Join(dir,"access"),filepath.Join(dir,"secret");os.WriteFile(a,[]byte("synthetic-g0-admin"),0600);os.WriteFile(s,[]byte("synthetic-g0-secret-not-production"),0600)
 c:=Config{Endpoint:endpoint,Region:"us-east-1",AccessKeyFile:a,SecretKeyFile:s,CACertificateFile:os.Getenv("OUF_G0_CA")}
 sdk,_,e:=client(c);if e!=nil{t.Fatal(e)}
 // Fixture administration is separate from the collector's read-only transport.
 options:=sdk.Options();httpClient:=options.HTTPClient.(*http.Client);old:=httpClient.Transport.(*Budget);httpClient.Transport=old.transport;options.HTTPClient=httpClient;sdk=s3.New(options)
 ctx:=context.Background();buckets:=[]string{"g0-first","g0-second"}
 for _,b:=range buckets{if _,e=sdk.CreateBucket(ctx,&s3.CreateBucketInput{Bucket:aws.String(b)});e!=nil{t.Fatal(e)}}
 expected:=map[string]string{};var total int64
 for i:=0;i<120;i++{size:=1000;if i==119{size=84743};body:=bytes.Repeat([]byte{byte(i)},size);key:=fmtInt(i);if i==0{key="private/città λ ?#%"};bucket:=buckets[i/60];metadata:=map[string]string{};if i<110{metadata["ouf-content-hash"]="sha256:"+g0Hash(body)}
  _,e=sdk.PutObject(ctx,&s3.PutObjectInput{Bucket:aws.String(bucket),Key:aws.String(key),Body:bytes.NewReader(body),ContentLength:aws.Int64(int64(size)),ContentType:aws.String("application/octet-stream"),Metadata:metadata});if e!=nil{t.Fatal(e)};expected[bucket+"\x00"+key]=g0Hash(body);total+=int64(size)
 }
 run:=func(op string)(g0Receipt,string,error){cpath:=filepath.Join(dir,op+".json");input:=g0Config{Schema:"ouf.storage-g0-collection-input.v1",OperationID:op,InstallationRef:"synthetic-installation",Connection:c};os.WriteFile(cpath,g0JSON(input),0600);out:=filepath.Join(dir,op);cmd:=exec.Command(binary,"g0-collect",cpath,out);raw,e:=cmd.CombinedOutput();var report g0Receipt;if json.Unmarshal(bytes.TrimSpace(raw),&report)!=nil{t.Fatalf("not a redacted receipt: %s",raw)};return report,out,e}
 report,out,e:=run("success-once");if e!=nil||!report.Complete||report.VerifiedBodies!=120||report.VerifiedBytes!=203743||report.TargetWrites!=0||report.PointInTimeSnapshotProven||report.RuntimeAuthorityIssued{t.Fatalf("collection: %+v %v",report,e)}
 raw,e:=os.ReadFile(filepath.Join(out,"collection.private.json"));if e!=nil{t.Fatal(e)};var collection struct{Objects []g0Proof `json:"objects"`};if json.Unmarshal(raw,&collection)!=nil||len(collection.Objects)!=120{t.Fatal("proof count")};for _,proof:=range collection.Objects{if expected[proof.Bucket+"\x00"+proof.Key]!=proof.SHA256||proof.ETag==""{t.Fatal("body proof")}}
 repeat,_,e:=run("success-once");if e==nil||repeat.Requests!=0{t.Fatal("replay accepted")}
 crashPath:=filepath.Join(dir,"crash-once.json");crashOut:=filepath.Join(dir,"crash-once");os.WriteFile(crashPath,g0JSON(g0Config{Schema:"ouf.storage-g0-collection-input.v1",OperationID:"crash-once",InstallationRef:"synthetic-installation",Connection:c}),0600)
 child:=exec.Command(binary,"g0-collect",crashPath,crashOut);if e=child.Start();e!=nil{t.Fatal(e)}
 deadline:=time.Now().Add(10*time.Second);reserved:=false
 for time.Now().Before(deadline){if st,x:=os.Stat(filepath.Join(crashOut,"requests.private.jsonl"));x==nil&&st.Size()>0{reserved=true;break};time.Sleep(5*time.Millisecond)}
 child.Process.Kill();child.Wait();if !reserved{t.Fatal("no request reservation before crash")};crashed,_,e:=run("crash-once");if e==nil||crashed.Requests!=0{t.Fatal("crash reset scope")}
 // Metadata hash disagreement is held, without source mutation by the collector.
 _,e=sdk.PutObject(ctx,&s3.PutObjectInput{Bucket:aws.String(buckets[0]),Key:aws.String("mismatch"),Body:strings.NewReader("abc"),Metadata:map[string]string{"ouf-content-hash":"sha256:"+strings.Repeat("0",64)}});if e!=nil{t.Fatal(e)}
 denied,deniedDir,e:=run("hash-mismatch");if e==nil||denied.Complete||denied.Reason!="G0_ADVERTISED_HASH_MISMATCH"{t.Fatalf("bad hash accepted: %+v",denied)};if _,e=os.Stat(filepath.Join(deniedDir,"bodies.private.jsonl"));e!=nil{t.Fatal("missing partial evidence")}
 sdk.DeleteObject(ctx,&s3.DeleteObjectInput{Bucket:aws.String(buckets[0]),Key:aws.String("mismatch")})
 _,e=sdk.PutBucketVersioning(ctx,&s3.PutBucketVersioningInput{Bucket:aws.String(buckets[0]),VersioningConfiguration:&types.VersioningConfiguration{Status:types.BucketVersioningStatusEnabled}});if e!=nil{t.Fatal(e)}
 versioned,_,e:=run("versioned-held");if e==nil||versioned.Complete||versioned.BodiesAttempted!=0||versioned.Reason!="G0_VERSION_OR_MULTIPART_PROFILE_HELD"{t.Fatalf("versioned profile accepted: %+v",versioned)}
 evidence:=map[string]any{"schema":"ouf.storage-g0-native-minio.v1","status":"PASS_SYNTHETIC_NOT_TARGET_ACCEPTANCE","objects":120,"bytes":total,"missingAdvertisedHash":10,"collection":report,"replayDenied":true,"realProcessCrashScopeRemainsConsumed":true,"hashMismatchHeld":true,"versionedProfileHeldBeforeBodies":true,"runtimeAuthorityIssued":false,"targetOperations":0}
 if e=os.WriteFile(filepath.Join(root,"evidence","native-minio.json"),g0JSON(evidence),0600);e!=nil{t.Fatal(e)}
}
