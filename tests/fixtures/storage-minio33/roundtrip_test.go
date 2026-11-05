package storagecopy

import (
 "bytes"
 "context"
 "fmt"
 "os"
 "path/filepath"
 "testing"
 "time"
 "github.com/aws/aws-sdk-go-v2/aws"
 "github.com/aws/aws-sdk-go-v2/service/s3"
)

// Staged alongside the unchanged copy core; no operational entry point.
func TestMinio33RoundTrip(t *testing.T) {
 start:=time.Now()
 TestRealCopy120FromExactInventoryCompilerWire(t)
 forwardSeconds:=time.Since(start).Seconds()
 src,dst,ca:=lab(t)
 returned:=os.Getenv("OUF_COPY_RETURN")
 if returned==""||returned==src||returned==dst {t.Fatal("independent empty return fixture required")}
 retAdmin:=admin(t,returned,ca,sourceKey,sourceSecret)
 buckets:=[]string{"lab-copy-a","lab-copy-b"}
 for _,bucket:=range buckets {create(t,retAdmin,bucket)}
 items:=[]Item{}
 for i:=0;i<120;i++ {key:=fmt.Sprintf("object-%03d",i);if i==0 {key="private/è%2F?+#"};items=append(items,Item{ID:ID{buckets[i/60],key}})}
 original,target:=stores(t,src,dst,ca,ca,items)
 original.SetCredit(func()error{return nil});target.SetCredit(func()error{return nil})
 for i:=range items {meta,err:=target.Head(context.Background(),items[i].ID);if err!=nil {t.Fatal(err)};items[i].Meta=meta}
 reverseSource,err:=newLoopbackS3(dst,"us-east-1",destinationKey,destinationSecret,ca,items,false);if err!=nil {t.Fatal(err)}
 reverseDest,err:=newLoopbackS3(returned,"us-east-1",sourceKey,sourceSecret,ca,items,true);if err!=nil {t.Fatal(err)}
 reverseDest.SetCredit(func()error{return nil})
 before,err:=reverseDest.Snapshot(context.Background(),buckets);if err!=nil||len(before)!=0 {t.Fatal("return store must be empty",err)}
 root:=t.TempDir();start=time.Now()
 report,err:=(&Engine{Source:reverseSource,Destination:reverseDest}).run(context.Background(),items,filepath.Join(root,"reverse-ledger"))
 if err!=nil||report.Verified!=120||report.CopiedThisAttempt!=120 {t.Fatalf("reverse copy: %v %+v",err,report)}
 reverseSeconds:=time.Since(start).Seconds()
 reverseDest.SetCredit(func()error{return nil})
 rows:=[]map[string]any{};total:=0
 for i,item:=range items {
  size:=1000;if i==119 {size=84743};expected:=bytes.Repeat([]byte{byte(i)},size)
  hashes:=[]string{};metas:=[]Meta{}
  for _,store:=range []*s3Store{original,target,reverseDest} {
   meta,e:=store.Head(context.Background(),item.ID);if e!=nil {t.Fatal(e)}
   body,e:=store.Read(context.Background(),item.ID,meta.ETag);if e!=nil||!bytes.Equal(body,expected) {t.Fatal("independent conditional full-body parity",e)}
   hashes=append(hashes,hash(body));metas=append(metas,meta)
  }
  if !sameRepresentation(metas[0],metas[1])||!sameRepresentation(metas[0],metas[2]) {t.Fatal("three-provider representation mismatch")}
  rows=append(rows,map[string]any{"id":item.ID,"bytes":size,"sha256ByProvider":hashes,"representationSha256":metaHash(metas[0])});total+=size
 }
 if total!=203743 {t.Fatal("fixture bytes",total)}
 for _,store:=range []*s3Store{original,target,reverseDest} {snapshot,e:=store.Snapshot(context.Background(),buckets);if e!=nil||len(snapshot)!=120 {t.Fatal("exact final namespace",e)}}
 out:=os.Getenv("OUF_COPY_RECEIPT");if out=="" {t.Fatal("persistent receipt required")}
 receipt:=map[string]any{"schema":"ouf.minio-oci33-roundtrip.v1","status":"PASS_SYNTHETIC_NOT_ACCEPTANCE","objects":120,"bytes":total,"missingAdvertisedHashes":10,"independentConditionalBodyReads":360,"forwardIncludesInventoryAndCompilerSeconds":forwardSeconds,"reverseCopySeconds":reverseSeconds,"returnInitiallyEmpty":true,"sourceMutationsAfterSeed":0,"reverseReport":report,"objectsParity":rows,"targetOperations":0,"releaseAdmitted":false}
 if e:=os.WriteFile(out,append(encode(receipt),'\n'),0600);e!=nil {t.Fatal(e)}
}

// New acknowledged writes are exported into a separate, initially empty store.
// This is an object-store return proof, not a DB/application rollback decision.
func TestMinio33PostWriteReturn(t *testing.T) {
 src,dst,ca:=lab(t);ret:=os.Getenv("OUF_COPY_RETURN");ctx:=context.Background()
 source:=admin(t,src,ca,sourceKey,sourceSecret);dest:=admin(t,dst,ca,destinationKey,destinationSecret);returned:=admin(t,ret,ca,sourceKey,sourceSecret)
 bucket:="lab-post-write-return";for _,client:=range []*s3.Client{source,dest,returned} {create(t,client,bucket)}
 put:=func(client *s3.Client,key string,body []byte,marker string) {
  _,e:=client.PutObject(ctx,&s3.PutObjectInput{Bucket:aws.String(bucket),Key:aws.String(key),Body:bytes.NewReader(body),ContentType:aws.String("application/octet-stream"),Metadata:map[string]string{"ouf-content-hash":"sha256:"+hash(body),"fixture":marker}});if e!=nil {t.Fatal(e)}
 }
 initial:=[]string{"body-change","metadata-change","deleted"};items:=[]Item{}
 for _,key:=range initial {put(source,key,[]byte("before:"+key),"before");items=append(items,Item{ID:ID{bucket,key}})}
 original,target:=stores(t,src,dst,ca,ca,items);original.SetCredit(func()error{return nil})
 for i:=range items {m,e:=original.Head(ctx,items[i].ID);if e!=nil {t.Fatal(e)};items[i].Meta=m}
 root:=t.TempDir();report,e:=(&Engine{Source:original,Destination:target}).run(ctx,items,filepath.Join(root,"forward"));if e!=nil||report.Verified!=3 {t.Fatal("initial copy",e)}
 put(dest,"body-change",[]byte("acknowledged replacement"),"after")
 put(dest,"metadata-change",[]byte("before:metadata-change"),"after")
 if _,e:=dest.DeleteObject(ctx,&s3.DeleteObjectInput{Bucket:aws.String(bucket),Key:aws.String("deleted")});e!=nil {t.Fatal(e)}
 put(dest,"added",[]byte("acknowledged new object"),"after")
 current:=[]Item{{ID:ID{bucket,"body-change"}},{ID:ID{bucket,"metadata-change"}},{ID:ID{bucket,"added"}}}
 read,e:=newLoopbackS3(dst,"us-east-1",destinationKey,destinationSecret,ca,current,false);if e!=nil {t.Fatal(e)};read.SetCredit(func()error{return nil})
 for i:=range current {m,e:=read.Head(ctx,current[i].ID);if e!=nil {t.Fatal(e)};current[i].Meta=m}
 write,e:=newLoopbackS3(ret,"us-east-1",sourceKey,sourceSecret,ca,current,true);if e!=nil {t.Fatal(e)};write.SetCredit(func()error{return nil})
 snapshot,e:=write.Snapshot(ctx,[]string{bucket});if e!=nil||len(snapshot)!=0 {t.Fatal("empty return required",e)}
 report,e=(&Engine{Source:read,Destination:write}).run(ctx,current,filepath.Join(root,"return"));if e!=nil||report.Verified!=3||report.CopiedThisAttempt!=3 {t.Fatal("post-write return",e)}
 read.SetCredit(func()error{return nil});write.SetCredit(func()error{return nil});original.SetCredit(func()error{return nil})
 expected:=map[string][]byte{"body-change":[]byte("acknowledged replacement"),"metadata-change":[]byte("before:metadata-change"),"added":[]byte("acknowledged new object")}
 for _,item:=range current {
  for _,store:=range []*s3Store{read,write} {m,e:=store.Head(ctx,item.ID);if e!=nil||!sameRepresentation(m,item.Meta) {t.Fatal("post-write metadata",e)};b,e:=store.Read(ctx,item.ID,m.ETag);if e!=nil||!bytes.Equal(b,expected[item.ID.Key]) {t.Fatal("post-write body",e)}}
 }
 for _,store:=range []*s3Store{read,write} {snapshot,e:=store.Snapshot(ctx,[]string{bucket});if e!=nil||len(snapshot)!=3 {t.Fatal("post-write namespace",e)};if _,exists:=snapshot[ID{bucket,"deleted"}];exists {t.Fatal("deleted object resurrected")}}
 for _,item:=range items {m,e:=original.Head(ctx,item.ID);if e!=nil||!sameRepresentation(m,item.Meta) {t.Fatal("original source changed",e)};b,e:=original.Read(ctx,item.ID,m.ETag);if e!=nil||!bytes.Equal(b,[]byte("before:"+item.ID.Key)) {t.Fatal("original body changed",e)}}
 receipt:=map[string]any{"status":"PASS_SYNTHETIC_NOT_ACCEPTANCE","acknowledgedMutations":[]string{"REPLACE_BODY","REPLACE_METADATA","DELETE","ADD"},"returnInitiallyEmpty":true,"returnedCurrentObjects":3,"deletedObjectAbsent":true,"sourceOriginalsUnchanged":true,"dbReferencesReconciled":false,"runtimeRollbackAdmitted":false}
 if e:=os.WriteFile(filepath.Join(filepath.Dir(os.Getenv("OUF_COPY_RECEIPT")),"post-write-return.json"),append(encode(receipt),'\n'),0644);e!=nil {t.Fatal(e)}
}
