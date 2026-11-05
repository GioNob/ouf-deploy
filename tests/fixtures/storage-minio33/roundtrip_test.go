package storagecopy

import (
 "bytes"
 "context"
 "fmt"
 "os"
 "path/filepath"
 "testing"
 "time"
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
