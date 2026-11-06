package main
import("bytes";"context";"net/http";"os";"path/filepath";"testing";"github.com/aws/aws-sdk-go-v2/aws";"github.com/aws/aws-sdk-go-v2/service/s3")
// Disposable fixture administration only; does not invoke/repeat the collector.
func TestG0NetworkSeed(t *testing.T){
 root:=os.Getenv("OUF_G0_NETWORK_WORK");if root==""{t.Skip("explicit isolated fixture")}
 c:=Config{Endpoint:"http://127.0.0.1:9000",Region:"us-east-1",AccessKeyFile:filepath.Join(root,"inputs/access"),SecretKeyFile:filepath.Join(root,"inputs/secret"),AllowLoopbackHTTP:true}
 sdk,_,e:=client(c);if e!=nil{t.Fatal(e)};o:=sdk.Options();hc:=o.HTTPClient.(*http.Client);hc.Transport=hc.Transport.(*Budget).transport;sdk=s3.New(o)
 for _,entry:=range[][2]string{{"ouf-managed-files","managed-files/11111111-1111-1111-1111-111111111111"},{"ouf-udp","lake/tenant/raw/"+g0Hash([]byte("abc"))}}{
  if _,e=sdk.CreateBucket(context.Background(),&s3.CreateBucketInput{Bucket:aws.String(entry[0])});e!=nil{t.Fatal(e)}
  if _,e=sdk.PutObject(context.Background(),&s3.PutObjectInput{Bucket:aws.String(entry[0]),Key:aws.String(entry[1]),Body:bytes.NewReader([]byte("abc")),ContentLength:aws.Int64(3)});e!=nil{t.Fatal(e)}
 }
}
