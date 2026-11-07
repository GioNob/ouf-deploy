package main
import("bytes";"context";"encoding/json";"net/http";"os";"os/exec";"path/filepath";"testing";"github.com/aws/aws-sdk-go-v2/aws";"github.com/aws/aws-sdk-go-v2/service/s3")
// Only fixture administration writes objects. The child runs the production collector.
func TestG0DBSeed(t *testing.T){
 root:=os.Getenv("OUF_G0_DB_WORK");if root==""{t.Skip("explicit isolated fixture")};dir:=filepath.Join(root,"private");a,s:=filepath.Join(dir,"access"),filepath.Join(dir,"secret");os.WriteFile(a,[]byte("synthetic-g0-admin"),0600);os.WriteFile(s,[]byte("synthetic-g0-secret-not-production"),0600)
 c:=Config{Endpoint:"https://127.0.0.1:18443",Region:"us-east-1",AccessKeyFile:a,SecretKeyFile:s,CACertificateFile:filepath.Join(root,"tls/public.crt")};sdk,_,e:=client(c);if e!=nil{t.Fatal(e)};options:=sdk.Options();hc:=options.HTTPClient.(*http.Client);hc.Transport=hc.Transport.(*Budget).transport;sdk=s3.New(options)
 for _,entry:=range[][2]string{{"ouf-managed-files","managed-files/11111111-1111-1111-1111-111111111111"},{"ouf-udp","lake/tenant/raw/"+g0Hash([]byte("abc"))}}{if _,e=sdk.CreateBucket(context.Background(),&s3.CreateBucketInput{Bucket:aws.String(entry[0])});e!=nil{t.Fatal(e)};if _,e=sdk.PutObject(context.Background(),&s3.PutObjectInput{Bucket:aws.String(entry[0]),Key:aws.String(entry[1]),Body:bytes.NewReader([]byte("abc")),ContentLength:aws.Int64(3)});e!=nil{t.Fatal(e)}}
 config:=filepath.Join(dir,"bodies.json");os.WriteFile(config,g0JSON(g0Config{Schema:"ouf.storage-g0-collection-input.v1",OperationID:"bodies",InstallationRef:"synthetic-db-integration",Connection:c}),0600)
 out,e:=exec.Command(filepath.Join(root,"scan/inventory"),"g0-collect",config,filepath.Join(dir,"bodies")).CombinedOutput();var report g0Receipt;if e!=nil||json.Unmarshal(out,&report)!=nil||!report.Complete||report.VerifiedBodies!=2||report.VerifiedBytes!=6{t.Fatalf("collector failed %+v %v",report,e)};os.WriteFile(filepath.Join(root,"evidence/body-summary.json"),g0JSON(report),0600)
}
