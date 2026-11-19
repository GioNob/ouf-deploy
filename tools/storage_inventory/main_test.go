package main
import("net/http";"net/http/httptest";"os";"path/filepath";"testing")
func TestEndpointAdmission(t *testing.T){for _,raw:=range []string{"http://example.com","http://169.254.169.254","https://user:pass@host","https://host/path","https://host?query=1"}{if endpoint(raw,true)==nil{t.Fatalf("accepted forbidden endpoint")}};if endpoint("http://127.0.0.1:18333",false)==nil||endpoint("http://127.0.0.1:18333",true)!=nil||endpoint("https://host",false)!=nil{t.Fatal("endpoint policy")}}
func TestOnlyReadMethodsAllowed(t *testing.T){b:=&Budget{transport:http.DefaultTransport};r:=httptest.NewRequest("PUT","http://127.0.0.1:1/",nil);if _,e:=b.RoundTrip(r);e==nil{t.Fatal("write accepted")};if b.requests!=0{t.Fatal("write consumed read budget")}}
func TestSecretSymlinksAndPublicModesDenied(t *testing.T){d:=t.TempDir();p:=filepath.Join(d,"secret");if e:=os.WriteFile(p,[]byte("synthetic"),0600);e!=nil{t.Fatal(e)};if _,e:=secret(p);e!=nil{t.Fatal(e)};l:=filepath.Join(d,"link");os.Symlink(p,l);if _,e:=secret(l);e==nil{t.Fatal("symlink accepted")};os.Chmod(p,0644);if _,e:=secret(p);e==nil{t.Fatal("public credential accepted")}}

func TestReadBudgetExhaustion(t *testing.T){b:=&Budget{requests:10000,transport:http.DefaultTransport};r:=httptest.NewRequest("GET","http://127.0.0.1:1/",nil);if _,e:=b.RoundTrip(r);e==nil{t.Fatal("budget bypass")};if b.requests!=10000{t.Fatal("counter changed")}}

func TestUnsealedDescriptorAndMixedBindingsDenied(t *testing.T){p:=filepath.Join(t.TempDir(),"secret");os.WriteFile(p,[]byte("synthetic"),0600);f,e:=os.Open(p);if e!=nil{t.Fatal(e)};defer f.Close();if _,e:=sealedSecret(int(f.Fd()));e==nil{t.Fatal("unsealed file accepted")};fd:=int(f.Fd());if _,_,e:=credentialPair(Config{AccessKeyFD:&fd,SecretKeyFile:p});e==nil{t.Fatal("mixed bindings accepted")}}

func TestInventorySummaryRejectsDuplicateAndCountsConflicts(t *testing.T){rows:=[]Row{{Bucket:"b",Key:"a",Size:2},{Bucket:"b",Key:"a/b",Size:3}};s,e:=summary(rows,nil);if e!=nil||s["fileDirectoryCollisions"]!=1||s["namespaceGate"]!="HELD"||s["bytesAcrossVersions"]!=int64(5){t.Fatal("summary")};if _,e:=summary(append(rows,rows[0]),nil);e==nil{t.Fatal("duplicate identity accepted")}}

func TestRequestsCannotEscapeConfiguredEndpoint(t *testing.T){b:=&Budget{host:"127.0.0.1:9000",scheme:"http",transport:http.DefaultTransport};r:=httptest.NewRequest("GET","https://other.invalid/",nil);if _,e:=b.RoundTrip(r);e==nil||b.requests!=0{t.Fatal("endpoint escape")}}
