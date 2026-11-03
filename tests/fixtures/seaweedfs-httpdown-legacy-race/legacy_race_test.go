package httpdown
import("net";"net/http";"testing";"time")
func TestLegacyNegativeShutdownControlRace(t *testing.T){
 for i:=0;i<1000;i++ {
  l,e:=net.Listen("tcp","127.0.0.1:0");if e!=nil {t.Fatal(e)}
  s:=HTTP{StopTimeout:-time.Nanosecond,KillTimeout:-time.Nanosecond}.Serve(&http.Server{},l)
  if e:=s.Stop();e!=nil {t.Fatal(e)}
 }
}
