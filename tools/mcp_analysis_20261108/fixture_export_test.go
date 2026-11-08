package reprocessing

import (
 "errors"
 "os"
 "path/filepath"
 "testing"
 "time"
)

// CI only: generated keys and signed authority never leave the disposable job.
func TestExportExpiredRolloutFixture(t *testing.T) {
 root := os.Getenv("OUF_ROLLOUT_FIXTURE")
 if root == "" { t.Fatal("explicit disposable fixture directory required") }
 profile, policy, envelope, pin, old := fixture(t, func(p *Permit) {
  p.IssuedAt -= 1200; p.ExpiresAt -= 1200; p.OwnerReceiptAbsentAt -= 1200
 })
 v, err := VerifyDeployment(profile, policy, envelope, pin, Hash([]byte("new-manifest")), time.Now())
 if v == nil || !errors.Is(err, ErrExpired) || v.Value().ManifestChecksum != old || !errors.Is(v.CheckTime(time.Now(), 0), ErrExpired) {
  t.Fatal("expired fixture has not remained blocked")
 }
 for name, raw := range map[string][]byte{"profile.json":profile,"policy.json":policy,"permit.json":envelope,"profile.sha256":[]byte(pin)} {
  if err := os.WriteFile(filepath.Join(root,name),raw,0600); err != nil { t.Fatal(err) }
 }
}
