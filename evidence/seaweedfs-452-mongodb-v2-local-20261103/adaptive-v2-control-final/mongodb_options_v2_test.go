package mongodb

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"go.mongodb.org/mongo-driver/v2/bson"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/seaweedfs/seaweedfs/weed/filer"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/writeconcern"
)

func TestMongoV2OptionsPreserveAuthTopologyAndExplicitOverrides(t *testing.T) {
	uri := "mongodb://uriuser:uripass@127.0.0.1:27017/db?authSource=authdb&authMechanism=SCRAM-SHA-256&replicaSet=rs-fixture&maxPoolSize=9&readPreference=secondaryPreferred&retryWrites=true&retryReads=false&timeoutMS=1200&w=majority&compressors=zstd"
	opts, err := mongodbClientOptions(uri, 3, false, "", "", "", "override-user", "override-pass", false)
	if err != nil {
		t.Fatal(err)
	}
	if opts.Auth == nil || opts.Auth.Username != "override-user" || opts.Auth.Password != "override-pass" || !opts.Auth.PasswordSet || opts.Auth.AuthSource != "authdb" || opts.Auth.AuthMechanism != "SCRAM-SHA-256" {
		t.Fatal("URI authentication fields or explicit credentials changed")
	}
	if opts.MaxPoolSize == nil || *opts.MaxPoolSize != 3 || opts.ReplicaSet == nil || *opts.ReplicaSet != "rs-fixture" || opts.Timeout == nil || *opts.Timeout != 1200*time.Millisecond || opts.WriteConcern.W != "majority" || opts.ReadPreference.Mode().String() != "secondaryPreferred" || len(opts.Compressors) != 1 || opts.Compressors[0] != "zstd" {
		t.Fatal("URI topology/timeout/write/read/compression settings changed")
	}
	if opts.RetryWrites == nil || !*opts.RetryWrites || opts.RetryReads == nil || *opts.RetryReads {
		t.Fatal("explicit retry configuration changed")
	}
	inherited, err := mongodbClientOptions(uri, 0, false, "", "", "", "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if inherited.Auth.Username != "uriuser" || inherited.Auth.Password != "uripass" || *inherited.MaxPoolSize != 9 {
		t.Fatal("URI settings lost without override")
	}
	defaults, err := mongodbClientOptions("mongodb://127.0.0.1:27017", 0, false, "", "", "", "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if defaults.MaxAdaptiveRetries == nil || *defaults.MaxAdaptiveRetries != 0 {
		t.Fatal("new adaptive retry default not explicitly disabled")
	}
	if defaults.RetryWrites != nil || defaults.RetryReads != nil {
		t.Fatal("driver retry defaults silently changed")
	}
}
func TestMongoV2RejectsUnsafeOrLostSettingsBeforeConnection(t *testing.T) {
	for _, query := range []string{"w=0", "socketTimeoutMS=10", "wTimeoutMS=20", "SOCKETTIMEOUTMS=10", "maxAdaptiveRetries=1", "enableOverloadRetargeting=true"} {
		t.Run(query, func(t *testing.T) {
			f := newMongoWireFixture(t)
			uri := f.uri() + "&" + query
			store := &MongodbStore{database: "fixture", collectionName: "filemeta"}
			err := store.connection(uri, 0, false, "", "", "", "", "", false)
			if err == nil {
				store.Shutdown()
				t.Fatal("unsafe/removed option accepted")
			}
			if store.connect != nil {
				t.Fatal("failed options published client")
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if len(f.connections) != 0 || len(f.commands) != 0 {
				t.Fatal("invalid configuration reached server")
			}
		})
	}
	for _, uri := range []string{"not-a-mongodb-uri", "mongodb://127.0.0.1/?maxPoolSize=garbage"} {
		if _, err := mongodbClientOptions(uri, 0, false, "", "", "", "", "", false); err == nil {
			t.Fatal("invalid URI accepted")
		}
	}
}
func mongoTLSFixture(t *testing.T) (string, string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	return cert, cert, keyFile
}
func TestMongoV2TLSConfigurationAndFailures(t *testing.T) {
	ca, cert, key := mongoTLSFixture(t)
	opts, err := mongodbClientOptions("mongodb://127.0.0.1", 0, true, ca, cert, key, "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if opts.TLSConfig == nil || opts.TLSConfig.InsecureSkipVerify || len(opts.TLSConfig.Certificates) != 1 || opts.TLSConfig.RootCAs == nil {
		t.Fatal("TLS client configuration not preserved")
	}
	insecure, err := mongodbClientOptions("mongodb://127.0.0.1", 0, true, ca, cert, key, "", "", true)
	if err != nil || !insecure.TLSConfig.InsecureSkipVerify {
		t.Fatal("explicit historical insecure option changed")
	}
	if _, err := mongodbClientOptions("mongodb://127.0.0.1", 0, true, ca, cert, "missing-key", "", "", false); err == nil {
		t.Fatal("missing client key accepted")
	}
	invalidCA := filepath.Join(t.TempDir(), "bad-ca")
	if err := os.WriteFile(invalidCA, []byte("not a certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := mongodbClientOptions("mongodb://127.0.0.1", 0, true, invalidCA, cert, key, "", "", false); err == nil {
		t.Fatal("invalid CA accepted")
	}
}
func TestMongoV2UnacknowledgedResultsNeverSucceed(t *testing.T) {
	operations := map[string]func(*MongodbStore) error{"entry": func(s *MongodbStore) error { return s.UpdateEntry(context.Background(), &filer.Entry{FullPath: "/a"}) }, "kv-put": func(s *MongodbStore) error {
		return s.KvPut(context.Background(), []byte("fixture-key"), []byte("value"))
	}, "entry-delete": func(s *MongodbStore) error { return s.DeleteEntry(context.Background(), "/a") }, "folder-delete": func(s *MongodbStore) error { return s.DeleteFolderChildren(context.Background(), "/a") }, "kv-delete": func(s *MongodbStore) error { return s.KvDelete(context.Background(), []byte("fixture-key")) }}
	for name, operation := range operations {
		t.Run(name, func(t *testing.T) {
			f := newMongoWireFixture(t, mongoOK())
			opts := options.Client().ApplyURI(f.uri()).SetWriteConcern(writeconcern.Unacknowledged())
			client, err := mongo.Connect(opts)
			if err != nil {
				t.Fatal(err)
			}
			s := &MongodbStore{connect: client, database: "fixture", collectionName: "filemeta"}
			t.Cleanup(s.Shutdown)
			if err := operation(s); err == nil || !strings.Contains(err.Error(), "unacknowledged") {
				t.Fatalf("unacknowledged operation returned %v", err)
			}
		})
	}
}

func TestMongoV2AuthenticationAndTLSFailuresDoNotPublishClient(t *testing.T) {
	t.Run("SCRAM-denial", func(t *testing.T) {
		f := newMongoWireFixture(t, mongoError(18))
		s := &MongodbStore{database: "fixture", collectionName: "filemeta"}
		err := s.connection(strings.Replace(f.uri(), "mongodb://", "mongodb://fixture-user:fixture-password@", 1)+"&authMechanism=SCRAM-SHA-256", 0, false, "", "", "", "fixture-user", "fixture-password", false)
		if err == nil || s.connect != nil {
			if s.connect != nil {
				s.Shutdown()
			}
			t.Fatal("authentication failure accepted")
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		sawAuth := false
		for _, command := range f.commands {
			if len(command) > 0 && strings.EqualFold(command[0].Key, "saslStart") {
				sawAuth = true
			}
			if len(command) > 0 && strings.EqualFold(command[0].Key, "createIndexes") {
				t.Fatal("authentication denial reached DDL")
			}
		}
		if !sawAuth {
			t.Fatal("fixture did not observe real driver SCRAM request")
		}
	})
	t.Run("TLS-no-plaintext-fallback", func(t *testing.T) {
		f := newMongoWireFixture(t)
		ca, cert, key := mongoTLSFixture(t)
		s := &MongodbStore{database: "fixture", collectionName: "filemeta"}
		err := s.connection(f.uri(), 0, true, ca, cert, key, "", "", false)
		if err == nil || s.connect != nil {
			if s.connect != nil {
				s.Shutdown()
			}
			t.Fatal("TLS failure accepted")
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if len(f.commands) != 0 {
			t.Fatal("TLS failure fell back to plaintext commands")
		}
	})
}

func TestMongoV2RejectsServerBelowMinimumBeforeIndex(t *testing.T) {
	f := newMongoWireFixtureVersion(t, 8)
	store := &MongodbStore{database: "fixture", collectionName: "filemeta"}
	err := store.connection(f.uri(), 0, false, "", "", "", "", "", false)
	if err == nil || store.connect != nil {
		if store.connect != nil {
			store.Shutdown()
		}
		t.Fatal("pre-4.4 wire version accepted")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.commands) != 0 {
		t.Fatal("unsupported server received DDL")
	}
}

func TestMongoV2AdaptiveRetriesRemainDisabledInProfile(t *testing.T) {
	overload := mongoError(16500)
	overload = append(overload, bson.E{Key: "errorLabels", Value: bson.A{"RetryableError", "SystemOverloadedError"}})
	f := newMongoWireFixture(t, mongoOK(), overload, mongoOK())
	uri := strings.Replace(f.uri(), "&retryReads=false&retryWrites=false", "", 1)
	s := &MongodbStore{database: "fixture", collectionName: "filemeta"}
	if err := s.connection(uri, 0, false, "", "", "", "", "", false); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Shutdown)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := s.KvPut(ctx, []byte("fixture-key"), []byte("value"))
	var commandError mongo.CommandError
	if !errors.As(err, &commandError) || !commandError.HasErrorLabel("SystemOverloadedError") {
		t.Fatalf("overload was hidden or retried: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	writes := 0
	for _, command := range f.commands {
		if len(command) > 0 && command[0].Key == "update" {
			writes++
		}
	}
	if writes != 1 {
		t.Fatalf("new adaptive retries changed the v1 profile: writes=%d", writes)
	}
}
