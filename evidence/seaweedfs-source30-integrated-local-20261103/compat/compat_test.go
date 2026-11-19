package compat

import (
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	old "github.com/hashicorp/raft-boltdb/v2"
	current "github.com/seaweedfs/seaweedfs/weed/util/raftstore"
	"go.etcd.io/bbolt"
)

type store interface {
	raft.LogStore
	raft.StableStore
	Close() error
	Sync() error
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func fileBytes(t *testing.T, p string) []byte {
	t.Helper()
	b, e := os.ReadFile(p)
	must(t, e)
	return b
}

func expectedLogs() []*raft.Log {
	return []*raft.Log{
		{Index: 2, Term: 4, Type: raft.LogCommand, Data: []byte("original\x00\xff"), Extensions: []byte("ext"), AppendedAt: time.Date(2026, 11, 3, 12, 1, 2, 123000000, time.UTC)},
		{Index: 3, Term: 4, Type: raft.LogConfiguration, Data: []byte("configuration")},
		{Index: 7, Term: 5, Type: raft.LogNoop},
	}
}

func seed(t *testing.T, s store) {
	t.Helper()
	must(t, s.StoreLogs(expectedLogs()))
	must(t, s.SetUint64([]byte("CurrentTerm"), 5))
	must(t, s.SetUint64([]byte("LastVoteTerm"), 5))
	must(t, s.Set([]byte("LastVoteCand"), []byte("peer-1\x00")))
	must(t, s.Sync())
	must(t, s.Close())
}

func assertSeed(t *testing.T, s store) {
	t.Helper()
	first, e := s.FirstIndex()
	must(t, e)
	if first != 2 {
		t.Fatalf("first %d", first)
	}
	last, e := s.LastIndex()
	must(t, e)
	if last != 7 {
		t.Fatalf("last %d", last)
	}
	for _, expected := range expectedLogs() {
		var actual raft.Log
		must(t, s.GetLog(expected.Index, &actual))
		if !reflect.DeepEqual(*expected, actual) {
			t.Fatalf("log mismatch: %#v != %#v", *expected, actual)
		}
	}
	for _, key := range []string{"CurrentTerm", "LastVoteTerm"} {
		value, e := s.GetUint64([]byte(key))
		must(t, e)
		if value != 5 {
			t.Fatalf("%s=%d", key, value)
		}
	}
	value, e := s.Get([]byte("LastVoteCand"))
	must(t, e)
	if string(value) != "peer-1\x00" {
		t.Fatal("vote candidate mismatch")
	}
	var absent raft.Log
	if !errors.Is(s.GetLog(6, &absent), raft.ErrLogNotFound) {
		t.Fatal("hole must remain missing")
	}
}

func TestOldV2FileReadAndWriteWithLocalThenReopenOldV2(t *testing.T) {
	root := t.TempDir()
	original := filepath.Join(root, "original.db")
	copyPath := filepath.Join(root, "restored-copy.db")
	prior, e := old.NewBoltStore(original)
	must(t, e)
	seed(t, prior)
	originalBytes := fileBytes(t, original)
	must(t, os.WriteFile(copyPath, originalBytes, 0600))
	local, e := current.NewBoltStore(copyPath)
	must(t, e)
	assertSeed(t, local)
	// Raft may overwrite an uncommitted suffix; preserve the upstream store
	// semantics rather than inventing a monotonic-store promise.
	must(t, local.DeleteRange(3, 7))
	must(t, local.StoreLog(&raft.Log{Index: 3, Term: 6, Type: raft.LogCommand, Data: []byte("replacement")}))
	must(t, local.SetUint64([]byte("CurrentTerm"), 6))
	must(t, local.Sync())
	must(t, local.Close())
	back, e := old.NewBoltStore(copyPath)
	must(t, e)
	term, e := back.GetUint64([]byte("CurrentTerm"))
	must(t, e)
	if term != 6 {
		t.Fatal("term not durable")
	}
	var log raft.Log
	must(t, back.GetLog(3, &log))
	if log.Term != 6 || string(log.Data) != "replacement" {
		t.Fatal("replacement lost")
	}
	if !errors.Is(back.GetLog(7, &log), raft.ErrLogNotFound) {
		t.Fatal("truncated log resurrected")
	}
	must(t, back.Close())
	if sha256.Sum256(fileBytes(t, original)) != sha256.Sum256(originalBytes) {
		t.Fatal("source original modified")
	}
}

func TestLocalFileReadByOldV2AndReadOnlyLocalDoesNotChangeBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "local.db")
	local, e := current.NewBoltStore(path)
	must(t, e)
	seed(t, local)
	prior, e := old.NewBoltStore(path)
	must(t, e)
	assertSeed(t, prior)
	must(t, prior.Close())
	before := sha256.Sum256(fileBytes(t, path))
	ro, e := current.New(current.Options{Path: path, BoltOptions: &bbolt.Options{ReadOnly: true, Timeout: time.Second}})
	must(t, e)
	assertSeed(t, ro)
	if ro.SetUint64([]byte("CurrentTerm"), 7) == nil {
		t.Fatal("read-only write succeeded")
	}
	must(t, ro.Close())
	if sha256.Sum256(fileBytes(t, path)) != before {
		t.Fatal("read-only file bytes changed")
	}
}

func TestLogStoreMonotonicInterfaceRemainsUnclaimed(t *testing.T) {
	if _, ok := interface{}(&old.BoltStore{}).(raft.MonotonicLogStore); ok {
		t.Fatal("upstream assumptions changed")
	}
	if _, ok := interface{}(&current.BoltStore{}).(raft.MonotonicLogStore); ok {
		t.Fatal("local added monotonic promise")
	}
}
