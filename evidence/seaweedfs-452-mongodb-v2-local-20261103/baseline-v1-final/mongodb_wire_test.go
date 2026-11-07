package mongodb

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/seaweedfs/seaweedfs/weed/filer"
	"github.com/seaweedfs/seaweedfs/weed/pb/filer_pb"
	"github.com/seaweedfs/seaweedfs/weed/util"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// This deliberately limited TCP fixture uses the real driver serializer,
// connection pool, command encoding and response decoding. It is not MongoDB
// and does not prove database durability, query execution, auth, or failover.
type mongoWireFixture struct {
	listener    net.Listener
	wireVersion int32
	mu          sync.Mutex
	connections []net.Conn
	replies     []bson.D
	commands    []bson.D
	wg          sync.WaitGroup
}

func newMongoWireFixture(t *testing.T, replies ...bson.D) *mongoWireFixture {
	return newMongoWireFixtureVersion(t, 25, replies...)
}

func newMongoWireFixtureVersion(t *testing.T, version int32, replies ...bson.D) *mongoWireFixture {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &mongoWireFixture{listener: listener, replies: replies, wireVersion: version}
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			f.mu.Lock()
			f.connections = append(f.connections, c)
			f.mu.Unlock()
			f.wg.Add(1)
			go func() { defer f.wg.Done(); defer c.Close(); f.serve(c) }()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		f.mu.Lock()
		for _, c := range f.connections {
			c.Close()
		}
		f.mu.Unlock()
		f.wg.Wait()
	})
	return f
}
func (f *mongoWireFixture) uri() string {
	return "mongodb://" + f.listener.Addr().String() + "/?directConnection=true&serverSelectionTimeoutMS=500&connectTimeoutMS=500&retryReads=false&retryWrites=false"
}
func (f *mongoWireFixture) serve(c net.Conn) {
	for {
		var header [16]byte
		if _, err := io.ReadFull(c, header[:]); err != nil {
			return
		}
		length := int(binary.LittleEndian.Uint32(header[:4]))
		if length < 16 || length > 2<<20 {
			return
		}
		body := make([]byte, length-16)
		if _, err := io.ReadFull(c, body); err != nil {
			return
		}
		opcode := binary.LittleEndian.Uint32(header[12:])
		command, err := decodeMongoTestCommand(opcode, body)
		if err != nil || len(command) == 0 {
			return
		}
		name := strings.ToLower(command[0].Key)
		var response bson.D
		if name == "ismaster" || name == "hello" {
			response = bson.D{{Key: "ok", Value: 1}, {Key: "ismaster", Value: true}, {Key: "isWritablePrimary", Value: true}, {Key: "helloOk", Value: true}, {Key: "minWireVersion", Value: 0}, {Key: "maxWireVersion", Value: f.wireVersion}, {Key: "maxBsonObjectSize", Value: 16777216}, {Key: "maxMessageSizeBytes", Value: 48000000}, {Key: "maxWriteBatchSize", Value: 100000}, {Key: "logicalSessionTimeoutMinutes", Value: 30}}
		} else if name == "endsessions" {
			response = bson.D{{Key: "ok", Value: 1}}
		} else {
			f.mu.Lock()
			f.commands = append(f.commands, command)
			if len(f.replies) > 0 {
				response = f.replies[0]
				f.replies = f.replies[1:]
			} else {
				response = bson.D{{Key: "ok", Value: 0}, {Key: "code", Value: 59}, {Key: "errmsg", Value: "unexpected test command"}}
			}
			f.mu.Unlock()
		}
		doc, err := bson.Marshal(response)
		if err != nil {
			return
		}
		var out []byte
		if opcode == 2004 {
			out = make([]byte, 36)
			binary.LittleEndian.PutUint32(out[12:], 1)
			binary.LittleEndian.PutUint32(out[32:], 1)
		} else {
			out = make([]byte, 21)
			binary.LittleEndian.PutUint32(out[12:], 2013)
		}
		out = append(out, doc...)
		binary.LittleEndian.PutUint32(out[:4], uint32(len(out)))
		binary.LittleEndian.PutUint32(out[4:], 1)
		copy(out[8:12], header[4:8])
		if _, err := c.Write(out); err != nil {
			return
		}
	}
}
func decodeMongoTestCommand(opcode uint32, body []byte) (bson.D, error) {
	var command bson.D
	if opcode == 2004 {
		if len(body) < 5 {
			return nil, io.ErrUnexpectedEOF
		}
		i := 4
		for i < len(body) && body[i] != 0 {
			i++
		}
		i += 9
		if i >= len(body) {
			return nil, io.ErrUnexpectedEOF
		}
		err := bson.Unmarshal(body[i:], &command)
		return command, err
	}
	if opcode != 2013 || len(body) < 5 {
		return nil, fmt.Errorf("unsupported opcode %d", opcode)
	}
	for i := 4; i < len(body); {
		kind := body[i]
		i++
		if i+4 > len(body) {
			return nil, io.ErrUnexpectedEOF
		}
		size := int(binary.LittleEndian.Uint32(body[i:]))
		if size < 4 || i+size > len(body) {
			return nil, io.ErrUnexpectedEOF
		}
		if kind == 0 {
			if err := bson.Unmarshal(body[i:i+size], &command); err != nil {
				return nil, err
			}
			i += size
			continue
		}
		if kind != 1 {
			return nil, fmt.Errorf("unsupported section %d", kind)
		}
		end := i + size
		i += 4
		start := i
		for i < end && body[i] != 0 {
			i++
		}
		identifier := string(body[start:i])
		i++
		var documents bson.A
		for i < end {
			if i+4 > end {
				return nil, io.ErrUnexpectedEOF
			}
			n := int(binary.LittleEndian.Uint32(body[i:]))
			if n < 5 || i+n > end {
				return nil, io.ErrUnexpectedEOF
			}
			var document bson.D
			if err := bson.Unmarshal(body[i:i+n], &document); err != nil {
				return nil, err
			}
			documents = append(documents, document)
			i += n
		}
		command = append(command, bson.E{Key: identifier, Value: documents})
	}
	return command, nil
}
func (f *mongoWireFixture) command(t *testing.T, n int) bson.Raw {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if n >= len(f.commands) {
		t.Fatalf("wanted command %d, got %d", n, len(f.commands))
	}
	data, err := bson.Marshal(f.commands[n])
	if err != nil {
		t.Fatal(err)
	}
	return bson.Raw(data)
}
func mongoOK() bson.D {
	return bson.D{{Key: "ok", Value: 1}, {Key: "n", Value: 1}, {Key: "nModified", Value: 1}}
}
func mongoCursor(batch string, id int64, docs ...bson.D) bson.D {
	values := bson.A{}
	for _, d := range docs {
		values = append(values, d)
	}
	return bson.D{{Key: "ok", Value: 1}, {Key: "cursor", Value: bson.D{{Key: "id", Value: id}, {Key: "ns", Value: "fixture.filemeta"}, {Key: batch, Value: values}}}}
}
func mongoError(code int32) bson.D {
	return bson.D{{Key: "ok", Value: 0}, {Key: "code", Value: code}, {Key: "errmsg", Value: "synthetic server error"}}
}
func mongoTestClient(t *testing.T, f *mongoWireFixture) *mongo.Client {
	t.Helper()
	opts := options.Client().ApplyURI(f.uri())
	client, err := mongo.Connect(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = client.Disconnect(ctx)
	})
	return client
}
func mongoTestStore(t *testing.T, f *mongoWireFixture) *MongodbStore {
	return &MongodbStore{connect: mongoTestClient(t, f), database: "fixture", collectionName: "filemeta"}
}

func TestMongoModelBSONFixture(t *testing.T) {
	data, err := bson.Marshal(Model{Directory: "/é", Name: "x.$", Meta: []byte{0, 255}})
	if err != nil {
		t.Fatal(err)
	}
	const want = "33000000026469726563746f727900040000002fc3a900026e616d650004000000782e2400056d65746100020000000000ff00"
	if hex.EncodeToString(data) != want {
		t.Fatalf("BSON changed: %x", data)
	}
	var decoded Model
	if err := bson.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Directory != "/é" || decoded.Name != "x.$" || !reflect.DeepEqual(decoded.Meta, []byte{0, 255}) {
		t.Fatalf("bad model: %#v", decoded)
	}
}
func TestMongoWireIndexAndEntryRoundTrip(t *testing.T) {
	entry := &filer.Entry{FullPath: util.FullPath("/café/a.$[x]"), Attr: filer.Attr{Mtime: time.Unix(123, 0), Crtime: time.Unix(100, 0), Mode: 0644, Uid: 42, Mime: "application/octet-stream"}, Content: []byte{0, 255, 1}}
	meta, err := entry.EncodeAttributesAndChunks()
	if err != nil {
		t.Fatal(err)
	}
	f := newMongoWireFixture(t, mongoOK(), mongoOK(), mongoCursor("firstBatch", 0, bson.D{{Key: "directory", Value: "/café"}, {Key: "name", Value: "a.$[x]"}, {Key: "meta", Value: meta}}), mongoOK())
	store := &MongodbStore{database: "fixture", collectionName: "filemeta"}
	if err := store.connection(f.uri(), 3, false, "", "", "", "", "", false); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Shutdown)
	index := f.command(t, 0)
	if index.Lookup("createIndexes").StringValue() != "filemeta" {
		t.Fatal(index)
	}
	indexes := index.Lookup("indexes").Array()
	idx := indexes.Index(0).Value().Document()
	if !idx.Lookup("unique").Boolean() || idx.Lookup("key", "directory").Int32() != 1 || idx.Lookup("key", "name").Int32() != 1 {
		t.Fatal(idx)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := store.UpdateEntry(ctx, entry); err != nil {
		t.Fatal(err)
	}
	update := f.command(t, 1).Lookup("updates").Array().Index(0).Value().Document()
	if !update.Lookup("upsert").Boolean() || update.Lookup("q", "directory").StringValue() != "/café" || update.Lookup("q", "name").StringValue() != "a.$[x]" {
		t.Fatal(update)
	}
	_, actual := update.Lookup("u", "$set", "meta").Binary()
	if !reflect.DeepEqual(actual, meta) {
		t.Fatal("metadata encoding changed")
	}
	got, err := store.FindEntry(ctx, entry.FullPath)
	if err != nil {
		t.Fatal(err)
	}
	if got.FullPath != entry.FullPath || got.Mime != entry.Mime || got.Uid != 42 || !reflect.DeepEqual(got.Content, entry.Content) {
		t.Fatalf("roundtrip mismatch %#v", got)
	}
	if err := store.DeleteEntry(ctx, entry.FullPath); err != nil {
		t.Fatal(err)
	}
	del := f.command(t, 3).Lookup("deletes").Array().Index(0).Value().Document()
	if del.Lookup("limit").Int32() != 0 {
		t.Fatal("DeleteEntry no longer deletes matching metadata rows")
	}
}
func TestMongoWireKVAndMissingBehavior(t *testing.T) {
	f := newMongoWireFixture(t, mongoOK(), mongoCursor("firstBatch", 0, bson.D{{Key: "meta", Value: []byte{0, 1, 255}}}), mongoOK(), mongoCursor("firstBatch", 0), mongoCursor("firstBatch", 0))
	store := mongoTestStore(t, f)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	key := []byte("abcdefghsuffix")
	if err := store.KvPut(ctx, key, []byte{0, 1, 255}); err != nil {
		t.Fatal(err)
	}
	q := f.command(t, 0).Lookup("updates").Array().Index(0).Value().Document().Lookup("q").Document()
	if q.Lookup("directory").StringValue() != "abcdefgh" || q.Lookup("name").StringValue() != "suffix" {
		t.Fatal(q)
	}
	got, err := store.KvGet(ctx, key)
	if err != nil || !reflect.DeepEqual(got, []byte{0, 1, 255}) {
		t.Fatalf("kv %v %v", got, err)
	}
	if err := store.KvDelete(ctx, key); err != nil {
		t.Fatal(err)
	}
	if _, err := store.KvGet(ctx, key); !errors.Is(err, filer.ErrKvNotFound) {
		t.Fatalf("missing kv %v", err)
	}
	if _, err := store.FindEntry(ctx, "/absent"); !errors.Is(err, filer_pb.ErrNotFound) {
		t.Fatalf("missing entry %v", err)
	}
}
func TestMongoWireFailuresRemainFailures(t *testing.T) {
	t.Run("index-does-not-publish-client", func(t *testing.T) {
		f := newMongoWireFixture(t, mongoError(11000))
		store := &MongodbStore{database: "fixture", collectionName: "filemeta"}
		err := store.connection(f.uri(), 0, false, "", "", "", "", "", false)
		if err == nil {
			t.Fatal("index error accepted")
		}
		if store.connect != nil {
			store.Shutdown()
			t.Fatal("failed index published unusable client")
		}
	})
	t.Run("find-server-error-is-not-missing", func(t *testing.T) {
		f := newMongoWireFixture(t, mongoError(13))
		store := mongoTestStore(t, f)
		_, err := store.FindEntry(context.Background(), "/a")
		var commandError mongo.CommandError
		if errors.Is(err, filer_pb.ErrNotFound) || !errors.As(err, &commandError) || commandError.Code != 13 {
			t.Fatalf("server failure lost: %v", err)
		}
	})
	t.Run("cursor-failure-is-not-complete", func(t *testing.T) {
		f := newMongoWireFixture(t, mongoCursor("firstBatch", 12), mongoError(43), mongoOK())
		store := mongoTestStore(t, f)
		_, err := store.ListDirectoryEntries(context.Background(), "/", "", false, 4, func(*filer.Entry) (bool, error) { t.Fatal("unexpected entry"); return false, nil })
		var commandError mongo.CommandError
		if !errors.As(err, &commandError) || commandError.Code != 43 {
			t.Fatalf("cursor failure lost: %v", err)
		}
	})
	t.Run("cancelled-find-is-not-missing", func(t *testing.T) {
		f := newMongoWireFixture(t)
		store := mongoTestStore(t, f)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := store.FindEntry(ctx, "/a")
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation lost: %v", err)
		}
	})
	t.Run("write-server-error-preserves-code", func(t *testing.T) {
		f := newMongoWireFixture(t, mongoError(13))
		store := mongoTestStore(t, f)
		err := store.UpdateEntry(context.Background(), &filer.Entry{FullPath: "/a"})
		var commandError mongo.CommandError
		if !errors.As(err, &commandError) || commandError.Code != 13 {
			t.Fatalf("write failure lost: %v", err)
		}
	})
}
func TestMongoWireListingFiltersAndCallbackFailure(t *testing.T) {
	entry := &filer.Entry{FullPath: "/dir/a.[x]"}
	meta, err := entry.EncodeAttributesAndChunks()
	if err != nil {
		t.Fatal(err)
	}
	f := newMongoWireFixture(t, mongoCursor("firstBatch", 0, bson.D{{Key: "name", Value: "a.[x]"}, {Key: "meta", Value: meta}}))
	store := mongoTestStore(t, f)
	sentinel := errors.New("callback stopped")
	last, err := store.ListDirectoryPrefixedEntries(context.Background(), "/dir", "a", true, 7, "a.[", func(got *filer.Entry) (bool, error) {
		if got.FullPath != "/dir/a.[x]" {
			t.Fatal(got.FullPath)
		}
		return false, sentinel
	})
	if last != "a.[x]" || !errors.Is(err, sentinel) {
		t.Fatalf("last=%q err=%v", last, err)
	}
	cmd := f.command(t, 0)
	if cmd.Lookup("filter", "name", "$regex").StringValue() != `^a\.\[` || cmd.Lookup("filter", "name", "$gte").StringValue() != "a" || cmd.Lookup("sort", "name").Int32() != 1 || cmd.Lookup("limit").Int64() != 7 {
		t.Fatal(cmd)
	}
}
func TestMongoInvalidPathsAreRejectedWithoutClient(t *testing.T) {
	store := &MongodbStore{}
	ctx := context.Background()
	for _, op := range []func() error{func() error { return store.UpdateEntry(ctx, &filer.Entry{FullPath: "/bad\x00"}) }, func() error { _, err := store.FindEntry(ctx, "/bad\x00"); return err }, func() error { return store.DeleteEntry(ctx, "/bad\x00") }, func() error { return store.DeleteFolderChildren(ctx, "/bad\x00") }, func() error { _, err := store.ListDirectoryEntries(ctx, "/bad\x00", "", false, 1, nil); return err }} {
		if err := op(); err == nil {
			t.Fatal("invalid path accepted")
		}
	}
}
