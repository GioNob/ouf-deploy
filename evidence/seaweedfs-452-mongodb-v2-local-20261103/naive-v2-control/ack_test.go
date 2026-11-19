package mongodb
import("context";"strings";"testing";"github.com/seaweedfs/seaweedfs/weed/filer";"go.mongodb.org/mongo-driver/v2/mongo";"go.mongodb.org/mongo-driver/v2/mongo/options";"go.mongodb.org/mongo-driver/v2/mongo/writeconcern")
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
