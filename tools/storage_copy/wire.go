package storagecopy

import (
 "encoding/json"
 "time"
)
// itemsFromPrivatePlan checks the compiler's wire contract for synthetic fixtures.
// There is deliberately no production runner or runtime admission adapter.
func itemsFromPrivatePlan(raw []byte)([]Item,error){
 var plan struct{Schema string `json:"schema"`;ExecutionEnabled *bool `json:"executionEnabled"`;Authority json.RawMessage `json:"authority"`;CopiedObjects *int `json:"copiedObjects"`;VerifiedObjects *int `json:"verifiedObjects"`;Entries []struct{
 State string `json:"state"`;Body *string `json:"bodySha256Verified"`;Destination struct{Preserve *bool `json:"preserveBucketAndKey"`} `json:"destination"`
 Source struct{Bucket string `json:"bucket"`;Key string `json:"key"`;Version *string `json:"versionId"`;Latest bool `json:"isLatest"`;Marker bool `json:"deleteMarker"`;Size int64 `json:"size"`;Metadata map[string]string `json:"metadata"`;Head map[string]json.RawMessage `json:"headMetadata"`;Tags []struct{Key *string;Value *string} `json:"tags"`} `json:"source"`
 } `json:"entries"`}
 if len(raw)>64<<20||json.Unmarshal(raw,&plan)!=nil||plan.Schema!="ouf.storage-private-copy-plan.v1"||plan.ExecutionEnabled==nil||*plan.ExecutionEnabled||string(plan.Authority)!="null"||plan.CopiedObjects==nil||*plan.CopiedObjects!=0||plan.VerifiedObjects==nil||*plan.VerifiedObjects!=0||len(plan.Entries)==0||len(plan.Entries)>MaxObjects{return nil,code("UNADMITTED_PRIVATE_PLAN_WIRE_REQUIRED")}
 items:=[]Item{}
 for _,entry:=range plan.Entries{r:=entry.Source;if entry.State!="PLANNED_NOT_COPIED"||entry.Body!=nil||entry.Destination.Preserve==nil||!*entry.Destination.Preserve||r.Marker||!r.Latest||r.Version!=nil&&*r.Version!="null"{return nil,code("VERSION_HISTORY_OR_EXECUTABLE_PLAN_HELD")}
  m:=Meta{Size:r.Size,Metadata:map[string]string{},Headers:map[string]string{},Tags:map[string]string{}}
  for k,v:=range r.Metadata{m.Metadata[k]=v}
  for _,key:=range []string{"contentType","cacheControl","contentEncoding"}{if value,ok:=r.Head[key];ok&&string(value)!="null"{var text string;if json.Unmarshal(value,&text)!=nil{return nil,code("TYPED_PLANNED_HEADER_REQUIRED")};if text!=""{m.Headers[key]=text}}}
  if value,ok:=r.Head["lastModified"];ok&&string(value)!="null"{if json.Unmarshal(value,&m.LastModified)!=nil{return nil,code("TYPED_PLANNED_TIMESTAMP_REQUIRED")}}
  for _,key:=range []string{"serverSideEncryption","kmsKeyId","objectLockMode","retainUntilDate"}{if value,ok:=r.Head[key];ok&&string(value)!="null"&&string(value)!="\"\""{return nil,code("UNSUPPORTED_ENCRYPTION_OR_RETENTION_PLAN")}}
  for _,tag:=range r.Tags{if tag.Key==nil||tag.Value==nil{return nil,code("TYPED_PLANNED_TAG_REQUIRED")};if _,ok:=m.Tags[*tag.Key];ok{return nil,code("DUPLICATE_PLANNED_TAG")};m.Tags[*tag.Key]=*tag.Value}
  items=append(items,Item{ID{r.Bucket,r.Key},m})
 }
 return items,nil
}
var _=time.Second
