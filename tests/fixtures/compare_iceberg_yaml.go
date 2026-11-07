package main

import (
    "encoding/json"
    "fmt"
    "os"
    "reflect"

    "github.com/apache/iceberg-go/config"
    maintained "go.yaml.in/yaml/v3"
    legacy "gopkg.in/yaml.v3"
)

func main() {
    cases := []struct{name, input string}{
        {"empty", ""},
        {"ordinary", "default-catalog: lake\nmax-workers: 7\ncatalog:\n  lake:\n    type: rest\n    uri: https://catalog.example/\n    warehouse: bucket/prefix\n    credential: id:secret\n"},
        {"typed-legacy-bool", "catalog:\n  default:\n    rest:\n      sigv4-enabled: yes\n"},
        {"anchors-merge", "defaults: &base\n  type: rest\n  uri: https://catalog.example/\ncatalog:\n  default:\n    <<: *base\n    warehouse: first\n"},
        {"duplicate-key", "max-workers: 2\nmax-workers: 3\n"},
        {"duplicate-catalog", "catalog:\n  default: {type: rest}\n  default: {type: sql}\n"},
        {"unknown-field", "future: optional\ncatalog:\n  default: {unknown: ignored, type: rest}\n"},
        {"bad-int", "max-workers: many\n"},
        {"overflow-int", "max-workers: 999999999999999999999999999\n"},
        {"bad-bool", "catalog:\n  default:\n    rest: {sigv4-enabled: maybe}\n"},
        {"bad-nesting", "catalog: [not, a, map]\n"},
        {"bad-syntax", "catalog: [unterminated"},
        {"unknown-anchor", "catalog: *missing\n"},
        {"multiple-documents", "max-workers: 3\n---\nmax-workers: 4\n"},
        {"octal-int", "max-workers: 0777\n"},
        {"null-catalog", "catalog: null\n"},
        {"invalid-utf8", string([]byte{0xff,0xfe,0xff})},
    }
    type result struct{Name string;Equivalent bool;LegacyError string;MaintainedError string}
    results:=[]result{}
    failed:=false
    for _,c:=range cases {
        var old,new config.Config
        oldErr:=legacy.Unmarshal([]byte(c.input),&old)
        newErr:=maintained.Unmarshal([]byte(c.input),&new)
        same:=(oldErr==nil)==(newErr==nil) && reflect.DeepEqual(old,new)
        r:=result{Name:c.name,Equivalent:same}
        if oldErr!=nil{r.LegacyError=oldErr.Error()};if newErr!=nil{r.MaintainedError=newErr.Error()}
        results=append(results,r);failed=failed||!same
    }
    data,_:=json.MarshalIndent(results,"","  ");fmt.Println(string(data))
    if failed{os.Exit(1)}
}
