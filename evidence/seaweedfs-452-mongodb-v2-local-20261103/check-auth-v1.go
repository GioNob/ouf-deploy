package main
import("fmt";"go.mongodb.org/mongo-driver/mongo/options")
func main(){opts:=options.Client().ApplyURI("mongodb://127.0.0.1/?authMechanism=SCRAM-SHA-256");creds:=options.Credential{};if opts.Auth!=nil{creds=*opts.Auth};creds.Username="fixture";creds.Password="fixture";creds.PasswordSet=true;opts.SetAuth(creds);fmt.Printf("validation=%v authMechanism=%s authSource=%s\n",opts.Validate(),opts.Auth.AuthMechanism,opts.Auth.AuthSource)}
