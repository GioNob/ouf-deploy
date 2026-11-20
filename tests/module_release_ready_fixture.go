// Disposable PID 1 for the MCP module-release native test.
package main

import (
	"log"
	"net/http"
	"os"
)

func main() {
	if len(os.Args) != 2 || os.Args[1] != "server" {
		os.Exit(2)
	}
	http.HandleFunc("/health/ready", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	log.Fatal(http.ListenAndServe("127.0.0.1:8080", nil))
}
