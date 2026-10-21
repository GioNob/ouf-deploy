// Build inside the exact observed Moby commit; use its initlayer implementation.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/moby/moby/v2/daemon/initlayer"
)

func main() {
	if os.Geteuid() != 0 || len(os.Args) != 2 || !filepath.IsAbs(os.Args[1]) {
		fmt.Fprintln(os.Stderr, "OUF_OFFLINE_DOCKER_INIT=DENIED")
		os.Exit(1)
	}
	root := filepath.Clean(os.Args[1])
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		fmt.Fprintln(os.Stderr, "OUF_OFFLINE_DOCKER_INIT=DENIED")
		os.Exit(1)
	}
	// Match daemon/command/daemon_unix.go at the same sealed Moby commit.
	syscall.Umask(0)
	if err := initlayer.Setup(root, 0, 0); err != nil {
		fmt.Fprintln(os.Stderr, "OUF_OFFLINE_DOCKER_INIT=DENIED")
		os.Exit(1)
	}
}
