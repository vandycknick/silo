package main

import (
	"context"
	"log"

	"github.com/vandycknick/silo/sdk/go"
)

func main() {
	installation, err := silo.InstallRuntime(context.Background(), silo.WithRuntimeArchive("/absolute/path/to/silo-runtime-0.1.0-linux-amd64-gnu.tar.zst"))
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("runtime installed at %s", installation.Root)
}
