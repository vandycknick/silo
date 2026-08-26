package main

import (
	"context"
	"log"

	"github.com/vandycknick/silo/sdk/go"
)

func inspect(ctx context.Context, runtime *silo.Runtime) error {
	image, err := runtime.Images().Inspect(ctx, "ubuntu:24.04")
	if err != nil {
		return err
	}
	if image == nil {
		log.Print("image is not cached")
		return nil
	}
	log.Printf("image %s has %d layers", image.Handle.ImageID, len(image.Layers))
	return nil
}
func main() { log.Print("call inspect with an open *silo.Runtime") }
