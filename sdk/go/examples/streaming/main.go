package main

import (
	"context"
	"errors"
	"io"
	"log"

	"github.com/vandycknick/silo/sdk/go"
)

func stream(ctx context.Context, machine *silo.Machine) error {
	session, err := machine.Spawn(ctx, "/bin/cat", nil, silo.WithExecStdinPipe())
	if err != nil {
		return err
	}
	defer session.Close()
	stdin := session.Stdin()
	if stdin == nil {
		return errors.New("stdin pipe unavailable")
	}
	if _, err = stdin.Write([]byte("hello\n")); err != nil {
		return err
	}
	if err = stdin.Close(); err != nil {
		return err
	}
	for {
		event, recvErr := session.Recv(ctx)
		if errors.Is(recvErr, io.EOF) {
			break
		}
		if recvErr != nil {
			return recvErr
		}
		log.Printf("%s: %s", event.Kind, event.Data)
	}
	result, err := session.Wait(ctx)
	if err != nil {
		return err
	}
	log.Printf("terminal result: %s", result.Kind)
	return nil
}

func main() { log.Print("call stream with a running *silo.Machine") }
