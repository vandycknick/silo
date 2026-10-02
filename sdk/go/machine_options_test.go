package silo

import (
	"context"
	"encoding/json"
	"testing"
)

func TestMachineOptionsCopyCallerCollections(t *testing.T) {
	labels := map[string]string{"a": "b"}
	metadata := map[string]string{"c": "d"}
	disks := []string{"disk.raw"}
	mounts := []Mount{{Source: "/host", Tag: "host"}}
	forwards := []Forward{{Listen: "host:tcp:8080", Connect: "guest:tcp:80"}}
	config := machineConfig{}
	WithLabels(labels)(&config)
	WithMetadata(metadata)(&config)
	WithDisks(disks...)(&config)
	WithMounts(mounts...)(&config)
	WithForwards(forwards...)(&config)
	forwards[0].Listen = "changed"
	if config.Forwards[0].Listen != "host:tcp:8080" {
		t.Fatal("forwards retained caller-owned slice")
	}
	labels["a"] = "changed"
	metadata["c"] = "changed"
	disks[0] = "changed"
	mounts[0].Tag = "changed"
	if config.Labels["a"] != "b" || config.Metadata["c"] != "d" || config.Disks[0] != "disk.raw" || config.Mounts[0].Tag != "host" {
		t.Fatalf("machine options retained caller-owned collections: %#v", config)
	}
}
func TestForwardingOptionsAndInspectionRoundTrip(t *testing.T) {
	forward := Forward{Name: "docker", Listen: "host:unix:docker.sock", Connect: "guest:unix:/var/run/docker.sock", Mode: "0660"}
	network := PrivateNetwork(nil).WithPublish(PublishLoopback)
	config := machineConfig{}
	WithForwards(forward)(&config)
	WithVsock(false)(&config)
	WithMachineNetwork(network)(&config)
	network.Publish.Bind = PublishAny
	if config.error != nil {
		t.Fatal(config.error)
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	var roundTrip machineConfig
	if err := json.Unmarshal(encoded, &roundTrip); err != nil {
		t.Fatal(err)
	}
	if len(roundTrip.Forwards) != 1 || roundTrip.Forwards[0] != forward || roundTrip.Vsock == nil || *roundTrip.Vsock || roundTrip.Network.Publish.Bind != PublishLoopback {
		t.Fatalf("forwarding options lost configuration: %s", encoded)
	}
	data, err := decodeMachineData([]byte(`{"forwards":[{"name":"docker","listen":"host:unix:docker.sock","connect":"guest:unix:/var/run/docker.sock","mode":"0660"}],"vsock":{"enabled":true,"uds":"custom.sock"},"network":{"kind":"private","publish":{"bind":"any"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(data.Forwards) != 1 || data.Forwards[0] != forward || data.Vsock == nil || !data.Vsock.Enabled || data.Vsock.UDS != "custom.sock" || data.Network.Publish.Bind != PublishAny {
		t.Fatalf("inspection lost forwarding configuration: %#v", data)
	}
	for _, network := range []MachineNetwork{NoNetwork().WithPublish(PublishAny), NamedNetwork("shared").WithPublish(PublishLoopback), PrivateNetwork(nil).WithPublish("invalid")} {
		if _, err := network.wire(); err == nil {
			t.Fatalf("accepted invalid publication: %#v", network)
		}
	}
}

func TestMachineMemoryUsesExactBytes(t *testing.T) {
	config := machineConfig{}
	WithMemory(Gibibytes(2))(&config)
	if config.MemoryBytes == nil || *config.MemoryBytes != 2*1024*1024*1024 {
		t.Fatalf("memory bytes = %v", config.MemoryBytes)
	}
}

func TestGuestUserExplicitSyntaxAndValidation(t *testing.T) {
	for _, value := range []string{"nickvd:1000:1000:/home/nickvd", "Silo_2:42:43:/srv/work", "machine$:1001:1002:/home/machine", "1$:1:1:/home/one"} {
		if _, err := ParseGuestUser(value); err != nil {
			t.Errorf("%q: %v", value, err)
		}
	}
	for _, value := range []string{"", "nickvd", "nickvd:1000:1000", "nickvd:1000:1000:/home/nickvd:extra", "root:1:1:/root", "nobody:1:1:/home/nobody", "nickvd:0:1:/home/x", "nickvd:1:65534:/home/x", "nickvd:4294967295:1:/home/x", "nickvd:1:4294967295:/home/x", "123:1:1:/home/x", "-x:1:1:/home/x", "x$:1:1:relative", "x:1:1:/", "x:1:1:/home/../x", "x:1:1:/home/./x", "x:1:1:/home/x\x00", "x:1:1:/home/x\n", "x:1:1:/home/x\r", "x:+1:1:/home/x", "x:4294967296:1:/home/x"} {
		if _, err := ParseGuestUser(value); err == nil {
			t.Errorf("accepted %q", value)
		}
	}
	var runtime Runtime
	if _, err := runtime.CreateMachine(context.Background(), OCIImage("invalid.example/image"), WithGuestUser("root", 0, 0, "/root")); !IsErrorKind(err, ErrorInvalidArgument) {
		t.Fatal(err)
	}
}
