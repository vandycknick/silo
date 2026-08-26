package silo

import "testing"

func TestMachineOptionsCopyCallerCollections(t *testing.T) {
	labels := map[string]string{"a": "b"}
	metadata := map[string]string{"c": "d"}
	disks := []string{"disk.raw"}
	mounts := []Mount{{Source: "/host", Tag: "host"}}
	config := machineConfig{}
	WithLabels(labels)(&config)
	WithMetadata(metadata)(&config)
	WithDisks(disks...)(&config)
	WithMounts(mounts...)(&config)
	labels["a"] = "changed"
	metadata["c"] = "changed"
	disks[0] = "changed"
	mounts[0].Tag = "changed"
	if config.Labels["a"] != "b" || config.Metadata["c"] != "d" || config.Disks[0] != "disk.raw" || config.Mounts[0].Tag != "host" {
		t.Fatalf("machine options retained caller-owned collections: %#v", config)
	}
}
func TestMachineMemoryUsesExactBytes(t *testing.T) {
	config := machineConfig{}
	WithMemory(Gibibytes(2))(&config)
	if config.MemoryBytes == nil || *config.MemoryBytes != 2*1024*1024*1024 {
		t.Fatalf("memory bytes = %v", config.MemoryBytes)
	}
}
