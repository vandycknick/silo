package sshd

import (
	"fmt"
	"strings"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/service"
)

func renderList(vms []service.VM) string {
	var b strings.Builder
	b.WriteString("NAME STATE NODE ADDRESS CPUS MEMORY CREATED\n")
	for _, vm := range vms {
		fmt.Fprintf(&b, "%s %s %s %s %d %d %s\n", vm.Name, vm.State, vm.Node, vm.Address, vm.CPUs, vm.Memory, vm.Created.Format(time.RFC3339))
	}
	return b.String()
}
func renderShow(v service.VM) string {
	text := fmt.Sprintf("Name: %s\nID: %s\nOwner: %s\nState: %s\nCPUs: %d\nMemory: %d\nDisk: %d\nImage: %s\nLabels: %v\n", v.Name, v.ID, v.Owner, v.State, v.CPUs, v.Memory, v.Disk, v.Image, v.Labels)
	if v.LastOperation != nil {
		text += fmt.Sprintf("Last operation: %s %s\n", v.LastOperation.ID, v.LastOperation.State)
	}
	return text
}
func commandHelp(cmd string) (string, bool) {
	help := map[string]string{
		"create": "create NAME [IMAGE|--image OCI] [--cpus N] [--memory SIZE] [--disk-size SIZE] [--userdata INLINE|-] [--label K=V]... [--owner tag:NAME] [--no-tailnet] [--no-start]",
		"ls":     "ls [--json]", "show": "show VM [--json]", "start": "start VM [--json]", "stop": "stop VM [--force] [--timeout DURATION] [--json]", "restart": "restart VM [--json]", "rm": "rm VM [--force] [--yes|--json]", "set": "set VM name=NAME|cpus=N|memory=SIZE|disk=SIZE... [--json]", "shell": "shell VM [-u USER] (requires ssh -t)", "exec": "exec VM [-u USER] [-w DIR] [-e K=V]... [-t] -- CMD...", "logs": "logs VM [--follow] [--stream monitor|serial|exec|network|network-audit] [--output stdout|stderr]", "ops": "ops [show op_ULID] [--json]", "whoami": "whoami [--json]", "version": "version [--json]", "help": "help [COMMAND] [--json]",
	}
	value, ok := help[cmd]
	return value + "\n", ok
}
