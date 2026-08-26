// Package silo provides daemonless local virtual machine management through Silo's libvm runtime.
//
// Runtime installation is explicit. Call [InstallRuntime], then pass the returned root to [Open]
// with [WithRuntimeRoot]. Importing this package and opening or starting machines never downloads
// runtime components.
//
// Native operations require CGO_ENABLED=1 on a supported host. Call Close on Runtime, Machine,
// ExecutionSession, ExecutionStdin, and MachineLogStream values when they are no longer needed.
package silo
