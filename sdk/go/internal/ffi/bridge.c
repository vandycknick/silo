//go:build cgo && (linux || darwin)

#include "bridge.h"

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void *library;

// Derive loader signatures from the cbindgen header so Rust remains the ABI source of truth.
static __typeof__(&silo_ffi_abi_version) ffi_abi_version;
static __typeof__(&silo_ffi_sdk_version) ffi_sdk_version;
#define DECLARE_FFI(name) static __typeof__(&silo_##name) ffi_##name
DECLARE_FFI(buffer_free);
DECLARE_FFI(error_free);
DECLARE_FFI(runtime_open);
DECLARE_FFI(runtime_free);
DECLARE_FFI(runtime_machine_create);
DECLARE_FFI(runtime_machine_get);
DECLARE_FFI(runtime_machines);
DECLARE_FFI(images_call);
DECLARE_FFI(machine_handle_list_at);
DECLARE_FFI(machine_handle_list_free);
DECLARE_FFI(machine_free);
DECLARE_FFI(machine_id);
DECLARE_FFI(machine_inspect);
DECLARE_FFI(machine_start);
DECLARE_FFI(machine_stop);
DECLARE_FFI(machine_remove);
DECLARE_FFI(machine_exec);
DECLARE_FFI(machine_shell);
DECLARE_FFI(machine_spawn);
DECLARE_FFI(machine_attach);
DECLARE_FFI(machine_attach_shell);
DECLARE_FFI(execution_recv);
DECLARE_FFI(execution_wait);
DECLARE_FFI(execution_collect);
DECLARE_FFI(execution_stdin);
DECLARE_FFI(execution_signal);
DECLARE_FFI(execution_resize_pty);
DECLARE_FFI(execution_close_requests);
DECLARE_FFI(execution_cancel);
DECLARE_FFI(execution_free);
DECLARE_FFI(stdin_write);
DECLARE_FFI(stdin_close);
DECLARE_FFI(stdin_free);
DECLARE_FFI(machine_logs);
DECLARE_FFI(log_recv);
DECLARE_FFI(log_close);
DECLARE_FFI(log_free);
DECLARE_FFI(network_policy_build);
#undef DECLARE_FFI

static char *load_symbol(void **target, const char *name) {
    dlerror();
    *target = dlsym(library, name);
    const char *error = dlerror();
    if (error == NULL && *target != NULL) return NULL;
    size_t length = strlen(name) + (error == NULL ? 0 : strlen(error)) + 40;
    char *message = malloc(length);
    if (message == NULL) return NULL;
    snprintf(message, length, "resolve native symbol %s: %s", name, error == NULL ? "not found" : error);
    return message;
}

#define LOAD(target, name) do { \
    char *error = load_symbol((void **)&target, name); \
    if (error != NULL) { \
        dlclose(library); \
        library = NULL; \
        return error; \
    } \
} while (0)

char *bridge_load(const char *path) {
    if (library != NULL) return NULL;
    library = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (library == NULL) {
        const char *error = dlerror();
        return strdup(error == NULL ? "dlopen failed" : error);
    }
    LOAD(ffi_abi_version, "silo_ffi_abi_version");
    LOAD(ffi_sdk_version, "silo_ffi_sdk_version");
    LOAD(ffi_buffer_free, "silo_buffer_free");
    LOAD(ffi_error_free, "silo_error_free");
    LOAD(ffi_runtime_open, "silo_runtime_open");
    LOAD(ffi_runtime_free, "silo_runtime_free");
    LOAD(ffi_runtime_machine_create, "silo_runtime_machine_create");
    LOAD(ffi_runtime_machine_get, "silo_runtime_machine_get");
    LOAD(ffi_runtime_machines, "silo_runtime_machines");
    LOAD(ffi_images_call, "silo_images_call");
    LOAD(ffi_machine_handle_list_at, "silo_machine_handle_list_at");
    LOAD(ffi_machine_handle_list_free, "silo_machine_handle_list_free");
    LOAD(ffi_machine_free, "silo_machine_free");
    LOAD(ffi_machine_id, "silo_machine_id");
    LOAD(ffi_machine_inspect, "silo_machine_inspect");
    LOAD(ffi_machine_start, "silo_machine_start");
    LOAD(ffi_machine_stop, "silo_machine_stop");
    LOAD(ffi_machine_remove, "silo_machine_remove");
    LOAD(ffi_machine_exec, "silo_machine_exec");
    LOAD(ffi_machine_shell, "silo_machine_shell");
    LOAD(ffi_machine_spawn, "silo_machine_spawn");
    LOAD(ffi_machine_attach, "silo_machine_attach");
    LOAD(ffi_machine_attach_shell, "silo_machine_attach_shell");
    LOAD(ffi_execution_recv, "silo_execution_recv");
    LOAD(ffi_execution_wait, "silo_execution_wait");
    LOAD(ffi_execution_collect, "silo_execution_collect");
    LOAD(ffi_execution_stdin, "silo_execution_stdin");
    LOAD(ffi_execution_signal, "silo_execution_signal");
    LOAD(ffi_execution_resize_pty, "silo_execution_resize_pty");
    LOAD(ffi_execution_close_requests, "silo_execution_close_requests");
    LOAD(ffi_execution_cancel, "silo_execution_cancel");
    LOAD(ffi_execution_free, "silo_execution_free");
    LOAD(ffi_stdin_write, "silo_stdin_write");
    LOAD(ffi_stdin_close, "silo_stdin_close");
    LOAD(ffi_stdin_free, "silo_stdin_free");
    LOAD(ffi_machine_logs, "silo_machine_logs");
    LOAD(ffi_log_recv, "silo_log_recv");
    LOAD(ffi_log_close, "silo_log_close");
    LOAD(ffi_log_free, "silo_log_free");
    LOAD(ffi_network_policy_build, "silo_network_policy_build");
    return NULL;
}

uint32_t bridge_abi_version(void) { return ffi_abi_version(); }
const char *bridge_sdk_version(void) { return ffi_sdk_version(); }
void bridge_string_free(char *value) { free(value); }
void bridge_buffer_free(silo_buffer value) { ffi_buffer_free(value); }
void bridge_error_free(silo_error *error) { ffi_error_free(error); }

silo_error *bridge_runtime_open(const uint8_t *request, size_t request_len, silo_runtime **out_runtime) { return ffi_runtime_open(request, request_len, out_runtime); }
void bridge_runtime_free(silo_runtime *runtime) { ffi_runtime_free(runtime); }
silo_error *bridge_runtime_machine_create(const silo_runtime *runtime, const uint8_t *request, size_t request_len, silo_machine **out_machine) { return ffi_runtime_machine_create(runtime, request, request_len, out_machine); }
silo_error *bridge_runtime_machine_get(const silo_runtime *runtime, const uint8_t *reference, size_t reference_len, silo_machine **out_machine) { return ffi_runtime_machine_get(runtime, reference, reference_len, out_machine); }
silo_error *bridge_runtime_machines(const silo_runtime *runtime, silo_machine_handle_list *out_machines) { return ffi_runtime_machines(runtime, out_machines); }
silo_error *bridge_images_call(const silo_runtime *runtime, const uint8_t *request, size_t request_len, silo_buffer *out_data) { return ffi_images_call(runtime, request, request_len, out_data); }
silo_machine *bridge_machine_handle_list_at(const silo_machine_handle_list *machines, size_t index) { return ffi_machine_handle_list_at(machines, index); }
void bridge_machine_handle_list_free(silo_machine_handle_list machines) { ffi_machine_handle_list_free(machines); }
void bridge_machine_free(silo_machine *machine) { ffi_machine_free(machine); }
silo_error *bridge_machine_id(const silo_machine *machine, silo_buffer *out_id) { return ffi_machine_id(machine, out_id); }
silo_error *bridge_machine_inspect(const silo_machine *machine, silo_buffer *out_data) { return ffi_machine_inspect(machine, out_data); }
silo_error *bridge_machine_start(const silo_machine *machine, silo_buffer *out_data) { return ffi_machine_start(machine, out_data); }
silo_error *bridge_machine_stop(const silo_machine *machine, silo_buffer *out_data) { return ffi_machine_stop(machine, out_data); }
silo_error *bridge_machine_remove(const silo_machine *machine) { return ffi_machine_remove(machine); }
silo_error *bridge_machine_exec(const silo_machine *machine, const uint8_t *request, size_t request_len, silo_execution_output *out_output) { return ffi_machine_exec(machine, request, request_len, out_output); }
silo_error *bridge_machine_shell(const silo_machine *machine, const uint8_t *request, size_t request_len, silo_execution_output *out_output) { return ffi_machine_shell(machine, request, request_len, out_output); }
silo_error *bridge_machine_spawn(const silo_machine *machine, const uint8_t *request, size_t request_len, silo_execution **out_session) { return ffi_machine_spawn(machine, request, request_len, out_session); }
silo_error *bridge_machine_attach(const silo_machine *machine, const uint8_t *request, size_t request_len, silo_buffer *out_result) { return ffi_machine_attach(machine, request, request_len, out_result); }
silo_error *bridge_machine_attach_shell(const silo_machine *machine, const uint8_t *request, size_t request_len, silo_buffer *out_status) { return ffi_machine_attach_shell(machine, request, request_len, out_status); }
silo_error *bridge_execution_recv(const silo_execution *session, silo_execution_event *out_event, _Bool *out_eof) { return ffi_execution_recv(session, out_event, out_eof); }
silo_error *bridge_execution_wait(const silo_execution *session, silo_buffer *out_result) { return ffi_execution_wait(session, out_result); }
silo_error *bridge_execution_collect(const silo_execution *session, silo_execution_output *out_output) { return ffi_execution_collect(session, out_output); }
silo_error *bridge_execution_stdin(const silo_execution *session, silo_stdin **out_stdin) { return ffi_execution_stdin(session, out_stdin); }
silo_error *bridge_execution_signal(const silo_execution *session, uint32_t signal) { return ffi_execution_signal(session, signal); }
silo_error *bridge_execution_resize_pty(const silo_execution *session, uint16_t rows, uint16_t columns) { return ffi_execution_resize_pty(session, rows, columns); }
silo_error *bridge_execution_close_requests(const silo_execution *session) { return ffi_execution_close_requests(session); }
silo_error *bridge_execution_cancel(const silo_execution *session) { return ffi_execution_cancel(session); }
void bridge_execution_free(silo_execution *session) { ffi_execution_free(session); }
silo_error *bridge_stdin_write(const silo_stdin *stdin_handle, const uint8_t *data, size_t data_len) { return ffi_stdin_write(stdin_handle, data, data_len); }
silo_error *bridge_stdin_close(const silo_stdin *stdin_handle) { return ffi_stdin_close(stdin_handle); }
void bridge_stdin_free(silo_stdin *stdin_handle) { ffi_stdin_free(stdin_handle); }
silo_error *bridge_machine_logs(const silo_machine *machine, const uint8_t *request, size_t request_len, silo_log **out_log) { return ffi_machine_logs(machine, request, request_len, out_log); }
silo_error *bridge_log_recv(const silo_log *log, silo_log_chunk *out_chunk, _Bool *out_eof) { return ffi_log_recv(log, out_chunk, out_eof); }
silo_error *bridge_log_close(const silo_log *log) { return ffi_log_close(log); }
void bridge_log_free(silo_log *log) { ffi_log_free(log); }
silo_error *bridge_network_policy_build(const uint8_t *request, size_t request_len, silo_buffer *out_policy) { return ffi_network_policy_build(request, request_len, out_policy); }
