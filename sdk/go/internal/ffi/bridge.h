#ifndef SILO_GO_BRIDGE_H
#define SILO_GO_BRIDGE_H

#include "../../native/include/silo_go_ffi.h"

char *bridge_load(const char *path);
uint32_t bridge_abi_version(void);
const char *bridge_sdk_version(void);
void bridge_string_free(char *value);
void bridge_buffer_free(silo_buffer value);
void bridge_error_free(silo_error *error);

silo_error *bridge_runtime_open(const uint8_t *request, size_t request_len, silo_runtime **out_runtime);
void bridge_runtime_free(silo_runtime *runtime);
silo_error *bridge_runtime_machine_create(const silo_runtime *runtime, const uint8_t *request, size_t request_len, silo_machine **out_machine);
silo_error *bridge_runtime_machine_get(const silo_runtime *runtime, const uint8_t *reference, size_t reference_len, silo_machine **out_machine);
silo_error *bridge_runtime_machines(const silo_runtime *runtime, silo_machine_handle_list *out_machines);
silo_error *bridge_images_call(const silo_runtime *runtime, const uint8_t *request, size_t request_len, silo_buffer *out_data);
silo_machine *bridge_machine_handle_list_at(const silo_machine_handle_list *machines, size_t index);
void bridge_machine_handle_list_free(silo_machine_handle_list machines);
void bridge_machine_free(silo_machine *machine);
silo_error *bridge_machine_id(const silo_machine *machine, silo_buffer *out_id);
silo_error *bridge_machine_inspect(const silo_machine *machine, silo_buffer *out_data);
silo_error *bridge_machine_start(const silo_machine *machine, silo_buffer *out_data);
silo_error *bridge_machine_stop(const silo_machine *machine, silo_buffer *out_data);
silo_error *bridge_machine_remove(const silo_machine *machine);
silo_error *bridge_machine_exec(const silo_machine *machine, const uint8_t *request, size_t request_len, silo_execution_output *out_output);
silo_error *bridge_machine_shell(const silo_machine *machine, const uint8_t *request, size_t request_len, silo_execution_output *out_output);
silo_error *bridge_machine_spawn(const silo_machine *machine, const uint8_t *request, size_t request_len, silo_execution **out_session);
silo_error *bridge_machine_attach(const silo_machine *machine, const uint8_t *request, size_t request_len, silo_buffer *out_result);
silo_error *bridge_machine_attach_shell(const silo_machine *machine, const uint8_t *request, size_t request_len, silo_buffer *out_status);
silo_error *bridge_execution_recv(const silo_execution *session, silo_execution_event *out_event, _Bool *out_eof);
silo_error *bridge_execution_wait(const silo_execution *session, silo_buffer *out_result);
silo_error *bridge_execution_collect(const silo_execution *session, silo_execution_output *out_output);
silo_error *bridge_execution_stdin(const silo_execution *session, silo_stdin **out_stdin);
silo_error *bridge_execution_signal(const silo_execution *session, uint32_t signal);
silo_error *bridge_execution_resize_pty(const silo_execution *session, uint16_t rows, uint16_t columns);
silo_error *bridge_execution_close_requests(const silo_execution *session);
silo_error *bridge_execution_cancel(const silo_execution *session);
void bridge_execution_free(silo_execution *session);
silo_error *bridge_stdin_write(const silo_stdin *stdin_handle, const uint8_t *data, size_t data_len);
silo_error *bridge_stdin_close(const silo_stdin *stdin_handle);
void bridge_stdin_free(silo_stdin *stdin_handle);
silo_error *bridge_machine_logs(const silo_machine *machine, const uint8_t *request, size_t request_len, silo_log **out_log);
silo_error *bridge_log_recv(const silo_log *log, silo_log_chunk *out_chunk, _Bool *out_eof);
silo_error *bridge_log_close(const silo_log *log);
void bridge_log_free(silo_log *log);
silo_error *bridge_network_policy_build(const uint8_t *request, size_t request_len, silo_buffer *out_policy);

#endif
