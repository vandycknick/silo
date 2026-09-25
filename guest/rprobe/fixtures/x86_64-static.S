.section .rodata
message:
    .ascii "SILO_X86_STATIC_OK\n"
message_end:

.section .text
.global _start
.type _start, @function
_start:
    mov $1, %eax
    mov $1, %edi
    lea message(%rip), %rsi
    mov $(message_end - message), %edx
    syscall
    cmp $(message_end - message), %eax
    jne write_failed

    mov $60, %eax
    mov $37, %edi
    syscall

write_failed:
    mov $60, %eax
    mov $111, %edi
    syscall
.size _start, . - _start
