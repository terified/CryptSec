section .data
    hello db 'Hello, World!', 0

section .bss

section .text
    global _start

_start:
    ; write our string to stdout
    mov eax, 4            ; sys_write
    mov ebx, 1            ; file descriptor 1 is stdout
    mov ecx, hello        ; put our string's address in ecx
    mov edx, 13           ; number of bytes
    int 0x80              ; call the kernel

    ; exit
    mov eax, 1            ; sys_exit
    xor ebx, ebx          ; exit code 0
    int 0x80              ; call the kernel