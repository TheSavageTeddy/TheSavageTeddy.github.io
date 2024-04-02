BITS 64

start:
    rdtsc
    and eax, 0b10
    shr al, 1
    xchg eax, ebx

    xor ecx, 0b11111111_11111111_11111111_11111111
    xor ecx, 0b11001111_11111111_11111111_11111111

    mov [ecx], bl
    xor al, 0b11111111
    xor al, 0b11111011
