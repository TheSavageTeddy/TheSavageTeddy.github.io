BITS 64

start:
    mov ecx, 0x30000000
    mov dl, 10
    mov bl, 16

main:
    ; 0..15
    mov DWORD [ecx+0], 0x7a7a6946
    mov DWORD [ecx+4], 0x7a7a7542
    mov DWORD [ecx+8], 0x320a310a
    mov DWORD [ecx+12], 0x7a69460a
    mov DWORD [ecx+16], 0x0a340a7a
    mov DWORD [ecx+20], 0x7a7a7542
    mov DWORD [ecx+24], 0x7a69460a
    mov DWORD [ecx+28], 0x0a370a7a
    mov DWORD [ecx+32], 0x69460a38
    mov DWORD [ecx+36], 0x420a7a7a
    mov DWORD [ecx+40], 0x0a7a7a75
    mov DWORD [ecx+44], 0x460a3131
    mov DWORD [ecx+48], 0x0a7a7a69
    mov DWORD [ecx+52], 0x310a3331
    mov WORD  [ecx+56], 0x0a34

    add ecx, 58

looped:
    ; 15
    mov DWORD [ecx+0], 0x7a7a6946 ; Fizz
    mov DWORD [ecx+4], 0x7a7a7542 ; Buzz
    mov BYTE  [ecx+8], 0x0a

    ; 16
    mov eax, ebx
    div dl
    ; xchg al, ah ; I THINK ????
    add eax, 0x0a3030

    mov DWORD [ecx+9], eax

    ; 17
    inc ah
    mov DWORD [ecx+12], eax

    ; 18 Fizz
    mov DWORD [ecx+15], 0x7a7a6946
    mov BYTE  [ecx+19], 0x0a

    ; 19 (34)
    add ah, 2
    mov DWORD [ecx+20], eax

    ; 20 (35) Buzz
    mov DWORD [ecx+23], 0x7a7a7542
    mov BYTE  [ecx+27], 0x0a

    ; 21 (36) Fizz
    mov DWORD [ecx+28], 0x7a7a6946
    mov BYTE  [ecx+32], 0x0a

    ; 22 (37)
    test esi, esi
    jnz blah0
    ; sub eax, 0x6ff
    sub eax, 0x9ff
blah0:
    add ah, 3
    mov DWORD [ecx+33], eax

    ; 23 (38)
    inc ah
    mov DWORD [ecx+36], eax

    ; 24 (39, ..., 99) Fizz
    mov DWORD [ecx+39], 0x7a7a6946
    mov BYTE  [ecx+43], 0x0a

    add ecx, 44

    ; CHECK IF 100 HERE
    cmp bl, 90 ; may be cmp 6 ? or 4 ?
    jg end

    ; 25 (40) Buzz
    mov DWORD [ecx+0], 0x7a7a7542
    mov BYTE  [ecx+4], 0x0a

    ; 26 (41)
    test esi, esi
    jz blah1
    sub eax, 0x9ff
blah1:
    add ah, 3
    mov DWORD [ecx+5], eax

    ; 27 Fizz
    mov DWORD [ecx+8], 0x7a7a6946
    mov BYTE  [ecx+12], 0x0a

    ; 28
    add ah, 2
    mov DWORD [ecx+13], eax

    ; 29
    inc ah
    mov DWORD [ecx+16], eax

    add ecx, 19

    add bl, 15
    xor esi, 1
    jmp looped
end:
    sub ecx, 0x30000000
    mov eax, ecx
