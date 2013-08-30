        ;; Simple asm that prints 1337 on screen
        ;; Should not be used with a INFECT example!!!

        ;; WARNING, remember that 0x37333331 is the
        ;; default malelficus magic number and if
        ;; used inside an asm code, the infector will
        ;; try to replace then with the entry point
        ;; of the host binary ... messing your binary!

        BITS 32

_start:
	mov ebp, esp
	push ebp

	push dword 0x37333331
	mov ecx, esp
	mov edx, 4
	mov ebx, 1
	mov eax, 4
	int 0x80

	mov ebx, 0
	mov eax, 1
	int 0x80
