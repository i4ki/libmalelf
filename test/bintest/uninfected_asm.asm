BITS 32
	SECTION .data
hello_str:	db "I'm uninfected...",0xa
	SECTION .text
	global _start
	
_start:
	mov ecx, hello_str
	mov edx, 18
	mov ebx, 1
	mov eax, 4
	int 0x80

	xor eax, eax
	inc eax
	xor ebx, ebx
	int 0x80
	
	