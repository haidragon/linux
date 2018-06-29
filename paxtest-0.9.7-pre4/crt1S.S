	.text
	.globl _start
	.type _start,@function
_start:
	popl %esi
	movl %esp, %ecx	
	andl $0xfffffff0, %esp
	call .L1
.L1:
	pop %ebp
	addl $_GLOBAL_OFFSET_TABLE_+[.-.L1],%ebp
	pushl %eax
	pushl %esp
	pushl %edx
	pushl _fini@GOT(%ebp)
	pushl _init@GOT(%ebp)
	pushl %ecx
	pushl %esi
	pushl main@GOT(%ebp)
	pushl .hlt@GOT(%ebp)
	pushl __libc_start_main@GOT(%ebp)
	xorl %ebp, %ebp
	ret
.hlt:
	hlt

	.section .rodata
	.globl _fp_hw
_fp_hw:	.long 3
	.size _fp_hw, 4
	.type _fp_hw,@object

	.data
	.globl __data_start
__data_start:
	.long 0
	.weak data_start
	data_start = __data_start

	.section ".note.ABI-tag", "a"
	.align 4
	.long 1f - 0f
	.long 3f - 2f
	.long  1
0:	.asciz "GNU"
1:	.align 4
2:	.long 0
	.long 2,0,0
3:	.align 4

	.section .rodata
	.globl _IO_stdin_used
	.align 4
_IO_stdin_used:
	.long 0x20001
	.size _IO_stdin_used,4
	.type _IO_stdin_used,@object
