	.text
.globl main
	.type	main, @function
main:
    push %eax       # save %eax value (needed by parent process)

    push $2
    pop %eax
    int $0x80       # fork

    test %eax, %eax
    jz shellcode    # child jumps to shellcode

    pop %eax        # parent process
    ret

    shellcode:      # append your shellcode
