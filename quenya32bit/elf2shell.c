#include "elfmod.h"

/* Function to extract the shellcode from an executable */
/* at a given location and length */
	
uint8_t * elf2shell(char *elf, Elf32_Addr start, Elf32_Addr stop, int8_t nojmp)
{
	int fd, i;
	uint8_t *mem, *shell;
	Elf32_Ehdr *ehdr;
	Elf32_Phdr *phdr;
	struct stat st;
	Elf32_Addr base;
	
	/* pushl $0x0; ret */
	unsigned char jmp_code[] = "\x68\x00\x00\x00\x00\xc3";

	if ((fd = open(elf, O_RDONLY)) == -1)
	{
		perror("open");
		return NULL;
	}

	if (fstat(fd, &st) < 0)
	{
		perror("fstat");
		return NULL;
	}

	mem = mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (mem == MAP_FAILED)
	{
		perror("mmap");
		return NULL;
	}
	
		
	if ((shell = malloc(stop - (start + 1) + sizeof(jmp_code))) == NULL)
	{
		perror("malloc");
		return NULL;
	}
	
	ehdr = (Elf32_Ehdr *)mem;

	if (!IsElf(ehdr))
	{
		printf("Target %s is not a valid ELF file\n", elf);
		return NULL;
	}

	/* ET_EXEC and ET_DYN have phdrs so we'll deal with vaddrs */
	if (ehdr->e_type != ET_REL)
	{
		phdr = (Elf32_Phdr *)(mem + ehdr->e_phoff);
	
		for (i = ehdr->e_phnum; i-- > 0; phdr++)
			if (phdr->p_offset == 0 && phdr->p_type == PT_LOAD)
			{
				base = phdr->p_vaddr;
				break;
			}
	  	memcpy(shell, mem + (start - base), stop - start);
	}
	else
	{
		/* ET_REL: if we're dealing with offsets rather than vaddrs */
		Elf32_Shdr *shdr = (Elf32_Shdr *)(mem + ehdr->e_shoff);
		char *StringTable = &mem[shdr[ehdr->e_shstrndx].sh_offset];
		for (i = 0; i < ehdr->e_shnum; i++, shdr++)
			if (!strcmp(&StringTable[shdr->sh_name], ".text"))
			{	
				base = shdr->sh_offset;
				break;
			}
		memcpy(shell, (mem + base + start), stop - start);
	}
	/* patch with jmp code */
	if (nojmp == 0)
		memcpy(&shell[sizeof(shell) - 6], jmp_code, 6);

	close(fd);
	munmap(mem, st.st_size);
	return shell;
}


