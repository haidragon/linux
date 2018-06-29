/*
 *  Part of AntiVirus UNIX 
 *  Author: Ryan O'Neill <ryan@bitlackeys.com>
 * 
 *  This code does basic ELF integrity checks, mainly to determine the 
 *  state of the binary before inspecting it for infection 	
 */

#include "avu.h"

struct oddity_count
{
	char **msg;
	int index;
	int severity[3];
	int msg_size;
	char name[50];
	int check;
} elfhdr[3];

struct options opts;
/* it is not wise to print every potential oddity as soon as found */
/* so we have a message buffer to keep track of the oddity types */
/* based on elf header type: P (phdr) S (shdr) E (ehdr), and severity */
/* level. Severity level is purely determined by how the potential oddity */
/* might affect the AV code from running (i.e corrupt section headers could */
/* cause a memcpy() from segfaulting) */

int add_msg(int type, int severity, char *fmt, ...)
{

	char msg[MAXBUF];
	
	va_list va;
	va_start(va, fmt);
	vsnprintf(msg, MAXBUF-1, fmt, va);
	va_end(va);
	
	elfhdr[type].msg[elfhdr[type].index] = strdup(msg);
	elfhdr[type].msg_size += sizeof(char *);
	elfhdr[type].check++;
	elfhdr[type].severity[elfhdr[type].index] = severity;
	elfhdr[type].index++;

	if((elfhdr[type].msg = realloc(elfhdr[type].msg, elfhdr[type].msg_size)) == NULL)
	{
		perror("add_msg() - calloc()");
		exit(-1);
        }
	return 1;
	
}

/* returning -1 means that the file can't be fully analyzed */
int integrity_check(unsigned char *mem, char *filename)
{
	Elf32_Ehdr *ehdr;
	Elf32_Shdr *shdr;
	Elf32_Phdr *phdr;

	ehdr = (Elf32_Ehdr *)mem;
	phdr = (Elf32_Phdr *)(mem + ehdr->e_phoff);
	shdr = (Elf32_Shdr *)(mem + ehdr->e_shoff);
	
	int i, j, k, phindex, shindex, tmp, ret, sev = 1;
	int msg_size = 2;

	/* initialize msg buffer system */
	for (i = 0; i < 3; i++)
	{
		if((elfhdr[i].msg = calloc(2, sizeof(char *))) == NULL)
		{
			perror("integrity_check - calloc()");
			exit(-1);
		}
		elfhdr[i].check = 0;
		elfhdr[i].index = 0;
		elfhdr[i].msg_size = 4 << 1;
		
	}
	strcpy(elfhdr[E].name, "Elf Ehdr"); 
	strcpy(elfhdr[P].name, "Elf Phdr");				
	strcpy(elfhdr[S].name, "Elf Shdr"); 

        if (ehdr->e_ident[0] != 0x7f && strcmp(&ehdr->e_ident[1], "ELF"))
		return -1;
	
	if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN)
		return -1; 

	if (ehdr->e_ident[4] != ELFCLASS32 && ehdr->e_ident[5] != ELFDATA2LSB && ehdr->e_ident[6] != EV_CURRENT)
		return -1;

	if (ehdr->e_machine != EM_386 && ehdr->e_machine != EM_860)
		return -1;

	/* --- check validity of program headers --- */

	if (ehdr->e_phentsize != sizeof(Elf32_Phdr))
	{
		if((tmp = (ehdr->e_phentsize < sizeof(Elf32_Phdr)) ? 0 : 1) == 0)
			add_msg(P, SEV1, "Phdr size is unusually small");
		else
			add_msg(P, SEV1, "Phdr size is unusually large");
	}
	
	if (ehdr->e_phnum <= 0)
	{
		if (opts.verbose)
			printf("File: %s - Cannot view program headers (e_hdr->e_phnum is zero or less)\n", filename);
		return SEV1;
	}
	
	if (ehdr->e_phnum > 10)
		add_msg(P, SEV3, "Number of Phdrs exceeds the usual: %d\n", ehdr->e_phnum);
	
	if (ehdr->e_phoff == 0 || ehdr->e_phoff > 0xf0000000)
	{
			printf("File: %s - Cannot view program headers (e_hdr->e_phoff is illogical)\n", filename);
			return SEV1;
		}

		phindex = 1;
		pt_interp = 0;
		for (i = ehdr->e_phnum; i-- > 0; phdr++)
		{	
			if (phdr->p_type == PT_LOAD)
				if ((phdr->p_vaddr % 4096) != (phdr->p_offset % 4096))
					add_msg(P, SEV3, "Phdr %d does not have an offset/vaddr that are congruent (mod PAGE_SIZE)\n", phindex);
			
			if (phdr->p_type == PT_INTERP)
				pt_interp = 1;

			if (phdr->p_type > 8 && phdr->p_type != PT_LOOS && phdr->p_type != PT_HIOS && phdr->p_type != PT_LOPROC
			&& phdr->p_type != PT_HIPROC && phdr->p_type != PT_GNU_EH_FRAME && phdr->p_type != PT_GNU_STACK 
			&& phdr->p_type != PT_GNU_RELRO && phdr->p_type != PT_LOSUNW && phdr->p_type != PT_SUNWBSS 
			&& phdr->p_type != PT_SUNWSTACK && phdr->p_type != PT_HISUNW && phdr->p_type != PAXFLAGS)
				add_msg(P, SEV3, "Phdr %d is an unknown type of segment (p_type is unknown: %x)\n",phindex, phdr->p_type);
			
			if (phdr->p_type == PT_LOAD && phdr->p_flags == (PF_R | PF_X))
			{
				if (ehdr->e_type == ET_EXEC)
				{
					if (phdr->p_vaddr != TEXT_VADDR /* 8048000 */ && phdr->p_vaddr < 0xc0000000)
						add_msg(P, (phdr->p_vaddr == 0) ? SEV1 : SEV3, "text segment has an unusual virtual address: %x\n", phdr->p_vaddr);
					else
					if (phdr->p_vaddr != TEXT_VADDR /* 8048000 */ && phdr->p_vaddr > 0xc0000000)
						add_msg(P, SEV1, "text segment shows a virtual address that lies at the beginning of kernel memory (vmlinux?): %x\n", phdr->p_vaddr);
					if (phdr->p_offset)		
						add_msg(P, SEV3, "text segment has a p_offset larger than zero: %d\n", phdr->p_offset);
				}
			}

			if (phdr->p_filesz > phdr->p_memsz)
				add_msg(P, SEV3, "Phdr %d has a file size larger than its memory size\n", phindex);
			phindex++;

			if (phdr->p_align > 1)
				if (phdr->p_align % 2)	
					add_msg(P, SEV3, "Phdr %d has an alignment not of a power of two: %d\n", phdr->p_align);
			
		} 
		
	/* --- check validity of section headers */
	
	if (ehdr->e_shoff == 0 || ehdr->e_shoff > 0xf0000000)
	{
		if (opts.verbose)
			printf("File: %s - Cannot view section headers (e_hdr->e_shoff is not logical)\n", filename);
              		return SEV1;
	}
	if (ehdr->e_shentsize != sizeof(Elf32_Shdr))
        {
                if((tmp = (ehdr->e_shentsize < sizeof(Elf32_Shdr)) ? 0 : 1) == 0)
                        add_msg(P, SEV1, "Shdr size is unusually small");
                else
                        add_msg(P, SEV2, "Shdr size is unusually large");
        }

	if (ehdr->e_shnum == 0)
        {
                if (opts.verbose)
                        printf("File: %s - Cannot view section headers (e_hdr->e_phnum is zero)\n", filename);
                return SEV1;
        }
        
        if (ehdr->e_shnum > 40)
                add_msg(S, SEV2, "Number of Shdrs exceeds the usual: %d\n", ehdr->e_shnum);
	
	if (ehdr->e_shstrndx != SHN_UNDEF) 
		if (ehdr->e_shstrndx > ehdr->e_shnum)
		/* avu requires the string table, hence the SEV1 */
			add_msg(S, SEV1, "String table index %d exceeds section count %d\n", ehdr->e_shstrndx, ehdr->e_shnum);

	shindex = 1;
	for (i = ehdr->e_shnum; i-- > 0; shdr++)
	{
		if (shdr->sh_type > 19 && shdr->sh_type != SHT_LOOS && shdr->sh_type != SHT_GNU_HASH
		&& shdr->sh_type != SHT_GNU_LIBLIST && shdr->sh_type != SHT_CHECKSUM && shdr->sh_type != SHT_LOSUNW
		&& shdr->sh_type != SHT_SUNW_move && shdr->sh_type != SHT_SUNW_COMDAT && shdr->sh_type != SHT_SUNW_syminfo 
		&& shdr->sh_type != SHT_GNU_verdef && shdr->sh_type != SHT_GNU_verneed && shdr->sh_type != SHT_GNU_versym
		&& shdr->sh_type != SHT_HISUNW && shdr->sh_type != SHT_HIOS && shdr->sh_type != SHT_LOPROC   
		&& shdr->sh_type != SHT_HIPROC && shdr->sh_type != SHT_LOUSER && shdr->sh_type != SHT_HIUSER)
		 	/* if the 1st section header is an invalid type, then there may be corruption */
			/* and this could cause avu to crash, if the first section header is ok, then the chances */
			/* of the others being corrupt is more slim and more likely to be of a different sh_type for */
			/* different reasons, like an evil section added to account for a parasite */
			add_msg(S, (shindex == 1) ? SEV1 : SEV2, "Shdr %d is an invalid type of section (sh_type is unknown)\n", shindex);
	
	}
	
	print_summary:

	for (i = 0; i < 3; i++)
	{ 
		if (elfhdr[i].index > 0)
		{ 
			printf("\n[%s] - %s Summary: %d oddities\n",filename, elfhdr[i].name, elfhdr[i].check);
		
			for (j = 0; j < elfhdr[i].index; j++)
			{
				printf("\n%s - Severity level: %i\n", elfhdr[i].msg[j], elfhdr[i].severity[j]);
				free(elfhdr[i].msg[j]);
			}
		} 
		
 	}		
	
	for (i = 0; i < 3; i++)
	{
		for (j = 0; j < elfhdr[i].index; j++)
		{
			if (j == elfhdr[i].index && sev == 1)
			{
				j = 0;
				sev = 2;
				continue;
			} 
			else
			if (j == elfhdr[i].index && sev == 2)
			{
				j = 0;
				sev = 3;	
				continue;
			}
			if (sev == 1)
			{
				if (elfhdr[i].severity[j] == SEV1)
					return SEV1;
			}
			else
			if (sev == 2)
				if (elfhdr[i].severity[j] == SEV2)
					return SEV2;
			else
			if (sev == 3)
				if (elfhdr[i].severity[j] == SEV3)
					return SEV3;
		}
			
		
	}
			
	return 0;
}

