
#include "elfmod.h"

extern int global_debug, global_force_elf;

char mmap_shellcode[] =
        "\xe9\x3b\x00\x00\x00\x31\xc9\xb0\x05\x5b\x31\xc9\xcd\x80\x83\xec"
        "\x18\x31\xd2\x89\x14\x24\xc7\x44\x24\x04\x00\x20\x00\x00\xc7\x44"
        "\x24\x08\x07\x00\x00\x00\xc7\x44\x24\x0c\x02\x00\x00\x00\x89\x44"
        "\x24\x10\x89\x54\x24\x14\xb8\x5a\x00\x00\x00\x89\xe3\xcd\x80\xcc"
        "\xe8\xc0\xff\xff\xff\x2f\x6c\x69\x62\x2f\x6c\x69\x62\x74\x65\x73"
        "\x74\x2e\x73\x6f\x2e\x31\x2e\x30\x00";

int IsElf(uint8_t *mem)
{
	Elf32_Ehdr *ehdr = (Elf32_Ehdr *)mem;
	
        if (ehdr->e_ident[0] != 0x7f && strcmp(&ehdr->e_ident[1], "ELF"))
  	{
		if (global_debug)
			printf("File is missing ELF magic\n");
		return 0;
	}

        if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN && ehdr->e_type != ET_REL && ehdr->e_type != ET_CORE && ehdr->e_type != ET_NONE)
        {
		if (global_debug)
			printf("File is not any of the following ELF types: EXEC, DYN, REL, CORE, NONE\n");
	       	return 0;
	}
        if (ehdr->e_ident[4] != ELFCLASS32 && ehdr->e_ident[5] != ELFDATA2LSB && ehdr->e_ident[6] != EV_CURRENT)
        {
		if (global_debug)
			printf("File does not have any of the following ELF idents: ELFCLASS32, ELFDATA2LSB, EV_CURRENT\n");
	        return 0;
	}
        if (ehdr->e_machine != EM_386 && ehdr->e_machine != EM_860)
        {
		if (global_debug)
			printf("File is not any of the following machine types: i386, 860\n");
	        return 0;
	}
	return 1;
}

int build_sections(uint8_t ***sp, int8_t *mem)
{
	Elf32_Ehdr *ehdr = (Elf32_Ehdr *)mem;
	Elf32_Shdr *shdr = (Elf32_Shdr *)(mem + ehdr->e_shoff);
	int i;

	if ((*sp = (uint8_t **)calloc(ehdr->e_shnum, sizeof(uint8_t *))) == NULL)
		return -1;
	
	for (i = 0; i < ehdr->e_shnum; i++, shdr++)
	{
		if((*((*sp) + i) = malloc(shdr->sh_size)) == NULL)
			return -1;
		memcpy(*((*sp) + i), &mem[shdr->sh_offset], shdr->sh_size);
	}
	return 0;
}
	
/* like ElfDup(&elf1, &elf2, ELFDUP_CLOSE); */
int ElfReload(Elf32mem_t *elf)
{
	int type = elf->elf_type;
	int size = elf->size;

	char name[MAXSTR];
	strcpy(name, elf->name);

	UnloadElf(elf);
        
	if(LoadElf(name, MAP_SHARED, PROT_READ|PROT_WRITE, 0, 0, elf) == -1)
		return -1;
	return 0;

}

/* similar to dup() this duplicates an ELF descriptor, but reflects */
/* any new changes to the file, whereas the current desc. doesn't always */
int ElfDup(Elf32mem_t *elf, Elf32mem_t *newelf, int dupflag)
{
	int fd;
	uint8_t *mem;
	struct stat st;

	if ((fd = open(elf->name, O_RDWR)) == -1)
		return -1;
	
	if (fstat(fd, &st) < 0)
		return -1;

	mem = mmap((void *)NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (mem == MAP_FAILED)
		return -1;
	
	strcpy(newelf->name, elf->name);

	newelf->mode = st.st_mode;
	newelf->size = st.st_size;
        
	newelf->mem = mem;
	newelf->ehdr = (Elf32_Ehdr *)mem;
        newelf->shdr = (Elf32_Shdr *)(mem + elf->ehdr->e_shoff);
        newelf->phdr = (Elf32_Phdr *)(mem + elf->ehdr->e_phoff);

        build_sections(&elf->section, mem);
	close(fd);

	/* close previous descriptor */
	if (dupflag == ELFDUP_CLOSE)
		UnloadElf(elf);	

	return 0;

}

/* we use msync to commit changes that don't require file size extension */
int CommitChanges(Elf32mem_t *target)
{
	if (msync(target->mem, target->size, MS_SYNC) == -1)
	{
		perror("msync:");
		return -1;
	}
	return 0;
}


int LoadElf(char *name, int flags, int protect, Elf32_Addr vaddr, Elf32_Off offset, Elf32mem_t *elf)
{
        int fd;
        uint8_t *mem;
        struct stat st;
	int i;

        strncpy(elf->name, name, 254);
       
	if ((fd = open(name, O_RDWR)) == -1)
        {
                perror("LoadElf() open");
                return -1;
        }

        if (fstat(fd, &st) < 0)
        {
                perror("LoadElf() fstat");
                return -1;
        }

        mem = mmap((void *)vaddr, st.st_size, protect, flags, fd, offset);
        if (mem == MAP_FAILED)
        {
                perror("LoadElf() mmap");
                return -1;
        }
	
	if (global_force_elf == 0)
        	if (!IsElf(mem))
                	return -1;
	
        elf->size = st.st_size;
        elf->mode = st.st_mode;
        elf->mem = mem;
        elf->ehdr = (Elf32_Ehdr *)(mem);
        elf->shdr = (Elf32_Shdr *)(mem + elf->ehdr->e_shoff);
        elf->phdr = (Elf32_Phdr *)(mem + elf->ehdr->e_phoff);
	elf->elf_type = elf->ehdr->e_type;

	/* Define PT_LOAD vaddrs and offsets */
	for (i = 0; i < elf->ehdr->e_phnum; i++)
	{
		if (elf->phdr[i].p_offset == 0 || elf->phdr[i].p_offset == 0x1000)
			if (elf->phdr[i].p_type == PT_LOAD && (elf->phdr[i].p_flags & PF_X))
			{
				elf->text_vaddr = elf->phdr[i].p_vaddr;
				elf->text_offset = elf->phdr[i].p_offset;
				elf->text_filesz = elf->phdr[i].p_filesz;
				elf->text_memsz = elf->phdr[i].p_memsz;
				
				if (elf->phdr[i + 1].p_type == PT_LOAD)
				{
					elf->data_vaddr = elf->phdr[i + 1].p_vaddr;
					elf->data_offset = elf->phdr[i + 1].p_offset;
					elf->data_filesz = elf->phdr[i + 1].p_filesz;
					elf->data_memsz = elf->phdr[i + 1].p_memsz;
				}
				break;
			}
	}
	
	elf->typestr[0] = strdup("ET_NONE");
	elf->typestr[1] = strdup("ET_REL");
	elf->typestr[2] = strdup("ET_EXEC");
	elf->typestr[3] = strdup("ET_DYN");
	elf->typestr[4] = strdup("ET_CORE");

        build_sections(&elf->section, mem);

        close(fd);
	return 1;
}

void UnloadElf(Elf32mem_t *elf)
{
	int i;
	if (!elf)
		return;

	//for (i = 0; i < elf->ehdr->e_shnum; i++)
	//	free(elf->section[i]);
	//free(elf->section);
	munmap(elf->mem, elf->size);
}

uint8_t *
allocate_memory (uint32_t size, int protect, Elf32_Addr vaddr, int stack_flag, int fd)
{
        uint8_t *mem;
        long flags;
        int i;
	
        if (stack_flag)
                flags = (MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS | MAP_GROWSDOWN);
        else
                flags = (vaddr ? (MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS)
                       : (MAP_PRIVATE | MAP_ANONYMOUS));

        mem = mmap ((void *) vaddr, size, protect, flags, fd, 0);
        if (mem == MAP_FAILED)
        {
                perror ("allocate_memory() mmap");
                return NULL;
        }
        return mem;
}

