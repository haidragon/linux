
#include "avu.h"

extern int global_force_elf;
int IsElf(uint8_t *mem)
{
	Elf32_Ehdr *ehdr = (Elf32_Ehdr *)mem;
	
        if (ehdr->e_ident[0] != 0x7f && strcmp(&ehdr->e_ident[1], "ELF"))
		return 0;

        if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN && ehdr->e_type != ET_REL && ehdr->e_type != ET_CORE && ehdr->e_type != ET_NONE)
	       	return 0;
        
	if (ehdr->e_ident[4] != ELFCLASS32 && ehdr->e_ident[5] != ELFDATA2LSB && ehdr->e_ident[6] != EV_CURRENT)
	        return 0;
        
	if (ehdr->e_machine != EM_386 && ehdr->e_machine != EM_860)
	        return 0;
	
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

	for (i = 0; i < elf->ehdr->e_shnum; i++)
		free(elf->section[i]);
	munmap(elf->mem, elf->size);
}

