#include "elfmod.h"

/* PT_PAX_FLAGS */
#define PT_PAX PT_LOOS + 0x5041580

/* return segment type based on section index */
int GetSegByIndex(Elf32mem_t *target, int index)
{
	int i;
	Elf32_Addr saddr;

	for (i = 0; i < target->ehdr->e_shnum; i++)
		if (i == index)
		{
			saddr = target->shdr[i].sh_addr;	
			break;
		}
	
	for (i = 0; i < target->ehdr->e_phnum; i++)
	{
		if (saddr >= target->phdr[i].p_vaddr && saddr <= (target->phdr[i].p_vaddr + target->phdr[i].p_filesz) 
			&& target->phdr[i].p_type == PT_LOAD)		
		{
			if (target->phdr[i].p_offset == 0 && target->phdr[i].p_flags & PF_X)
				return TEXT;
			else
			if (target->phdr[i].p_offset != 0 && target->phdr[i].p_flags == (PF_R | PF_W))
				return DATA;
			else continue;
		} 
	}

	return 0;
}


int extend_PT_LOAD(Elf32mem_t *target, uint32_t len, char type)
{
	int i, ret = 0;
	
	if (type == 0)
		return 0;

	switch(type)
	{
	case TEXT:
		for (i = 0; i < target->ehdr->e_phnum; i++)
			if (target->phdr[i].p_type == PT_LOAD && target->phdr[i].p_offset == 0)
			{
				target->phdr[i].p_filesz += len;
				target->phdr[i].p_memsz += len;	
				ret++;
				break;
			}
		break;
	case DATA:
	        for (i = 0; i < target->ehdr->e_phnum; i++)
                        if (target->phdr[i].p_type == PT_LOAD && target->phdr[i].p_offset)
                        {
                                target->phdr[i].p_filesz += len;
                                target->phdr[i].p_memsz += len;
				ret++;
                                break;
                        }
                break;
	}
	
	return ret;
}

int WhichSegment(Elf32mem_t *target, Elf32_Addr vaddr)
{
	Elf32_Addr text_base, data_base, data_end;
	int i;

	text_base = GetBase(target, TEXT);
	data_base = GetBase(target, DATA);

	if (text_base == 0 || data_base == 0)
		return 0;
	
	if (vaddr >= text_base && vaddr < data_base)
		return TEXT;
	else
	{
		for (i = 0; i < target->ehdr->e_phnum; i++)
			if ((target->phdr[i].p_offset == 0 || target->phdr[i].p_offset == 0x1000) && target->phdr[i].p_type == PT_LOAD)
			{
				data_end = target->phdr[i + 1].p_vaddr + target->phdr[i + 1].p_offset;
				break;
			}
		if (vaddr >= data_base && vaddr < data_end)				
			return DATA;
		else
			/* Outside of range */
			return -1;
	}
}		

	
Elf32_Addr GetBase(Elf32mem_t *target, int which)
{
	int i;
	
	for (i = 0; i < target->ehdr->e_phnum; i++)
		if ((target->phdr[i].p_offset == 0 || target->phdr[i].p_offset == 0x1000) && target->phdr[i].p_type == PT_LOAD)
		{
			if (which == TEXT)
				return target->phdr[i].p_vaddr;
			else
			if (which == DATA)
				return target->phdr[i+1].p_vaddr;
			else
				return 0;	
		}
	return 0;
}


int dump_phdrs(Elf32mem_t *target)
{
	int i;
	char type[32] = {0};
	char interp[MAXSTR];

	printf("Type\t\tOffset   VirtAddr   PhysAddr   FileSiz MemSiz Flg Align\n");
	for (i = 0; i < target->ehdr->e_phnum; i++)
	{
		switch(target->phdr[i].p_type)	
		{
			case PT_NULL:
				strcpy(type, "NULL");
				break;
			case PT_LOAD:
				strcpy(type, "LOAD");
				break;
			case PT_DYNAMIC:
				strcpy(type, "DYNAMIC");
				break;
			case PT_INTERP:
				strcpy(type, "INTERP");
				strncpy(interp, &target->mem[target->phdr[i].p_offset], MAXSTR-1);
				break;
			case PT_NOTE:
				strcpy(type, "NOTE");
				break;
			case PT_SHLIB:
				strcpy(type, "SHLIB");
				break;
			case PT_PHDR:
				strcpy(type, "PHDR");
				break;
			case PT_TLS:
				strcpy(type, "TLS");
				break;
			case PT_NUM:
				strcpy(type, "NUM");
				break;
			case PT_GNU_EH_FRAME:
				strcpy(type, "GNU_EH_FRAME");
				break;
		 	case PT_GNU_STACK:
				strcpy(type, "GNU_STACK");
				break;
			case PT_GNU_RELRO:
				strcpy(type, "GNU_RELRO");
				break;
			
			case PT_PAX:
				strcpy(type, "PAX_FLAGS");
				break;
			
		}
		
		if (strlen(type) > 7)
			printf("%s\t0x%06x 0x%08x 0x%08x 0x%05x 0x%05x %c%c%c 0x%04x\n",
			type, target->phdr[i].p_offset, target->phdr[i].p_vaddr,
			target->phdr[i].p_paddr, target->phdr[i].p_filesz, target->phdr[i].p_memsz,
			(target->phdr[i].p_flags & PF_R) ? 'R' : ' ',
			(target->phdr[i].p_flags & PF_W) ? 'W' : ' ',
			(target->phdr[i].p_flags & PF_X) ? 'E' : ' ',
			target->phdr[i].p_align); 
		else
			printf("%s\t\t0x%06x 0x%08x 0x%08x 0x%05x 0x%05x %c%c%c 0x%04x\n",
                        type, target->phdr[i].p_offset, target->phdr[i].p_vaddr,
                        target->phdr[i].p_paddr, target->phdr[i].p_filesz, target->phdr[i].p_memsz,
                        (target->phdr[i].p_flags & PF_R) ? 'R' : ' ',
                        (target->phdr[i].p_flags & PF_W) ? 'W' : ' ',
                        (target->phdr[i].p_flags & PF_X) ? 'E' : ' ',
                        target->phdr[i].p_align);
			
		if (target->phdr[i].p_type == PT_INTERP)
			printf("\tRequesting Interpreter: %s\n", interp);

			memset(type, 0, 32);
	}
}

