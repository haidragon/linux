/*
 * Code for injection of relocatable code, performing relocations, and making necessary modifications
 * to the symbol table of the target ET_EXEC.
 */

#include "elfmod.h"

int ListRelEntry(Elf32mem_t *target, int index)
{
	struct linking_info *linfo;
	int i;

	linfo = (struct linking_info *)get_plt(target->mem);
	printf("r_offset    r_info    r_type\t\t Sym.Value  Name\n");
	if (linfo)
	{
		for (i = 0; i < linfo[0].count; i++)
		{
			if (linfo[i].r_type != R_386_NONE)
				printf("0x%08x 0x%08x ", linfo[i].r_offset, linfo[i].r_info);
			else continue;
			switch(linfo[i].r_type)
                        {
                        case R_386_JMP_SLOT:
                                printf("R_386_JUMP_SLOT\t ");
                                break;
                        case R_386_PC32:
                                printf("R_386_PC32\t ");
                                break;
                        case R_386_32:
                                printf("R_386_32\t\t ");
                                break;
                        case R_386_GOT32:
                                printf("R_386_GOT32\t ");
                                break;
                        case R_386_PLT32:
                                printf("R_386_PLT32\t ");
                                break;
                        case R_386_RELATIVE:
                                printf("R_386_RELATIVE\t ");
                                break;
                        case R_386_GOTOFF:
                                printf("R_386_GOTOFF\t ");
                                break;
                        case R_386_GOTPC:
                                printf("R_386_GOTPC\t ");
                                break;
                        case R_386_COPY:
                                printf("R_386_COPY\t ");
                                break;
                        case R_386_GLOB_DAT:
                                printf("R_386_GLOB_DAT\t ");
                                break;
                        }
                        printf("0x%08x %s\n", linfo[i].s_value, linfo[i].name);
		}	
	}
	linfo = (struct linking_info *)get_rel(target->mem);
        if (linfo)
        {
                for (i = 0; i < linfo[0].count; i++)
                {
			/* already got JMP_SLOT stuff from DYNSYM above */
			if (linfo[i].r_type != R_386_NONE && linfo[i].r_type != R_386_JMP_SLOT)
				printf("0x%08x 0x%08x ", linfo[i].r_offset, linfo[i].r_info);
			else continue;
			switch(linfo[i].r_type)
			{
			case R_386_PC32:
				printf("R_386_PC32\t ");
				break;
			case R_386_32:
				printf("R_386_32\t\t ");
				break;
			case R_386_GOT32:
				printf("R_386_GOT32\t ");
				break;
			case R_386_PLT32:
				printf("R_386_PLT32\t ");
				break;
			case R_386_RELATIVE:
				printf("R_386_RELATIVE\t ");
				break;
			case R_386_GOTOFF:
				printf("R_386_GOTOFF\t ");
				break;
			case R_386_GOTPC:
				printf("R_386_GOTPC\t ");
				break;
			case R_386_COPY:
				printf("R_386_COPY\t ");
				break;
			case R_386_GLOB_DAT:
				printf("R_386_GLOB_DAT\t ");
				break;
			}
			printf("0x%08x %s\n", linfo[i].s_value, linfo[i].name);
                }
        }


}
/* This function adds a new symbol to the target ELF file */
int AddSymbol(char *name, Elf32_Addr vaddr, Elf32_Sym *sym, Elf32mem_t *target)
{
	int i, symsiz = sizeof(Elf32_Sym);
	int fd, st_index;
	Elf32_Off symoff;
	uint32_t st_offset, st_start;
	int slen = strlen(name) + 1;
	name[strlen(name)] = '\0';

	char *TargetStbl = &target->mem[target->shdr[target->ehdr->e_shstrndx].sh_offset];
	
	if ((fd = open(TMP_FILE, O_CREAT | O_WRONLY | O_TRUNC, target->mode)) == -1)
		return EFILE_ERR;
	
	/* adjust symbol table */
	sym->st_value = vaddr;
	for (i = 0; i < target->ehdr->e_shnum; i++)
		if (target->shdr[i].sh_type == SHT_SYMTAB)
		{
			symoff = target->shdr[i].sh_offset + target->shdr[i].sh_size;
			target->shdr[i].sh_size += symsiz;
		 	while (i++ < target->ehdr->e_shnum)
				target->shdr[i].sh_offset += symsiz;
		}		
	
	/* get symbol (Not DYNSYM)  string table info and make any necessary mods to shdrs */
	for (i = 0; i < target->ehdr->e_shnum; i++)
		if (target->shdr[i].sh_type == SHT_STRTAB && i != target->ehdr->e_shstrndx && 
		strcmp(&TargetStbl[target->shdr[i].sh_name], ".dynstr"))
		{		
			st_offset = target->shdr[i].sh_offset + target->shdr[i].sh_size - symsiz;
			st_index = i;
			st_start = target->shdr[i].sh_size;
			
			target->shdr[i].sh_size += slen;
			break;
		}

	/* increase section header offsets after strtab shdr to account for new string */
	for (i = 0; i < target->ehdr->e_shnum; i++)
	{
		if (i > st_index)
		{
			target->shdr[i].sh_offset += slen;
			target->shdr[i].sh_addr += slen; 
		}
	}
	/* point symbol st_name to new string */
	sym->st_name = st_start;

	/* write first chunk up until end of symbol table */
	if (write(fd, target->mem, symoff) != symoff)
		return EFILE_ERR;
	
	/* write our new symbol */ 
	if (write(fd, sym, symsiz) != symsiz)
		return EFILE_ERR;
	
	/* write next chunk up until the end of string table */
	if (write(fd, (target->mem + symoff), st_offset - symoff) != st_offset - symoff)
		return EFILE_ERR;
	
	/* write new string at end of string table */
	if(write(fd, name, slen) != slen)
		return EFILE_ERR;
	
	/* write final chunk */
	if (write(fd, (target->mem + st_offset), target->size - st_offset) != target->size - st_offset)
		return EFILE_ERR;

	if(rename(TMP_FILE, target->name) < 0)
		return EFILE_ERR;
	close(fd);
	
	/* size must be adjusted if multiple calls */
	/* to AddSym() are called */
	target->size += symsiz;
	target->size += slen;

	return 1;
}

Elf32_Sym * GetSymByName(char *name, Elf32_Shdr *shdr, int c, uint8_t *objmem)
{
 	Elf32_Sym *symtab;
        Elf32_Shdr *shdrp;
        char *SymStrTable;
        int i, j, symcount;

        for (shdrp = shdr, i = 0; i < c; i++, shdrp++)
                if (shdrp->sh_type == SHT_SYMTAB)
                {
                        SymStrTable = &objmem[shdr[shdrp->sh_link].sh_offset];
                        symtab = (Elf32_Sym *)&objmem[shdrp->sh_offset];

                        for (j = 0; j < shdrp->sh_size / sizeof(Elf32_Sym); j++, symtab++)
                        {
                                if(strcmp(&SymStrTable[symtab->st_name], name) == 0)
                                        return symtab;
                        }
                }
        return NULL;
}

/* get symbol by name from SYMTAB (not DYNSYM) */
Elf32_Addr GetRelocSymAddr(char *name, Elf32_Shdr *shdr, int c, uint8_t *objmem)
{
	Elf32_Sym *symtab;
	Elf32_Shdr *shdrp;
	char *SymStrTable;
	int i, j, symcount;

	for (shdrp = shdr, i = 0; i < c; i++, shdrp++)
		if (shdrp->sh_type == SHT_SYMTAB)
		{
			SymStrTable = &objmem[shdr[shdrp->sh_link].sh_offset]; 
			symtab = (Elf32_Sym *)&objmem[shdrp->sh_offset];

			for (j = 0; j < shdrp->sh_size / sizeof(Elf32_Sym); j++, symtab++)
			{
				if(strcmp(&SymStrTable[symtab->st_name], name) == 0)
					return ((Elf32_Addr)shdr[symtab->st_shndx].sh_addr + symtab->st_value);
			}
		}	
	return 0;
}

int ElfRelocate(Elf32mem_t *target, char *name, int type /* TEXT_PADDING_INFECTION or DATA_INFECTION */)
{

        Elf32_Sym *symtab, *symbol;
        Elf32_Shdr *TargetSection;
        Elf32_Addr TargetAddr;
        Elf32_Addr *RelocPtr;
        Elf32_Addr RelVal;
        int TargetIndex;
        char *SymName;
	char *targname;
	int i, fd, symstrndx, j;
	struct stat st;
	Elf32_Addr objvaddr;
	Elf32mem_t dst;
	Elf32_Rel *rel;
	Elf32_Rela *rela;
	Elf32_Sym *sym;
	
	struct function_call
	{
		char *function;
		unsigned long vaddr;
	} function_call[4096 * 2];

	int fnc = 0;

	Elf32mem_t obj;
	char *SymStringTable;
	
	/* total length of object code */
	uint32_t totLen, secLen;
	uint8_t *ObjCode;

	/* Load the ET_REL file into memory as 'obj' */
	if(LoadElf(name, MAP_PRIVATE, PROT_READ|PROT_WRITE, 0, 0, &obj) == -1)
	{
		printf("Unable to load ELF object\n");
		return -1;
	}
	
	/* find how much memory to allocate for the object code and do so */
	for (i = 0, totLen = 0; i < obj.ehdr->e_shnum; i++)
		if (obj.shdr[i].sh_type == SHT_PROGBITS)
			totLen += obj.shdr[i].sh_size;
	if ((ObjCode = (uint8_t *)malloc(totLen)) == NULL)
		return EMALLOC;
	
	/* address to inject object code in target */
	objvaddr = target->phdr[TEXT].p_vaddr + target->phdr[TEXT].p_memsz;
	
	/* adjust section addresses */
	for (secLen = 0, i = 0; i < obj.ehdr->e_shnum; i++)
	{
		if (obj.shdr[i].sh_type == SHT_PROGBITS)
		{
			obj.shdr[i].sh_addr = objvaddr + secLen;
			secLen += obj.shdr[i].sh_size;
		}
	        if (obj.shdr[i].sh_type == SHT_STRTAB && i != obj.ehdr->e_shstrndx)
                	symstrndx = i;
	}
	SymStringTable = obj.section[symstrndx]; //&obj.mem[obj.shdr[symstrndx].sh_offset];
	/* PERFORM RELOCATIONS ON OBJECT CODE */
	for (i = 0; i < obj.ehdr->e_shnum; i++)
	{
		switch(obj.shdr[i].sh_type)
		{
		case SHT_REL:
			 rel = (Elf32_Rel *)(obj.mem + obj.shdr[i].sh_offset);
			 for (j = 0; j < obj.shdr[i].sh_size / sizeof(Elf32_Rel); j++, rel++)
			 {
			 	/* symbol table */ 
			 	symtab = (Elf32_Sym *)obj.section[obj.shdr[i].sh_link]; 
			
			 	/* symbol we are applying relocation to */
			 	symbol = &symtab[ELF32_R_SYM(rel->r_info)];
			
			 	/* section to modify */
			 	TargetSection = &obj.shdr[obj.shdr[i].sh_info];	
			 	TargetIndex = obj.shdr[i].sh_info;
			 
			 	/* target location */
			 	TargetAddr = TargetSection->sh_addr + rel->r_offset;
			 
				 /* pointer to relocation target */
			 	RelocPtr = (Elf32_Addr *)(obj.section[TargetIndex] + rel->r_offset);
			 
			 	/* relocation value */
			 	RelVal = symbol->st_value; 
			 	RelVal += obj.shdr[symbol->st_shndx].sh_addr;
			 	
				printf("0x%08x %s addr: 0x%x\n",RelVal, &SymStringTable[symbol->st_name], TargetAddr);
				
				/* gotta complete hueristics here so we know its a call */
				if (RelVal == 0)
				{
					function_call[fnc].function = strdup(&SymStringTable[symbol->st_name]);
					function_call[fnc].vaddr = TargetAddr;
					printf("function: %s\n", function_call[fnc].function);
					fnc++;

				}

				switch (ELF32_R_TYPE(rel->r_info)) 
			 	{
			 
				 /* R_386_PC32	    2    word32  S + A - P */ 
				 case R_386_PC32:
					*RelocPtr += RelVal;
				 	*RelocPtr -= TargetAddr;
					break;
	
				 /* R_386_32	    1    word32  S + A */
				 case R_386_32:
				 	*RelocPtr += RelVal;
					break;
				 } 
			}
			break;
		case SHT_RELA:
			 for (j = 0; j < obj.shdr[i].sh_size / sizeof(Elf32_Rela); j++, rela++)
			 {
		       	 	rela = (Elf32_Rela *)(obj.mem + obj.shdr[i].sh_offset);
	
       		                /* symbol table */
       	        	        symtab = (Elf32_Sym *)obj.section[obj.shdr[i].sh_link];
	
       	                  	/* symbol we are applying relocation to */
                         	symbol = &symtab[ELF32_R_SYM(rela->r_info)];

                        	/* section to modify */
                         	TargetSection = &obj.shdr[obj.shdr[i].sh_info];
                        	TargetIndex = obj.shdr[i].sh_info;

                         	/* target location */
 	                        TargetAddr = TargetSection->sh_addr + rela->r_offset;
	
       	          	        /* pointer to relocation target */
       		                RelocPtr = (Elf32_Addr *)(obj.section[TargetIndex] + rela->r_offset);
	
       	               	        /* relocation value */
       	                  	RelVal = symbol->st_value;
                         	RelVal += obj.shdr[symbol->st_shndx].sh_addr;

                        	switch (ELF32_R_TYPE(rela->r_info))
                         	{

                         	/* R_386_PC32      2    word32  S + A - P */
                         	case R_386_PC32:
                                	*RelocPtr += RelVal;
					*RelocPtr += rela->r_addend;
                                	*RelocPtr -= TargetAddr;
                                	break;

                         	/* R_386_32        1    word32  S + A */
                         	case R_386_32:
                                	*RelocPtr += RelVal;
					*RelocPtr += rela->r_addend;
                                	break;
				}
                         }
			 break;
		}
	}
	
        for (secLen = 0, i = 0; i < obj.ehdr->e_shnum; i++)
                if (obj.shdr[i].sh_type == SHT_PROGBITS)
                {
                        memcpy(&ObjCode[secLen], obj.section[i], obj.shdr[i].sh_size);
                        secLen += obj.shdr[i].sh_size;
                }

	/* Inject Relocated Object */
        if ((objvaddr = inject_elf_binary(target, ObjCode, totLen, NO_JMP_CODE, type)) < 0)
 	      return -1;

	if ((targname = strdup(target->name)) == NULL)
		return -1;

	/* Unload ELF so we can reload the version that has the object code */
	/* injected */

	if(LoadElf(targname, MAP_PRIVATE, PROT_READ|PROT_WRITE, 0, 0, &dst) == -1)
        {
                printf("Could not load target %s\n", targname);
        	return -1;
        }
		
	for (i = 0; i < obj.ehdr->e_shnum; i++)
		if (obj.shdr[i].sh_type == SHT_SYMTAB)
		{
			SymStringTable = (char *)obj.section[obj.shdr[i].sh_link];
			symtab = (Elf32_Sym *)obj.section[i];

			for (j = 0; j < obj.shdr[i].sh_size / sizeof(Elf32_Sym); j++, symtab++)
				if ((ELF32_ST_TYPE(symtab->st_info) == STT_FUNC) ||
				    (ELF32_ST_TYPE(symtab->st_info) == STT_OBJECT))
				{
					AddSymbol( /* lets add this symbol! */
					&SymStringTable[symtab->st_name],
			 		GetRelocSymAddr(&SymStringTable[symtab->st_name], obj.shdr, obj.ehdr->e_shnum, obj.mem),
					GetSymByName(&SymStringTable[symtab->st_name], obj.shdr, obj.ehdr->e_shnum, obj.mem),
					&dst);
					if (ElfReload(&dst) == -1)
					{
						printf("Could not reload target %s\n", targname);	
						return -1;
					}
					

				}
		}
	
	UnloadElf(&obj);

 	if (ElfReload(&dst) == -1)
        {
                printf("Could not reload target %s\n", targname);
                return -1;
        }

	struct linking_info *lp;
	int c;
	for (i = 0; i < fnc; i++)
	{
        	if ((lp = (struct linking_info *)get_plt(dst.mem)) == NULL)
                {
                        printf("Unable to get GOT/PLT info, failure...\n");
                        return -1;
                }
                for (j = 0; j < lp[0].count; j++)
		{
                        if (strcmp(lp[j].name, function_call[i].function) == 0)
 			{
				/* assign call the proper offset */
				/* formula: address - callsite - 4 = offset */
				long vaddr = *(long *)&dst.mem[dst.data_offset + lp[j].r_offset - dst.data_vaddr];
				
				long call_offset = lp[j].r_offset - function_call[i].vaddr - 4;
				printf("Resolved call vaddr to call offse 0x%x\n", call_offset);

				*(uint8_t *)&dst.mem[(function_call[i].vaddr - GetBase(&dst, TEXT)) - 1] = 0xff;
				*(uint8_t *)&dst.mem[function_call[i].vaddr - GetBase(&dst, TEXT)] = 0x15;
				*(unsigned long *)&dst.mem[function_call[i].vaddr - GetBase(&dst, TEXT) + 1]
				= lp[j].r_offset;
				
				//*(unsigned long *)&dst.mem[function_call[i].vaddr - GetBase(&dst, TEXT)] 
				//= call_offset;

				ElfReload(&dst);
			}
		}
	}
				
	UnloadElf(&dst);
	free(targname);
	return 0;
	
}	
	
	
	
