#include "elfmod.h" 

#define W 1      /* SHF_WRITE */
#define A 2      /* SHF_ALLOC */
#define X 4      /* SHF_EXECINSTR */
#define M 8	 /* SHF_MERGE */
#define S 16	 /* SHF_STRING */

struct section_type section_type[] = {
{".interp",     SHT_PROGBITS,   A },
{".hash",       SHT_HASH,       A },
{".note.ABI-tag", SHT_NOTE,     A },
{".gnu.hash",   SHT_GNU_HASH,   A },
{".dynsym",     SHT_DYNSYM,     A },
{".dynstr",     SHT_STRTAB,     A },
{".gnu.version",SHT_VERSYM,     A },
{".gnu.version_r",SHT_VERNEED,  A },
{".rel.dyn",    SHT_REL,        A },
{".rel.plt",    SHT_REL,        A },
{".init",       SHT_PROGBITS,   A|X},
{".plt",        SHT_PROGBITS,   A|X},
{".text",       SHT_PROGBITS,   A|X},
{".fini",       SHT_PROGBITS,   A|X},
{".rodata",     SHT_PROGBITS,   A },
{".eh_frame_hdr",SHT_PROGBITS,  A },
{".eh_frame",   SHT_PROGBITS,   A },
{".ctors",      SHT_PROGBITS,   W|A},
{".dtors",      SHT_PROGBITS,   W|A},
{".jcr",        SHT_PROGBITS,   W|A},
{".dynamic",    SHT_DYNAMIC,    W|A},
{".got",        SHT_PROGBITS,   W|A},
{".got.plt",    SHT_PROGBITS,   W|A},
{".data",       SHT_PROGBITS,   W|A},
{".bss",        SHT_NOBITS,     W|A},
{".shstrtab",   SHT_STRTAB,     0 },
{".symtab",     SHT_SYMTAB,     0 },
{".strtab",     SHT_STRTAB,     0 },
{"",    	SHT_NULL,	0 }
};

struct type_strings type_strings[] = {
{ SHT_PROGBITS, "PROGBITS"  		},
{ SHT_HASH,	"HASH"      		},
{ SHT_NOTE,	"NOTE"      		},
{ SHT_REL,	"REL"			},
{ SHT_NOBITS,	"NOBITS"		},
{ SHT_SYMTAB,	"SYMTAB"		},
{ SHT_STRTAB,	"STRTAB"		},
{ SHT_DYNAMIC,	"DYNAMIC"		},
{ SHT_VERSYM,	"VERSYM"		},
{ SHT_VERNEED,	"VERNEED"		},
{ SHT_DYNSYM,	"DYNSYM"		},
{ SHT_SHLIB,	"SHLIB"			},
{ SHT_NUM,	"NUM"			},
{ SHT_SYMTAB_SHNDX, "SYMTAB_SHNDX"	},
{ SHT_GROUP,	"GROUP"			},
{ SHT_PREINIT_ARRAY, "PREINIT_ARRAY"	},
{ SHT_FINI_ARRAY, "FINI_ARRAY"		},
{ SHT_INIT_ARRAY, "INIT_ARRAY"		},
{ SHT_GNU_HASH,	"GNU_HASH"		},
{ SHT_NULL,	"NULL"			}
};


char *filename;

/* this function is so ugly, I will be replacing it with something */
/* much more flexible */
void dump_elf_sections(uint8_t *mem)
{
	Elf32_Ehdr *ehdr = (Elf32_Ehdr *)mem;
	Elf32_Shdr *shdr = (Elf32_Shdr *)(mem + ehdr->e_shoff);
	char *StringTable, found_type = 0;
	int i, j;

        StringTable = &mem[shdr[ehdr->e_shstrndx].sh_offset];

	printf("SHT -> %d section headers, starting at offset 0x%x\n", ehdr->e_shnum, ehdr->e_shoff);
	printf("Name\t\t\tType\t\tAddr\tOff\tSize\tFlags\n");

	for (i = 0; i < ehdr->e_shnum; shdr++, i++)
	{	
		
		if (i <= 9)
			printf("[0%d]", i);
		else
			printf("[%d]", i);
		if (strlen(&StringTable[shdr->sh_name]) == 0)
		{
			printf("\t\t\t", &StringTable[shdr->sh_name]);
			goto next;
		}
		if (strlen(&StringTable[shdr->sh_name]) >= 10)
			printf(" %s\t", &StringTable[shdr->sh_name]);
		else
			printf(" %s\t\t", &StringTable[shdr->sh_name]);
		next:
		for (j = 0; j < 20; j++)
			if (shdr->sh_type == type_strings[j].type)
			{
				if (strlen(type_strings[j].name) < 8)
					printf("%s\t\t", type_strings[j].name);
				else
					printf("%s\t", type_strings[j].name);
				found_type = 1;
			}
		
		if (!found_type)
		{
			printf("UNKNOWN\t\t");
			found_type = 0;
		}

		printf("%08x %08x %08x %c%c%c%c%c", 
		shdr->sh_addr,
		shdr->sh_offset,
		shdr->sh_size,
		shdr->sh_flags & W ? 'W' : '-',
		shdr->sh_flags & A ? 'A' : '-',
		shdr->sh_flags & X ? 'X' : '-',
		shdr->sh_flags & M ? 'M' : '-',
		shdr->sh_flags & S ? 'S' : '-');
		printf("\n");
	}
}
	
/* function to get new offsets for section names*/
int STBL_OFFSET(char *p, char *string, int count)
{
        char *offset = p;
        while (count-- > 0)
        {
                while (*offset++ != '.')
                        ;
                if (strcmp(string, offset-1) == 0)
                        return ((offset - 1) - p);
                /* some section names have two periods, thus messing us up */
                /* this will take care of that */
                if (!strncmp(offset-1, ".rel.", 5) || !strncmp(offset-1, ".gnu.", 5) 
                ||  !strncmp(offset-1, ".not.", 5) || !strncmp(offset-1, ".got.", 5))
                        while (*offset++ != '.');
                
        }
        return 0;
}

int strused(char *s, char **used_strings, int count)
{
        int i;

        for (i = 0; i < count; i++)
                if (!strcmp(s, used_strings[i]))
                        return 1;
        return 0;
}

/* A silly function that does superficial obfuscation */
/* against tools that rely on sections, by generating */
/* a new string table, and randomly assigning a new string */
/* to each section. This includes some other mild modifications */
/* to the section type and flag (if desired) */
int randomize_strtbl(uint8_t *mem, char *exec, int flags)
{       
        Elf32_Ehdr *ehdr;
        Elf32_Shdr *shdr, *shp;
        Elf32_Phdr *phdr;
 	
	struct stat st;

	struct options  
	{	     
		char smix;
      		char sh_type;
        	char sh_flags;
	} opts;
  
        char *StringTable, *NewStringTable;
        char **STBL, **STBL_USED_STRINGS;
        char *p;
        char tmp[64];

        int fd;
        int i, j, k, count;
        int strcnt, slen;
        char c, failed = 0;
        
        struct timeval time;
        struct timezone tz;

	/* the original code for this used struct opts */
	/* so I kept them out of laziness */
	opts.smix = (flags & RANDOMIZE_STBL_MIX);
        opts.sh_type = (flags & RANDOMIZE_STBL_TYPE_CONSISTENCY);
        opts.sh_flags = (flags & RANDOMIZE_STBL_FLAG_CONSISTENCY);
 	
        ehdr = (Elf32_Ehdr *)mem;
 	phdr = (Elf32_Phdr *)(mem + ehdr->e_phoff);
        shdr = (Elf32_Shdr *)(mem + ehdr->e_shoff);

        /* setup string table pointer */        
        StringTable = &mem[shdr[ehdr->e_shstrndx].sh_offset];

        printf("[+] ELF Section obfuscation ->\n");
        printf("[+] Beginning string table randomization\n");
        if (opts.sh_type)
                printf("[+] sh_type consistency enabled\n");
        if (opts.sh_flags)
                printf("[+] sh_flag consistency enabled\n");

        if ((STBL = calloc(ehdr->e_shnum, sizeof(char *))) == NULL)
        {
                perror("calloc");
                return -1;
        }
        
        if ((STBL_USED_STRINGS = calloc(ehdr->e_shnum, sizeof(char *))) == NULL)
        {
                perror("calloc");
                return -1;
        }
        
        for (i = 0, shp = shdr; i < ehdr->e_shnum; shp++, i++)
                STBL[i] = strdup(&StringTable[shp->sh_name]); 
        strcnt = i - 1;

        for (slen = 0, i = 0; i < strcnt; i++, slen += strlen(STBL[i]) + 1);

        if ((NewStringTable = (char *)malloc(slen)) == NULL)
        {
                perror("malloc");
                return -1;
        }
  	for (p = NewStringTable, i = 0; i < strcnt; i++)
        {
                strcpy(p, STBL[i]); 
                p += strlen(p) + 1;
                *p = 0;
        }
        
        for (i = 0; i < strcnt; i++)
                STBL_USED_STRINGS[i] = malloc(64);
        j = 0;
        for (i = 0, shp = shdr; i < ehdr->e_shnum; i++, shp++)
        {
                
                memset(tmp, 0, sizeof(tmp));
                /* copy a random section name into tmp */
                strcpy(tmp, STBL[rand() % strcnt]); 

                /* is the string already used? */
                if (strused(tmp, STBL_USED_STRINGS, strcnt))
                {
                        --i;
                        --shp;
                        continue;
                }
                /* confirm that were not assigning a duplicate of itself */
                /* i.e .symtab to .symtab */
                if (!strcmp(&StringTable[shp->sh_name], tmp))
                {
                        --i; --shp;
                        continue;
                } 
                if (shp->sh_type == SHT_NULL)
                        continue;

 	  	/* dynamic section should be kept in place */
                if (!strcmp(&StringTable[shp->sh_name], ".dynamic") || !strcmp(tmp, ".dynamic"))
                {
                        if ((shp->sh_name = STBL_OFFSET(NewStringTable, ".dynamic", strcnt)) == 0)
                        {
                                  printf("STBL_OFFSET failed, could not find section name: %s, moving on\n", tmp);
                                  goto done;
                        }
                        continue;
                }
                /* lets create its new offset */
                if ((shp->sh_name = STBL_OFFSET(NewStringTable, tmp, strcnt)) == 0)
                        printf("STBL_OFFSET failed, could not find section name: %s\n", tmp);
        
                /* lets keep .text marked with 0x8048000 */
                if (!strcmp(tmp, ".text"))
                        shp->sh_addr = 0x8048000;
                
                /* change the section type to match its name */
                /* symtab, rel and dynsym types require a specific entry size */
                if (opts.sh_type)
                        for (count = 0; count < strcnt; count++)
                                if (!strcmp(tmp, section_type[count].name))
                                {       
                                        shp->sh_type = section_type[count].type;
                                        if (shp->sh_type == SHT_SYMTAB)
                                                shp->sh_entsize = 0x10;
                                        else
                                        if (shp->sh_type == SHT_DYNSYM)
                                                shp->sh_entsize = 0x10;
                                        else
                                        if (shp->sh_type == SHT_REL)
                                                shp->sh_entsize = 0x08;
                                }
                
                if (opts.sh_flags)
                        for (count = 0; count < strcnt; count++)
                                if (!strcmp(tmp, section_type[count].name))
                                        shp->sh_flags = section_type[count].flags;

                strcpy(STBL_USED_STRINGS[j++], tmp);
	}
        memcpy(&mem[shdr[ehdr->e_shstrndx].sh_offset], NewStringTable, shdr[ehdr->e_shstrndx].sh_size);
        
        if (msync(mem, st.st_size, MS_SYNC) == -1)
        {
                perror("msync");
                failed++;
        }

        done:
        munmap(mem, st.st_size);
        for (i = 0; i < strcnt; i++)
        {       free(STBL[i]);
                free(STBL_USED_STRINGS[i]);
        } 
        if (!failed)
                printf("Finished section obfuscation sucessfully\n");
        else
                printf("section obfuscation did not complete sucessfully\n");
        return 0;
}
int ModifyShdr(uint8_t *mem, Elf32_Shdr NewShdr, int index)
{
	Elf32_Ehdr *ehdr = (Elf32_Ehdr *)mem;
	Elf32_Shdr *shdr = (Elf32_Shdr *)(mem + ehdr->e_shoff);
	int i;

	for (i = 0; i < ehdr->e_shnum; shdr++, i++)
		if (i == index)
		{
			memcpy(shdr, &NewShdr, sizeof(Elf32_Shdr));
			return 1;
		}
	return 0;	
}
	
/* Add a string to string tables */
uint32_t Add2StrTab(char *string, Elf32mem_t *target, int type)
{
	int fd, i, slen = strlen(string);
	/* insertion offset */
	Elf32_Off insert;

	if ((fd = open(TMP_FILE, O_CREAT | O_TRUNC | O_WRONLY, target->mode)) == -1)
		return EFILE_ERR;

	switch(type)
	{
	case SYM_STRTAB:
		for (i = 0; i < target->ehdr->e_shnum; i++)
		{
			printf("%d\n", i);
			if (target->shdr[i].sh_type == SHT_STRTAB && i != target->ehdr->e_shstrndx)
			{
				insert = target->shdr[i].sh_offset + target->shdr[i].sh_size;
				printf("Found insert: %x\n", insert);
				break;
			}
		}
		break;
	case DYN_STRTAB:
		break;

	case SHD_STRTAB:
		break;
	}
	
	if (write(fd, target->mem, insert) != insert)
		return EFILE_ERR;
	if (write(fd, string, slen) != slen)
		return EFILE_ERR;
	if (write(fd, (target->mem + insert), target->size - insert) != target->size - insert)
		return EFILE_ERR;
	close(fd);
	
	rename(TMP_FILE, target->name);
	printf("insert: %x\n", insert);
	return insert;

}

int AddSection(Elf32mem_t *target, int SectIndex, char *SectName, Elf32_Shdr *NewShdr)
{
	int fd, i;
	Elf32_Addr dynamic;
	Elf32_Addr section_vaddr;
	
	Elf32_Off SectionOffset, SectionVaddr, ShdrOffset, dynoffs;
	uint32_t st_offset, st_size;

	int slen = strlen(SectName) + 1;
	SectName[strlen(SectName)] = '\0';
	
	char *StringTable = &target->mem[target->shdr[target->ehdr->e_shstrndx].sh_offset];
	
	if ((fd = open(TMP_FILE, O_CREAT | O_WRONLY | O_TRUNC, target->mode)) == -1)
               return EFILE_ERR;
  
        for (i = 0; i < target->ehdr->e_shnum; i++)
                if (i == SectIndex)
                {
			SectionOffset = target->shdr[i].sh_offset;
			SectionVaddr = target->shdr[i].sh_addr;
			/* adjust section offsets after our new insertion */
                        while (i < target->ehdr->e_shnum)
			{
				if (i != target->ehdr->e_shstrndx)
				{
			        	target->shdr[i].sh_offset += NewShdr->sh_size;
					target->shdr[i].sh_addr += NewShdr->sh_size;
				}
				i++;
			}
                }

	st_offset = target->shdr[target->ehdr->e_shstrndx].sh_offset;
	st_size = target->shdr[target->ehdr->e_shstrndx].sh_size;
	st_offset += st_size; /* offset actually points to end of string table */

	ShdrOffset = target->ehdr->e_shoff + SectIndex * target->ehdr->e_shentsize;

	/* adjust sections after string table to make room for new string */
	for (i = 0; i < target->ehdr->e_shnum; i++)
		if (i > target->ehdr->e_shstrndx)
		{
			target->shdr[i].sh_offset += slen;
			target->shdr[i].sh_addr += slen;
		}

	/* adjust sections after new shdr to make room it */
	for (i = 0; i < target->ehdr->e_shnum; i++)
		if (target->shdr[i].sh_offset > ShdrOffset)
		{
			target->shdr[i].sh_offset += target->ehdr->e_shentsize;
			target->shdr[i].sh_addr += target->ehdr->e_shentsize;
		}
 	
	for (i = target->ehdr->e_phnum; i-- > 0; target->phdr++)
                if (target->phdr->p_type == PT_DYNAMIC)
                {
		        dynamic = target->phdr->p_vaddr;
			dynoffs = target->phdr->p_offset;
			break;
		}

	/* Lets make sure the dynamic section retains its normal offset and addr */
	for (i = 0; i < target->ehdr->e_shnum; i++)
		if (strcmp(&StringTable[target->shdr[i].sh_name], ".dynamic") == 0)
		{
			if (i > SectIndex)
			{
				target->shdr[i].sh_addr = dynamic;
				target->shdr[i].sh_offset = dynoffs;

				target->shdr[i - 1].sh_offset -= 1;
				break;
			}
		}
	

	/* increase string table size to allow for new string */   
	target->shdr[target->ehdr->e_shstrndx].sh_size += slen;

	/* adjust section header offset to account for new string */
	if (target->ehdr->e_shoff > target->shdr[target->ehdr->e_shstrndx].sh_offset)
        	target->ehdr->e_shoff += slen;

	target->ehdr->e_shstrndx += 1;
        target->ehdr->e_shnum += 1;
	
	/* fill in Shdr aspects that aren't user controlled */
	NewShdr->sh_offset = SectionOffset;
	NewShdr->sh_addr = SectionVaddr;
	NewShdr->sh_name = st_size;
	
	/* set the proper entry size */	
	if (NewShdr->sh_type == SHT_REL)
		NewShdr->sh_entsize = sizeof(Elf32_Rel);
	else
	if (NewShdr->sh_type == SHT_RELA)
		NewShdr->sh_entsize = sizeof(Elf32_Rela);
	else
	if (NewShdr->sh_type == SHT_SYMTAB)
		NewShdr->sh_entsize = sizeof(Elf32_Sym);
	else
	if (NewShdr->sh_type == SHT_DYNAMIC)
		NewShdr->sh_entsize = sizeof(Elf32_Dyn);

	if (write(fd, target->mem, st_offset) != st_offset)
		return -1;
	
	if (write(fd, SectName, slen) != slen)
                return -1;
	
	if (write(fd, (target->mem + st_offset), ShdrOffset - st_offset) != ShdrOffset - st_offset)
		return -1;

	if (write(fd, NewShdr, sizeof(Elf32_Shdr)) != sizeof(Elf32_Shdr))
		return -1;

	if (write(fd, (target->mem + ShdrOffset), target->size - ShdrOffset) != target->size - ShdrOffset)
		return -1;

	if (rename(TMP_FILE, target->name) < 0)
		return -1;

	close (fd);
	target->size += sizeof(Elf32_Shdr) + slen;
	return 1;
}
	

