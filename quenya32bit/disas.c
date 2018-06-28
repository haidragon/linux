/* Quenya Disassembler */

#include "elfmod.h"

extern int global_debug;

/* This whole function is very simple, it writes data to a given location */
/* within the target ELF object (ET_DYN,ET_EXEC for now) */
/* The value can be 8, 16, or 32 bits. */
int OverWrite(Elf32mem_t *target, Elf32_Addr vaddr, long value, int len)
{
	Elf32_Addr text_base, data_base, base;
	uint32_t off;
	uint8_t *mp;
	int i, which;
	unsigned long data_vaddr;
	
	/* which segment does vaddr reside in? */
	which = WhichSegment(target, vaddr);
	if (which != DATA && which != TEXT)
	{
		printf("Virtual Address: 0x%x does not exist within boundaries of executable %s\n", vaddr, target->name);
		return -1;
	}
	if ((base = GetBase(target, which)) == 0)
	{
		printf("Unable to find base address: %s -> corrupted binary?\n", target->name);
		return -1;
	} 
	if (base == -1)
	{
		printf("Virtual Address: 0x%x does not exist within boundaries of executable %s\n", vaddr, target->name);
		return -1;
	}
	
	if (global_debug)
		printf("which: %d base: %x\n", which, base);

	if (which == DATA)
		mp = &target->mem[target->data_offset + (vaddr - base)];
	else
	if (which == TEXT)
		mp = &target->mem[target->text_offset + (vaddr - base)];

	//printf("offset: %d\n %x - %x", vaddr - base, vaddr, base);
	/* This should be obvious */
	switch(len)
	{
		case OW_BYTE:
			*(uint8_t *)mp = value;
			break;
		case OW_WORD:
			*(uint16_t *)mp = value;
			break;
		case OW_DWORD:
			*(uint32_t *)mp = value;
			break;
		
	}

	return 0;
}

int displayDisas(char *name, Elf32mem_t *target, int format, Elf32_Addr instr_vaddr, uint32_t InstCount)
{	
	INSTRUCTION inst;
	Elf32_Sym *sym;
	Elf32_Addr vaddr;
	Elf32_Addr base;
	Elf32_Word symlen;
	uint8_t *mp;
	uint32_t c, totlen;
	int symdisas = 0, t = 0;
	int i, bytes, len, line, nl = 0; // instruction len
	char string[MAXSTR], string2[MAXSTR], *p;
	char input;
	int which;
	/* We are disassembling an entire function frame */
	if (name != NULL)
		symdisas = 1;
	
	if (instr_vaddr)
	{	
		vaddr = instr_vaddr;
		which = WhichSegment(target, vaddr);
        	if (which != DATA && which != TEXT)
        	{
                	printf("Virtual Address: 0x%x does not exist within boundaries of executable %s\n", vaddr, target->name);
                	return -1;
        	}
        	if ((base = GetBase(target, which)) == 0)
        	{
                	printf("Unable to find base address: %s -> corrupted binary?\n", target->name);
                	return -1;
        	}
        	if (base == -1)
        	{
                	printf("Virtual Address: 0x%x does not exist within boundaries of executable %s\n", vaddr, target->name);
               	 	return -1;
        	}
	}
	else
	{
		/* get our symbol address */
		vaddr = GetSymAddr(name, target);
		if (!vaddr)
		{
			printf("\nUnable to locate symbol: %s\n", name);
			return -1;
		}
		which = WhichSegment(target, vaddr);
		if (which != DATA && which != TEXT)
                {
                        printf("Virtual Address: 0x%x does not exist within boundaries of executable %s\n", vaddr, target->name);
                        return -1;
                }
                if ((base = GetBase(target, which)) == 0)
                {
                        printf("Unable to find base address: %s -> corrupted binary?\n", target->name);
                        return -1;
                }
                if (base == -1)
                {
                        printf("Virtual Address: 0x%x does not exist within boundaries of executable %s\n", vaddr, target->name);
                        return -1;
                }

		/* hell, lets just get the whole symbol! */
		sym = GetSymByName(name, target->shdr, target->ehdr->e_shnum, target->mem);
		if (!sym)
		{
			printf("Unable to retrieve symbol: %s\n", name);
			return -1;
		}
	
		/* get symbol size (code len) */
		symlen = sym->st_size; 
	}
	disas:
	totlen = (symdisas == 1 ? symlen : 13); //13 is max instr len on ia32  
	
	/* This argument will only be active if the user */
	/* wants to view multiple lines of assembly with only */
	/* specifying an address (not a symbol name) */
	if (InstCount)
		totlen = InstCount;

	printf("\n");
	/* lets point at the offset where our symbol starts in memory! */
        if (which == DATA)
                mp = &target->mem[target->data_offset + (vaddr - base)];
        else
        if (which == TEXT)
                mp = &target->mem[target->text_offset + (vaddr - base)];
	c = 0;
	line = 0;
	bytes = 8;
	while (c < totlen)
	{ 
		/* This is our scrolling mechanism */
		if (line >= (GetMaxLine() - 5))
		{
			nl = 1; /* indicate we went over maxline */
			/* hitting enter prints a newline, we don't want that */
			/* when scrolling through code (obviously */
			echo_off();
			while(1)
			{	
				/* if enter is hit break out to print next line */
				if ((input = getchar()) == '\n' || input == ' ')
					break;
				else 
				if (input == 'q') /* quit */
				{
					echo_on();
					return 0;
				}
			}		
			echo_on();
		}
		len = get_instruction(&inst, &mp[c], MODE_32);
		if (!len || (len + c > totlen)) 
		{
                        printf("%.8x  ", c);
                	if (format == FORMAT_INTEL)
                                printf("db 0x%.2x\n", mp[c]);
                        else
                                printf(".byte 0x%.2x\n", mp[c]);
                        c++;
                        continue;
                }
	
		get_instruction_string(&inst, format, (DWORD)c, string, sizeof(string));
		/* I modify string a bit by adding a tab between */
		/* the instruction and the operands (for aesthetics) */
		p = string;
		t = 0;
		while (*p != ' ')
		{
			t++;
			p++;
		}
		strncpy(string2, string, t);
		string2[t] = '\t';
		strcat(string2, &string[t + 1]); 

		/* disassembling an entire symbol shows the symbol name for */
		/* each line of code, otherwise we don't */
		if (strstr(string2, "call"))
		{
			unsigned long call_vaddr = *(long *)&mp[c + 1];
			call_vaddr += 5 + (vaddr + c);

			if (symdisas)
				printf("[0x%08x-> %s+%i]\tcall\t0x%x\n", (vaddr + c), name, c, call_vaddr);
			else
				printf("[0x%08x]\t%s\t", (vaddr + c), string2);
		}
		else	
		{
			if (symdisas)
                        	printf("[0x%08x-> %s+%i]\t%s\n", (vaddr + c), name, c, string2);
                	else
                        	printf("[0x%08x]\t%s\t", (vaddr + c), string2);
		}

		if (!symdisas)
		{
			for (i = 0; i < len; i++)
				printf("\\x%.2x", mp[i]);
			printf("\n");
			break;
		}
		c += len;
		line++;
		memset(string, 0, sizeof(string));
		memset(string2, 0, sizeof(string2));
	 }
	 finished:
	 printf("\n");
	 if (nl)
	 	echo_off();
	 return 0; 
}

