
/* Returns the direct symbol value, whereas GetRelocSymAddr must calculate */
/* the relocated value */

#include "elfmod.h"

Elf32_Addr GetSymAddr(char *name, Elf32mem_t *target)
{
        Elf32_Sym *symtab;
        char *SymStrTable;
        int i, j, symcount;
	
	for (i = 0; i < target->ehdr->e_shnum; i++)	
                if (target->shdr[i].sh_type == SHT_SYMTAB || target->shdr[i].sh_type == SHT_DYNSYM)
                {
                        SymStrTable = (char *)target->section[target->shdr[i].sh_link];
                        symtab = (Elf32_Sym *)target->section[i];

                        for (j = 0; j < target->shdr[i].sh_size / sizeof(Elf32_Sym); j++, symtab++)
                        {
                                if(strcmp(&SymStrTable[symtab->st_name], name) == 0)
                                        return (symtab->st_value);
                        }
                }
        return 0;
}

int ModifySymbol(char *name, Elf32mem_t *target, Elf32_Addr value)
{
        Elf32_Sym *symtab;
        char *SymStrTable;
        int i, j, symcount;

        for (i = 0; i < target->ehdr->e_shnum; i++)
                if (target->shdr[i].sh_type == SHT_SYMTAB || target->shdr[i].sh_type == SHT_DYNSYM)
                {
                        SymStrTable = (char *)target->section[target->shdr[i].sh_link];
                        symtab = (Elf32_Sym *)target->section[i];

                        for (j = 0; j < target->shdr[i].sh_size / sizeof(Elf32_Sym); j++, symtab++)
                        {
                                if(strcmp(&SymStrTable[symtab->st_name], name) == 0)
                                {
				        symtab->st_value = value;
					return 1;
				}
                        }
                }
        return 0;
}

int ListSymTable(Elf32mem_t *target, int type /*SYMTAB OR DYNSYM*/, int index)
{
	Elf32_Sym *symtab;
	char *SymStrTable;
	int st_type, st_bind;
	int i, j;

	for (i = 0; i < target->ehdr->e_shnum; i++)
		if (target->shdr[i].sh_type == type)
		{
			SymStrTable = (char *)target->section[target->shdr[i].sh_link];
			symtab = (Elf32_Sym *)target->section[i];
			
			if (type == SHT_DYNSYM)
				printf("\nDYNAMIC SYMBOLS\n");
			else
			if (type == SHT_SYMTAB)
				printf("\nSYMBOLS\n");
			printf("#   Value      Size\t Type\t\tBind\t\tName\n");
			for (j = 0; j < target->shdr[i].sh_size / sizeof(Elf32_Sym); j++, symtab++)
			{
				st_type = ELF32_ST_TYPE(symtab->st_info);
				st_bind = ELF32_ST_BIND(symtab->st_info);
				if (j <= 9)
					printf("0%d: ", j);
				else
					printf("%d: ", j);
				printf("0x%08x 0x%05x\t ",symtab->st_value, symtab->st_size);
				switch(st_type)
				{
				case STT_NOTYPE:
					printf("NOTYPE\t\t");
					break;
				case STT_FILE:
					printf("FILE\t\t");
					break;
				case STT_OBJECT:
					printf("OBJECT\t\t");
					break;
				case STT_SECTION:
					printf("SECTION\t"); //single tab for this one
					break;
				case STT_LOPROC:
					printf("LOPROC\t\t");
					break;
				case STT_HIPROC:
					printf("HIPROC\t\t");
					break;
				case STT_FUNC:
					printf("FUNC\t\t");
					break;
				}
				
				switch(st_bind)
				{
				case STB_LOCAL:
					printf("LOCAL\t\t");
					break;
				case STB_GLOBAL:
					printf("GLOBAL\t\t");
					break;
				case STB_WEAK:
					printf("WEAK\t\t");
					break;
				case STB_LOPROC:
					printf("LOPROC\t\t");
					break;
				case STB_HIPROC:
					printf("HIPROC\t\t");
					break;
				}

				printf("%s\n", &SymStrTable[symtab->st_name]);
			}
		}
}

