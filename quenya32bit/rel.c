#include "elfmod.h"

/* This is a bloated function that gets global offset table info */

struct linking_info * get_plt(unsigned char *mem)
{
        Elf32_Ehdr *ehdr;
        Elf32_Shdr *shdr, *shdrp, *symshdr;
        Elf32_Sym *syms, *symsp;
        Elf32_Rel *rel;

        char *symbol;
        int i, j, symcount, k;

        struct linking_info *link;

        ehdr = (Elf32_Ehdr *)mem;
        shdr = (Elf32_Shdr *)(mem + ehdr->e_shoff);

        shdrp = shdr;

        for (i = ehdr->e_shnum; i-- > 0; shdrp++)
        {
                if (shdrp->sh_type == SHT_DYNSYM)
                {
                        symshdr = &shdr[shdrp->sh_link];
                        if ((symbol = malloc(symshdr->sh_size)) == NULL)
                                goto fatal;
                        memcpy(symbol, (mem + symshdr->sh_offset), symshdr->sh_size);

                        if ((syms = (Elf32_Sym *)malloc(shdrp->sh_size)) == NULL)
                                goto fatal;

                        memcpy((Elf32_Sym *)syms, (Elf32_Sym *)(mem + shdrp->sh_offset), shdrp->sh_size);
                        symsp = syms;

                        symcount = (shdrp->sh_size / sizeof(Elf32_Sym));
                        link = (struct linking_info *)malloc(sizeof(struct linking_info) * symcount);
                        if (!link)
                                goto fatal;

                        link[0].count = symcount;
                        for (j = 0; j < symcount; j++, symsp++)
                        {
                                strncpy(link[j].name, &symbol[symsp->st_name], sizeof(link[j].name)-1);
                                if (!link[j].name)
                                        goto fatal;
				link[j].s_value = symsp->st_value;
                                link[j].index = j;
                        }
                        break;
                }
        }
        for (i = ehdr->e_shnum; i-- > 0; shdr++)
        {
                switch(shdr->sh_type)
                {
                        case SHT_REL:
                                 rel = (Elf32_Rel *)(mem + shdr->sh_offset);
                                 for (j = 0; j < shdr->sh_size; j += sizeof(Elf32_Rel), rel++)
                                 {
                                        for (k = 0; k < symcount; k++)
  				  	{
                                                if (ELF32_R_SYM(rel->r_info) == link[k].index)
                                                {
						        link[k].r_offset = rel->r_offset;
							link[k].r_info = rel->r_info;
                                                        link[k].r_type = ELF32_R_TYPE(rel->r_info);
						}

                                        }
                                 }
                                 break;
                        case SHT_RELA:
                                break;

                        default:
                                break;
                }
        }

        return link;
        fatal:
                return NULL;
}

struct linking_info *get_rel(uint8_t *mem)
{
        Elf32_Ehdr *ehdr;
        Elf32_Shdr *shdr, *shdrp, *symshdr;
        Elf32_Sym *syms, *symsp;
        Elf32_Rel *rel;

        char *symbol;
        int i, j, symcount, k;

        struct linking_info *link;
        ehdr = (Elf32_Ehdr *)mem;
        shdr = (Elf32_Shdr *)(mem + ehdr->e_shoff);
	char *StringTable = &mem[shdr[ehdr->e_shstrndx].sh_offset];

        shdrp = shdr;

        for (i = ehdr->e_shnum; i-- > 0; shdrp++)
        {
                if (shdrp->sh_type == SHT_SYMTAB)
                {
                        symshdr = &shdr[shdrp->sh_link];
                        if ((symbol = malloc(symshdr->sh_size)) == NULL)
                                goto fatal;
                        memcpy(symbol, (mem + symshdr->sh_offset), symshdr->sh_size);

                        if ((syms = (Elf32_Sym *)malloc(shdrp->sh_size)) == NULL)
                                goto fatal;

                        memcpy((Elf32_Sym *)syms, (Elf32_Sym *)(mem + shdrp->sh_offset), shdrp->sh_size);
                        symsp = syms;

                        symcount = (shdrp->sh_size / sizeof(Elf32_Sym));
                        link = (struct linking_info *)malloc(sizeof(struct linking_info) * symcount);
                        if (!link)
                                goto fatal;

                        link[0].count = symcount;
                        for (j = 0; j < symcount; j++, symsp++)
                        {
                                strncpy(link[j].name, &symbol[symsp->st_name], sizeof(link[j].name)-1);
                                if (!link[j].name)
                                        goto fatal;
                                link[j].s_value = symsp->st_value;
                                link[j].index = j;
                        }
                        break;
                }
        }
	
	char relname[MAXSTR];
	for (i = ehdr->e_shnum; i-- > 0; shdr++)
        {
                switch(shdr->sh_type)
                {
                        case SHT_REL:
				 strcpy(relname, &StringTable[shdr->sh_name]);
                                 rel = (Elf32_Rel *)(mem + shdr->sh_offset);
                                 for (j = 0; j < shdr->sh_size; j += sizeof(Elf32_Rel), rel++)
                                 {
                                        for (k = 0; k < symcount; k++)
                                        {
                                                if (ELF32_R_SYM(rel->r_info) == link[k].index)
                                                {
						        link[k].r_offset = rel->r_offset;
							link[k].r_info = rel->r_info;
							link[k].r_type = ELF32_R_TYPE(rel->r_info);
						}
                                        }
                                 }
                                 break;
                        case SHT_RELA:
                                break;

                        default:
                                break;
                }
        }

        return link;
	fatal:
                return NULL;

}
