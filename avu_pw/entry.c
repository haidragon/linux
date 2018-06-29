/*
 * -- entry.c --		
 * locates the host entry point by using the glibc initializion 		
 * code as a signature 
 * <ryan@bitlackeys.com>
 */


#include "avu.h"

unsigned long get_host_entry(unsigned char *mem, unsigned *_start)
{	
 	int i, ip = 0;
	unsigned long entry_point;
	Elf32_Addr textaddr;
	Elf32_Off textend, textoff;

	Elf32_Ehdr *e_hdr;
	Elf32_Shdr *s_hdr;
	char *StringTable, found_text = 0;
	u_char *mp;

	e_hdr = (Elf32_Ehdr *)mem;
	s_hdr = (Elf32_Shdr *)(mem + e_hdr->e_shoff);

	StringTable = &mem[s_hdr[e_hdr->e_shstrndx].sh_offset];

	for (i = e_hdr->e_shnum; i-- > 0; s_hdr++)
	{
		 if (strcmp(&StringTable[s_hdr->sh_name], ".text") == 0)
		 {
		 	textaddr = s_hdr->sh_addr;
			textoff = s_hdr->sh_offset;
			textend = s_hdr->sh_offset + s_hdr->sh_size; 
			found_text++;
		 	break;
		 }
	}

	if (!found_text)
		return 0;

	mp = mem + textoff;
	while(ip < (textend - textoff))
	{
		if (code_cmp(mp, _start, 10) == 0)
			return (textaddr + ip);
		mp++;
		ip++;
	}

	return 0;
}

int code_cmp(unsigned char *mp, unsigned *code, int len)
{
	int i = 0;
	
	while (i++ < len)
	{
		if (mp[i] != code[i]) 
			return 1;
	}
	return 0;
}	
	
