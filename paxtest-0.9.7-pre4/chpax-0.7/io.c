/*
** io.c for chpax
**
** The PaX project : http://pax.grsecurity.net/
**
*/
#include "chpax.h"

#ifndef EM_X86_64
#define EM_X86_64 	62
#endif

/* Read flags */
int			read_header(char *name, int mode)
{
   char			*ptr;
   int			size;
   int			block;
   
   if ((fd = open(name, mode)) < 0)
     return 1;
   
   ptr = (char *) &header_elf64;
   size = sizeof(header_elf64);
   
   do
     {
	block = read(fd, ptr, size);
	if (block <= 0)
	  return (block ? 1 : 2);
	ptr += block; 
	size -= block;
     }
   while (size > 0);
   
   memcpy(&header_aout, &header_elf64, sizeof(header_aout));
   memcpy(&header_elf, &header_elf64, sizeof(header_elf));
   
   if (!memcmp(header_elf64.e_ident, ELFMAG, SELFMAG) && FILE_IS_ELF64(header_elf64))
     {
	if (header_elf64.e_type != ET_EXEC && header_elf.e_type != ET_DYN)
	  return 2;
	if (header_elf64.e_machine != EM_SPARC && 
	    header_elf64.e_machine != EM_SPARCV9 &&
	    header_elf64.e_machine != EM_ALPHA &&
	    header_elf64.e_machine != EM_X86_64 &&
	    header_elf64.e_machine != EM_IA_64 &&
	    header_elf64.e_machine != EM_PPC64)
	  return 3;
	header = &header_elf64;
	header_size = sizeof(header_elf64);
	get_flags = get_flags_elf64;
	put_flags = put_flags_elf64;
     }
   
   else if (!memcmp(header_elf.e_ident, ELFMAG, SELFMAG) && FILE_IS_ELF32(header_elf))
     {
       if (header_elf.e_type != ET_EXEC && header_elf.e_type != ET_DYN)
	 return 2;
       if (header_elf.e_machine != EM_386 &&
	   header_elf.e_machine != EM_SPARC && 
	   header_elf.e_machine != EM_SPARC32PLUS &&
	   header_elf.e_machine != EM_PARISC &&
	   header_elf.e_machine != EM_PPC &&
	   header_elf.e_machine != EM_MIPS &&
	   header_elf.e_machine != EM_MIPS_RS3_LE)
	 return 3;
	header = &header_elf;
	header_size = sizeof(header_elf);
	get_flags = get_flags_elf;
	put_flags = put_flags_elf;
     }
   
   else if (N_MAGIC(header_aout) == NMAGIC ||
	    N_MAGIC(header_aout) == ZMAGIC ||
	    N_MAGIC(header_aout) == QMAGIC)
     {
       
       if (N_MACHTYPE(header_aout) != M_386)
	 return 3;
       header = &header_aout;
       header_size = 4;
       get_flags = get_flags_aout; 
       put_flags = put_flags_aout;
     }
   
   else
     return (2);
   
   return (0);
}


/* Write flags */
int	write_header()
{
  char	*ptr;
  int	size;
  int	block;

  if ((off_t)-1 == lseek(fd, 0, SEEK_SET))
    return 1;

  ptr = (char *) header;
  size = header_size;

  do
    {
      block = write(fd, ptr, size);
      if (block <= 0)
	break;
      ptr += block;
      size -= block;
    }
  while (size > 0);

  return size;
}
