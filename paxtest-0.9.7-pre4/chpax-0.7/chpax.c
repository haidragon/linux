/*
 * chpax version 0.7
 *
 * This program manages various PaX related flags for ELF32, ELF64, 
 * and a.out binaries. The flags only have effect when running the 
 * patched Linux kernel.
 *
 * Written by Solar Designer and placed in the public domain.
 *
 * Adapted to PaX by the PaX Team
 * 
 * Maintained by [jv@grsecurity.net]
 *
 */
#include "chpax.h"

Elf32_Ehdr		header_elf;
Elf64_Ehdr		header_elf64;
struct exec		header_aout;
int			header_size;
void			*header;
int			fd;
unsigned long		(*get_flags)();
void			(*put_flags)(unsigned long);


int		 main(int argc, char *argv[])
{
  unsigned long  flags;
  unsigned long  aflags;
  unsigned int	 index = 2;
  int		 mode;
  char		 *current;
  int		 error = 0;
  int		 view = 0;

  if (!argv)
    usage(NULL);
  if (argc < 3 || !argv[1] || argv[1][0] != '-')
    usage(argv[0]);

  flags = scan_flags(0, argv, &view);
  mode = view & !flags ? O_RDONLY : O_RDWR;

   for (current = argv[index]; current; current = argv[++index])
    {

      error = read_header(current, mode);
      switch (error)
	{
	case 1:
	  perror(current);
	  continue ;
	case 2:
	  fprintf(stderr, "%s: Unknown file type (passed) \n", current);
	  XCLOSE(fd);
	  continue ;
	case 3:
	  fprintf(stderr, "%s: Wrong architecture (passed) \n", current);
	  XCLOSE(fd);
	  continue ;
	}

      aflags = get_flags();
      flags  = scan_flags(aflags, argv, &view);

      if (view)
	{
	  printf("\n----[ chpax %s : Current flags for %s (%s) ]---- \n\n", 
		 CHPAX_VERSION, current, pax_short_flags(aflags));
	  print_flags(aflags);
	  puts("");
	}

      put_flags(flags);

      if (flags != aflags && write_header())
	{
	  perror(current);
	  error = 4;
	}

      if (error)
	fprintf(stderr, "%s : Flags were not updated . \n", current);
      else if (view && aflags != flags)
	{
	  printf("\n----[ chpax %s : Updated flags for %s (%s) ]---- \n\n", 
		 CHPAX_VERSION, current, pax_short_flags(flags));
	  print_flags(flags);
	  puts("");
	}

      XCLOSE(fd);
    }

  return (error);
}
