/*
** flags.c for chpax
** 
** The PaX project : http://pax.grsecurity.net/
**
*/
#include "chpax.h"


#define USAGE \
"%s %s .::. Manage PaX flags for binaries\n" \
"Usage: %s OPTIONS FILE1 FILE2 FILEN ...\n" \
"  -P\tenforce paging based non-executable pages\n" \
"  -p\tdo not enforce paging based non-executable pages\n" \
"  -E\temulate trampolines\n" \
"  -e\tdo not emulate trampolines\n" \
"  -M\trestrict mprotect()\n" \
"  -m\tdo not restrict mprotect()\n" \
"  -R\trandomize mmap() base [ELF only]\n" \
"  -r\tdo not randomize mmap() base [ELF only]\n" \
"  -X\trandomize ET_EXEC base [ELF only]\n" \
"  -x\tdo not randomize ET_EXEC base [ELF only]\n" \
"  -S\tenforce segmentation based non-executable pages\n" \
"  -s\tdo not enforce segmentation based non-executable pages\n" \
"  -v\tview current flag mask \n" \
"  -z\tzero flag mask (next flags still apply)\n\n" \
"The flags only have effect when running the patched Linux kernel.\n" \


void	usage(char *name)
{
  char	*ptr;

  ptr = (name ? name : "chpax");
  printf(USAGE, ptr, CHPAX_VERSION, ptr);
  exit(1);
}


unsigned long	   scan_flags(unsigned long flags, char **argv, int *view)
{
  int		   index;

  for (index = 1; argv[1][index]; index++)
    switch (argv[1][index])
      {

      case 'p':
	flags |= HF_PAX_PAGEEXEC;
	continue ;

      case 'P':
	flags = (flags & ~HF_PAX_PAGEEXEC) | HF_PAX_SEGMEXEC;
	continue ;

      case 'E':
	flags |= HF_PAX_EMUTRAMP;
	continue ;

      case 'e':
	flags = (flags & ~HF_PAX_EMUTRAMP);
	continue ;

      case 'm':
	flags |= HF_PAX_MPROTECT;
	continue ;

      case 'M':
	flags = (flags & ~HF_PAX_MPROTECT);
	continue ;

      case 'r':
	flags |= HF_PAX_RANDMMAP;
	continue ;

      case 'R':
	flags = (flags & ~HF_PAX_RANDMMAP);
	continue ;

      case 'X':
	flags |= HF_PAX_RANDEXEC;
	continue ;

      case 'x':
	flags = (flags & ~HF_PAX_RANDEXEC);
	continue ;

      case 's':
	flags |= HF_PAX_SEGMEXEC;
	continue ;

      case 'S':
	flags = (flags & ~HF_PAX_SEGMEXEC) | HF_PAX_PAGEEXEC;
	continue ;

      case 'v':
	*view = 1;
	continue ;

      case 'z':
	flags = 0;
	continue ;

      default:
	fprintf(stderr, "Unknown option %c \n", argv[1][index]);
	usage(argv[0]);
      }

  return (flags);
}


char *pax_short_flags(unsigned long flags)
{
  static char buffer[7];

  buffer[0] = (flags & HF_PAX_PAGEEXEC ? 'p' : 'P');
  buffer[1] = (flags & HF_PAX_EMUTRAMP ? 'E' : 'e');
  buffer[2] = (flags & HF_PAX_MPROTECT ? 'm' : 'M');
  buffer[3] = (flags & HF_PAX_RANDMMAP ? 'r' : 'R');
  buffer[4] = (flags & HF_PAX_RANDEXEC ? 'X' : 'x');
  buffer[5] = (flags & HF_PAX_SEGMEXEC ? 's' : 'S');
  return buffer;
}


void		print_flags(unsigned long flags)
{
  printf(" * Paging based PAGE_EXEC       : %s \n"
	 " * Trampolines                  : %s \n"
	 " * mprotect()                   : %s \n"
	 " * mmap() base                  : %s \n"
	 " * ET_EXEC base                 : %s \n"
	 " * Segmentation based PAGE_EXEC : %s \n",
	 flags & HF_PAX_PAGEEXEC
	 ? "disabled" : flags & HF_PAX_SEGMEXEC ? "enabled" : "enabled (overridden)",
	 flags & HF_PAX_EMUTRAMP
	 ? "emulated" : "not emulated",
	 flags & HF_PAX_MPROTECT
	 ? "not restricted" : "restricted",
	 flags & HF_PAX_RANDMMAP
	 ? "not randomized" : "randomized",
	 flags & HF_PAX_RANDEXEC
	 ? "randomized" : "not randomized",
	 flags & HF_PAX_SEGMEXEC
	 ? "disabled" : "enabled");
}
