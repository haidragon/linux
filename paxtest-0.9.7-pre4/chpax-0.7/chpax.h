/*
 * Include file for chpax.c
 * 
 * The PaX project : http://pax.grsecurity.net/
 * 
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>
#include <a.out.h>

#define	CHPAX_VERSION		"0.7"

#define HF_PAX_PAGEEXEC         1    /* 0: Paging based non-exec pages */
#define HF_PAX_EMUTRAMP         2    /* 0: Emulate trampolines */
#define HF_PAX_MPROTECT         4    /* 0: Restrict mprotect() */
#define HF_PAX_RANDMMAP         8    /* 0: Randomize mmap() base */
#define HF_PAX_RANDEXEC         16   /* 1: Randomize ET_EXEC base */
#define HF_PAX_SEGMEXEC         32   /* 0: Segmentation based non-exec pages */

#define EI_PAX                  14   /* Index to read the PaX flags into ELF header e_ident[] array */

#ifndef PT_PAX_FLAGS
#define PT_PAX_FLAGS	0x65041580	/* Indicates PaX flag markings */
#define PF_PAGEEXEC	(1 << 4)	/* Enable  PAGEEXEC */
#define PF_NOPAGEEXEC	(1 << 5)	/* Disable PAGEEXEC */
#define PF_SEGMEXEC	(1 << 6)	/* Enable  SEGMEXEC */
#define PF_NOSEGMEXEC	(1 << 7)	/* Disable SEGMEXEC */
#define PF_MPROTECT	(1 << 8)	/* Enable  MPROTECT */
#define PF_NOMPROTECT	(1 << 9)	/* Disable MPROTECT */
#define PF_RANDEXEC	(1 << 10)	/* Enable  RANDEXEC */
#define PF_NORANDEXEC	(1 << 11)	/* Disable RANDEXEC */
#define PF_EMUTRAMP	(1 << 12)	/* Enable  EMUTRAMP */
#define PF_NOEMUTRAMP	(1 << 13)	/* Disable EMUTRAMP */
#define PF_RANDMMAP	(1 << 14)	/* Enable  RANDMMAP */
#define PF_NORANDMMAP	(1 << 15)	/* Disable RANDMMAP */
#endif

#define	XCLOSE(fd)		\
do				\
{				\
 if (close(fd))			\
   perror("close");		\
}				\
while (0)

#define	FILE_IS_ELF64(h)	(h.e_ident[EI_CLASS] == 2)
#define	FILE_IS_ELF32(h)	(h.e_ident[EI_CLASS] == 1)

/* Extern variables */
extern Elf32_Ehdr		header_elf;
extern Elf64_Ehdr		header_elf64;
extern struct exec		header_aout;
extern int			header_size;
extern void			*header;
extern int			fd;
extern unsigned long		(*get_flags)();
extern void			(*put_flags)(unsigned long);

/* Function prototypes */
int                     read_header(char *name, int mode);
int			write_header();
unsigned long		get_flags_elf();
void			put_flags_elf(unsigned long flags);
unsigned long		get_flags_aout();
void			put_flags_aout(unsigned long flags);
unsigned long		get_flags_elf64();
void			put_flags_elf64(unsigned long flags);
void			usage(char *name);
unsigned long		scan_flags(unsigned long flags, char **argv, int *view);
void			print_flags(unsigned long flags);
char			*pax_short_flags(unsigned long flags);
