#ifndef __PAXCTL_H
#define __PAXCTL_H

#include <elf.h>

#define PAXCTL_VERSION "0.9"

struct pax_state;

struct elf_ops {
  int (* const modify_phdr)(struct pax_state * const);
  union {
    Elf32_Phdr * _32;
    Elf64_Phdr * _64;
  } phdr;
  union {
    Elf32_Half _32;
    Elf64_Half _64;
  } phnum;
  union {
    Elf32_Shdr * _32;
    Elf64_Shdr * _64;
  } shdr;
  union {
    Elf32_Half _32;
    Elf64_Half _64;
  } shnum;
};

struct pax_state {
  char ** argv;
  unsigned int flags_on;
  unsigned int flags_off;
  unsigned int files;
  unsigned int quiet:1;
  unsigned int shortonly:1;
  unsigned int view:1;
  unsigned int convert:1;
  unsigned int create:1;
  struct elf_ops * ops;
  int fd;
  unsigned char * map;
  size_t size;
};

#ifndef PT_GNU_STACK
#define PT_GNU_STACK	0x6474e551	/* Indicates vanilla stack executability */
#endif

#ifndef PT_PAX_FLAGS

#define PT_PAX_FLAGS	0x65041580

#define PF_PAGEEXEC	(1U << 4)	/* Enable  PAGEEXEC */
#define PF_NOPAGEEXEC	(1U << 5)	/* Disable PAGEEXEC */
#define PF_SEGMEXEC	(1U << 6)	/* Enable  SEGMEXEC */
#define PF_NOSEGMEXEC	(1U << 7)	/* Disable SEGMEXEC */
#define PF_MPROTECT	(1U << 8)	/* Enable  MPROTECT */
#define PF_NOMPROTECT	(1U << 9)	/* Disable MPROTECT */
#define PF_RANDEXEC	(1U << 10)	/* Enable  RANDEXEC */
#define PF_NORANDEXEC	(1U << 11)	/* Disable RANDEXEC */
#define PF_EMUTRAMP	(1U << 12)	/* Enable  EMUTRAMP */
#define PF_NOEMUTRAMP	(1U << 13)	/* Disable EMUTRAMP */
#define PF_RANDMMAP	(1U << 14)	/* Enable  RANDMMAP */
#define PF_NORANDMMAP	(1U << 15)	/* Disable RANDMMAP */

#endif

#define PF_PAX_MASK	0xFFF0U

#endif
