/*
 * PaX control
 * Copyright 2004,2005,2006,2007,2009,2010,2011,2012,2014 PaX Team <pageexec@freemail.hu>
 * Licensed under the GNU GPL version 2
 */

#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <ctype.h>
#include <getopt.h>
#include <elf.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "paxctl.h"

static void report_flags(const Elf64_Word flags, const struct pax_state * const state)
{
  static const struct pax_flags {
    const char * longname;
    unsigned int flag;
    char shortname;
  } pax_flags[] = {
    { "PAGEEXEC", PF_PAGEEXEC, 'P' },
    { "SEGMEXEC", PF_SEGMEXEC, 'S' },
    { "MPROTECT", PF_MPROTECT, 'M' },
    { "RANDEXEC", PF_RANDEXEC, 'X' },
    { "EMUTRAMP", PF_EMUTRAMP, 'E' },
    { "RANDMMAP", PF_RANDMMAP, 'R' },
  };

  const unsigned int num_pax_flags = sizeof pax_flags / sizeof pax_flags[0];
  char buffer[2 * num_pax_flags + 1];
  unsigned int i;

  /* the logic is: lower case: explicitly disabled, upper case: explicitly enabled, - : default */
  memset(buffer, '-', sizeof buffer - 1);
  for (i = 0U; i < num_pax_flags; i++) {
    if (flags & pax_flags[i].flag)        buffer[2*i]   = pax_flags[i].shortname;
    if (flags & (pax_flags[i].flag << 1)) buffer[2*i+1] = pax_flags[i].shortname | 0x20;
  }
  buffer[sizeof buffer - 1] = 0;

  fprintf(stdout, "- PaX flags: %s [%s]\n", buffer, state->argv[state->files]);

  if (state->shortonly)
    return;

  for (i = 0U; i < num_pax_flags; i++) {
    if (flags & pax_flags[i].flag)        fprintf(stdout, "\t%s is enabled\n", pax_flags[i].longname);
    if (flags & (pax_flags[i].flag << 1)) fprintf(stdout, "\t%s is disabled\n", pax_flags[i].longname);
  }
}

#define PAXCTL_ELF_BITS 32
#include "paxctl-elf.c"
#undef PAXCTL_ELF_BITS

#define PAXCTL_ELF_BITS 64
#include "paxctl-elf.c"
#undef PAXCTL_ELF_BITS

static void banner(void)
{
  fprintf(stderr,
    "PaX control v" PAXCTL_VERSION "\n"
    "Copyright 2004,2005,2006,2007,2009,2010,2011,2012,2014 PaX Team <pageexec@freemail.hu>\n\n");
}

static void usage(void)
{
  banner();
  fprintf(stderr,
    "usage: paxctl <options> <files>\n\n"
    "options:\n"
    "\t-p: disable PAGEEXEC\t\t-P: enable PAGEEXEC\n"
    "\t-e: disable EMUTRAMP\t\t-E: enable EMUTRAMP\n"
    "\t-m: disable MPROTECT\t\t-M: enable MPROTECT\n"
    "\t-r: disable RANDMMAP\t\t-R: enable RANDMMAP\n"
    "\t-x: disable RANDEXEC\t\t-X: enable RANDEXEC\n"
    "\t-s: disable SEGMEXEC\t\t-S: enable SEGMEXEC\n\n"
    "\t-v: view flags\t\t\t-z: restore default flags\n"
    "\t-q: suppress error messages\t-Q: report flags in short format\n"
    "\t-c: convert PT_GNU_STACK into PT_PAX_FLAGS (see manpage!)\n"
    "\t-C: create PT_PAX_FLAGS (see manpage!)\n"
  );
  exit(EXIT_FAILURE);
}

static int pax_verify_file(struct pax_state * const state)
{
  int fd, oflags, mflags;
  struct stat st;

  if (state->flags_on | state->flags_off | state->convert | state->create) {
    oflags = O_RDWR;
    mflags = PROT_READ | PROT_WRITE;
  } else {
    oflags = O_RDONLY;
    mflags = PROT_READ;
  }

  fd = open(state->argv[state->files], oflags);
  if (-1 == fd) {
    if (!state->quiet)
      perror(state->argv[state->files]);
    return EXIT_FAILURE;
  }

  if (-1 == fstat(fd, &st)) {
    close(fd);
    if (!state->quiet)
      perror(state->argv[state->files]);
    return EXIT_FAILURE;
  }

  if (st.st_size < 0 || LONG_MAX < st.st_size) {
    close(fd);
    if (!state->quiet)
      fprintf(stderr, "file %s is too big\n", state->argv[state->files]);
    return EXIT_FAILURE;
  }
  state->size = (size_t)st.st_size;
  state->map = mmap(NULL, state->size, mflags, MAP_SHARED, fd, (off_t)0);
  if (MAP_FAILED == state->map) {
    state->map = NULL;
    state->size = 0;
    close(fd);
    if (!state->quiet)
      perror(state->argv[state->files]);
    return EXIT_FAILURE;
  }

  if (state->size < sizeof(Elf64_Ehdr) || (!is_elf32(state) && !is_elf64(state))) {
    munmap(state->map, (size_t)st.st_size);
    state->map = NULL;
    state->size = 0;
    close(fd);
    if (!state->quiet)
      fprintf(stderr, "file %s is not a valid ELF executable\n", state->argv[state->files]);
    return EXIT_FAILURE;
  }

  state->fd = fd;

  return EXIT_SUCCESS;
}

static int pax_process_file(struct pax_state * const state)
{
  int ret = EXIT_FAILURE;

  /* get/verify ELF header */
  if (EXIT_SUCCESS == pax_verify_file(state)) {
    /* report/modify program header */
    ret = state->ops->modify_phdr(state);

    munmap(state->map, state->size);
    close(state->fd);
    state->map = NULL;
    state->size = 0;
    state->fd = -1;
  }

  return ret;
}

static int pax_process_files(struct pax_state * const state)
{
  int status = EXIT_SUCCESS;

  while (state->argv[state->files]) {
    if (EXIT_SUCCESS != pax_process_file(state))
        status = EXIT_FAILURE;
    ++state->files;
  }

  return status;
}

static int pax_parse_args(int argc, struct pax_state * const state)
{
  while (1) {
    switch(getopt(argc, state->argv, "pPsSmMeErRxXvqQzcC")) {
    case -1:
      state->files = (unsigned int)optind;
      return optind < argc ? EXIT_SUCCESS : EXIT_FAILURE;

    case '?':
      return EXIT_FAILURE;

#define parse_flag(option1, option2, flag)		\
    case option1:					\
      state->flags_on &= (unsigned int)~PF_##flag;	\
      state->flags_on |= PF_NO##flag;			\
      state->flags_off &= (unsigned int)~PF_NO##flag;	\
      state->flags_off |= PF_##flag;			\
      break;						\
    case option2:					\
      state->flags_on &= (unsigned int)~PF_NO##flag;	\
      state->flags_on |= PF_##flag;			\
      state->flags_off &= (unsigned int)~PF_##flag;	\
      state->flags_off |= PF_NO##flag;			\
      break;

    parse_flag('p', 'P', PAGEEXEC);
    parse_flag('s', 'S', SEGMEXEC);
    parse_flag('m', 'M', MPROTECT);
    parse_flag('e', 'E', EMUTRAMP);
    parse_flag('r', 'R', RANDMMAP);
    parse_flag('x', 'X', RANDEXEC);

#undef parse_flag

    case 'v':
      state->view = 1;
      break;

    case 'q':
      state->quiet = 1;
      break;

    case 'Q':
      state->shortonly = 1;
      break;

    case 'z':
      state->flags_on = 0U;
      state->flags_off = PF_PAX_MASK;
      break;

    case 'c':
      state->convert = 1;
      break;

    case 'C':
      state->create = 1;
      break;
    }
  }
}

int main(int argc, char * argv[])
{
  struct pax_state state = {
    .argv = argv,
    .flags_on = 0U,
    .flags_off = 0U,
    .files = 0U,
    .quiet = 0,
    .shortonly = 0,
    .view = 0,
    .convert = 0,
    .create = 0,
    .ops = NULL,
    .map = NULL,
    .size = 0,
    .fd = -1,
  };

  if (3 > argc)
    usage();

  /* parse arguments */
  if (EXIT_SUCCESS != pax_parse_args(argc, &state))
    return EXIT_FAILURE;

  if (state.view)
    banner();

  /* process files */
  return pax_process_files(&state);
}
