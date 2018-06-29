/*
 * PaX control ELF support
 * Copyright 2004,2005,2006,2007,2009,2010,2011,2014 PaX Team <pageexec@freemail.hu>
 * Licensed under the GNU GPL version 2
 */

#ifndef PAXCTL_ELF_BITS
#error do not use this file directly!
#else

#define ElfW(prefix, postfix) _ElfW(prefix, PAXCTL_ELF_BITS, postfix)
#define _ElfW(prefix, bits, postfix) _ElfW_(prefix, bits, postfix)
#define _ElfW_(prefix, bits, postfix) prefix##bits##postfix

static int ElfW(elf, _modify_phdr) (struct pax_state * const state)
{
  unsigned int i, pt_phdr, pt_load, gnu_stack, pax_flags;
  ElfW(Elf, _Phdr) * phdr = state->ops->phdr.ElfW(_, );
  ElfW(Elf, _Shdr) * shdr = state->ops->shdr.ElfW(_, );

  /* init phdr info */
  pt_phdr = state->ops->phnum.ElfW(_, );
  pt_load = state->ops->phnum.ElfW(_, );
  gnu_stack = state->ops->phnum.ElfW(_, );
  pax_flags = state->ops->phnum.ElfW(_, );

  /* verify shdr info */
  for (i = 0U; i < state->ops->shnum.ElfW(_, ); i++) {
    if (SHT_NULL == shdr[i].sh_type)
      continue;

    if ((shdr[i].sh_addralign && (~(shdr[i].sh_addralign - 1) + shdr[i].sh_addralign)) ||
        (shdr[i].sh_addralign && shdr[i].sh_addr && (shdr[i].sh_addr & (shdr[i].sh_addralign - 1))) ||
        (shdr[i].sh_addr && shdr[i].sh_addr + shdr[i].sh_size < shdr[i].sh_addr) ||
        shdr[i].sh_offset < sizeof(ElfW(Elf, _Ehdr)) + sizeof(ElfW(Elf, _Phdr)) * state->ops->phnum.ElfW(_, ) ||
        shdr[i].sh_offset + shdr[i].sh_size < shdr[i].sh_offset ||
        (SHT_NOBITS != shdr[i].sh_type && shdr[i].sh_offset + shdr[i].sh_size > state->size))
    {
      if (!state->quiet)
        fprintf(stderr, "file %s is not a valid ELF executable (invalid SHT_ entry:%u)\n", state->argv[state->files], i);
      return EXIT_FAILURE;
    }
  }

  /* gather/verify phdr info */
  for (i = 0U; i < state->ops->phnum.ElfW(_, ); i++) {
    if ((phdr[i].p_align && (~(phdr[i].p_align - 1) + phdr[i].p_align)) ||
        (phdr[i].p_align && ((phdr[i].p_offset ^ phdr[i].p_vaddr) & (phdr[i].p_align - 1))) ||
        phdr[i].p_vaddr + phdr[i].p_memsz < phdr[i].p_vaddr ||
        phdr[i].p_offset + phdr[i].p_filesz < phdr[i].p_offset ||
        phdr[i].p_offset + phdr[i].p_filesz > state->size ||
        phdr[i].p_filesz > phdr[i].p_memsz)
    {
      if (!state->quiet)
        fprintf(stderr, "file %s is not a valid ELF executable (invalid PT_ entry:%u)\n", state->argv[state->files], i);
      return EXIT_FAILURE;
    }

    switch (phdr[i].p_type) {
    case PT_PHDR:
      if (pt_phdr == state->ops->phnum.ElfW(_, )) {
        if (pt_load != state->ops->phnum.ElfW(_, )) {
          if (!state->quiet)
            fprintf(stderr, "file %s is not a valid ELF executable (PT_LOAD before PT_PHDR)\n", state->argv[state->files]);
          return EXIT_FAILURE;
        }
        pt_phdr = i;
      } else {
        if (!state->quiet)
          fprintf(stderr, "file %s is not a valid ELF executable (more than one PT_PHDR)\n", state->argv[state->files]);
        return EXIT_FAILURE;
      }
      break;

    case PT_LOAD:
      if (pt_load == state->ops->phnum.ElfW(_, ))
        pt_load = i;
      break;

    case PT_PAX_FLAGS:
      if (pax_flags != state->ops->phnum.ElfW(_, )) {
        if (!state->quiet)
          fprintf(stderr, "file %s is not a valid ELF executable (more than one PT_PAX_FLAGS)\n", state->argv[state->files]);
        return EXIT_FAILURE;
      }
      pax_flags = i;
      break;

    case PT_GNU_STACK:
      if (gnu_stack != state->ops->phnum.ElfW(_, )) {
        if (!state->quiet)
          fprintf(stderr, "file %s is not a valid ELF executable (more than one PT_GNU_STACK)\n", state->argv[state->files]);
        return EXIT_FAILURE;
      }
      gnu_stack = i;
      break;
    }
  }

  /* verify phdr info */
  if (pt_load == state->ops->phnum.ElfW(_, )) {
    if (!state->quiet)
      fprintf(stderr, "file %s is not a valid ELF executable (no PT_LOAD found)\n", state->argv[state->files]);
    return EXIT_FAILURE;
  }

  if (pt_phdr < state->ops->phnum.ElfW(_, )) {
    if (phdr[pt_phdr].p_vaddr + phdr[pt_phdr].p_memsz <= phdr[pt_load].p_vaddr ||
        phdr[pt_load].p_vaddr + phdr[pt_load].p_memsz <= phdr[pt_phdr].p_vaddr) {
      if (!state->quiet)
        fprintf(stderr, "file %s is not a valid ELF executable (PT_PHDR is outside of first PT_LOAD)\n", state->argv[state->files]);
      return EXIT_FAILURE;
    }
  }

  /* convert PT_GNU_STACK if necessary/possible */
  if (pax_flags == state->ops->phnum.ElfW(_, ) && state->convert) {
    if (gnu_stack < state->ops->phnum.ElfW(_, )) {
      pax_flags = gnu_stack;
      phdr[pax_flags].p_type = PT_PAX_FLAGS;
      phdr[pax_flags].p_flags = PF_NORANDEXEC | PF_NOEMUTRAMP;
      if (!state->quiet)
        fprintf(stderr, "file %s had a PT_GNU_STACK program header, converted\n", state->argv[state->files]);
    } else {
      if (!state->quiet)
        fprintf(stderr, "file %s does not have a PT_GNU_STACK program header, conversion failed\n", state->argv[state->files]);
    }
  }

  /* create PT_PAX_FLAGS if necessary/possible */
  if (pax_flags == state->ops->phnum.ElfW(_, ) && state->create) {
    ElfW(Elf, _Ehdr) * ehdr = (ElfW(Elf, _Ehdr) *)state->map;
    ElfW(Elf, _Word) shift;

    if (phdr[pt_load].p_align != (ElfW(Elf, _Word))phdr[pt_load].p_align) {
        if (!state->quiet)
          fprintf(stderr, "file %s has a too big alignment, creation failed\n", state->argv[state->files]);
        return EXIT_FAILURE;
    }
    shift = (ElfW(Elf, _Word))phdr[pt_load].p_align;

    if (shift == phdr[pt_load].p_vaddr) {
      shift >>= 1;
      if (!state->quiet)
        fprintf(stderr, "file %s will be realigned, beware\n", state->argv[state->files]);
    }

    if ((pt_phdr == state->ops->phnum.ElfW(_, ) ||
        (phdr[pt_phdr].p_offset == sizeof(ElfW(Elf, _Ehdr)) &&
         phdr[pt_phdr].p_align < shift &&
         phdr[pt_phdr].p_memsz + sizeof(ElfW(Elf, _Phdr)) < phdr[pt_load].p_memsz)) &&
        phdr[pt_load].p_vaddr > shift &&
        ehdr->e_machine != EM_IA_64 &&
        state->size + shift > shift)
    {
      unsigned char * newmap;
      ElfW(Elf, _Phdr) * newphdr;

      /* unmap old mapping with old size */
      if (-1 == munmap(state->map, state->size)) {
        if (!state->quiet)
          perror(state->argv[state->files]);
        return EXIT_FAILURE;
      }

      /* set up new size */
      state->size += shift;

      /* adjust underlying file size */
      if (-1 == ftruncate(state->fd, (off_t)state->size)) {
        if (!state->quiet)
          perror(state->argv[state->files]);
        return EXIT_FAILURE;
      }

      /* map underlying file again with the new size */
      newmap = mmap(NULL, state->size, PROT_READ | PROT_WRITE, MAP_SHARED, state->fd, (off_t)0);
      if (MAP_FAILED == newmap) {
        if (!state->quiet)
          perror(state->argv[state->files]);
        return EXIT_FAILURE;
      }

      /* adjust pointers based on the new mapping */
      phdr = state->ops->phdr.ElfW(_, ) = (ElfW(Elf, _Phdr) *)((unsigned char*)phdr + (newmap - state->map));
      if (shdr)
        shdr = state->ops->shdr.ElfW(_, ) = (ElfW(Elf, _Shdr) *)((unsigned char*)shdr + (newmap - state->map));
      state->map = newmap;
      ehdr = (ElfW(Elf, _Ehdr) *)state->map;

      /* make room for the new PHDR */
      memmove(state->map + shift, state->map, state->size - shift);
      memset(state->map + sizeof(ElfW(Elf, _Ehdr)), 0, shift - sizeof(ElfW(Elf, _Ehdr)));

      /* adjust pointers again */
      phdr = state->ops->phdr.ElfW(_, ) = (ElfW(Elf, _Phdr) *)((unsigned char*)phdr + shift);
      if (shdr)
        shdr = state->ops->shdr.ElfW(_, ) = (ElfW(Elf, _Shdr) *)((unsigned char*)shdr + shift);

      /* adjust file offsets: ehdr */
      if (shdr)
        ehdr->e_shoff += shift;

      /* adjust file offsets: phdr */
      newphdr = (ElfW(Elf, _Phdr) *)(state->map + ehdr->e_phoff);
      for (i = 0; i < state->ops->phnum.ElfW(_, ); i++) {
        newphdr[i] = phdr[i];
        if (newphdr[i].p_offset >= sizeof(ElfW(Elf, _Ehdr)) + sizeof(ElfW(Elf, _Phdr)) * state->ops->phnum.ElfW(_, ))
          newphdr[i].p_offset += shift;
        else if (newphdr[i].p_vaddr >= phdr[pt_load].p_vaddr) {
          newphdr[i].p_vaddr -= shift;
          newphdr[i].p_paddr -= shift;
        }
        if (newphdr[i].p_align > shift)
          newphdr[i].p_align = shift;
      }
      if (newphdr[pt_load].p_offset < sizeof(ElfW(Elf, _Ehdr)) + sizeof(ElfW(Elf, _Phdr)) * state->ops->phnum.ElfW(_, )) {
        newphdr[pt_load].p_memsz += shift;
        newphdr[pt_load].p_filesz += shift;
      }

      /* the moment of truth */
      pax_flags = i;
      newphdr[pax_flags].p_type = PT_PAX_FLAGS;
      newphdr[pax_flags].p_flags = PF_NORANDEXEC | PF_NOEMUTRAMP;
      newphdr[pax_flags].p_align = 4;
      if (pt_phdr < state->ops->phnum.ElfW(_, )) {
        newphdr[pt_phdr].p_memsz += (ElfW(Elf, _Word))sizeof(ElfW(Elf, _Phdr));
        newphdr[pt_phdr].p_filesz += (ElfW(Elf, _Word))sizeof(ElfW(Elf, _Phdr));
      } else
        pt_phdr++;
      ++ehdr->e_phnum;
      ++state->ops->phnum.ElfW(_, );
      phdr = newphdr;

      /* adjust file offsets: shdr */
      for (i = 0; i < state->ops->shnum.ElfW(_, ); i++) {
        if (shdr[i].sh_offset)
          shdr[i].sh_offset += shift;
      }

      if (!state->quiet)
        fprintf(stderr, "file %s got a new PT_PAX_FLAGS program header\n", state->argv[state->files]);
    }
    if (pax_flags == state->ops->phnum.ElfW(_, )) {
      if (!state->quiet)
        fprintf(stderr, "file %s cannot have a PT_PAX_FLAGS program header, creation failed\n", state->argv[state->files]);
    }
  }

  if (pax_flags == state->ops->phnum.ElfW(_, )) {
    if (!state->quiet && !state->convert && !state->create)
      fprintf(stderr, "file %s does not have a PT_PAX_FLAGS program header, try conversion\n", state->argv[state->files]);
    return EXIT_FAILURE;
  }

  if (state->view)
    report_flags(phdr[pax_flags].p_flags, state);
  if (state->flags_on | state->flags_off) {
    const ElfW(Elf, _Ehdr) * const ehdr = (const ElfW(Elf, _Ehdr) *)state->map;

    if (ehdr->e_type == ET_DYN) {
      phdr[pax_flags].p_flags &= ~((state->flags_off | PF_RANDEXEC) & (ElfW(Elf, _Word))~PF_NORANDEXEC);
      phdr[pax_flags].p_flags |= (state->flags_on | PF_NORANDEXEC) & (ElfW(Elf, _Word))~PF_RANDEXEC;
    } else {
      phdr[pax_flags].p_flags &= ~state->flags_off;
      phdr[pax_flags].p_flags |= state->flags_on;
    }
  }
  return EXIT_SUCCESS;
}

static struct ElfW(elf_ops elf, ) = {
  .modify_phdr = ElfW(elf, _modify_phdr),
};

static int ElfW(is_elf, )(struct pax_state * const state)
{
  const ElfW(Elf, _Ehdr) * const ehdr = (const ElfW(Elf, _Ehdr) *)state->map;

  if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG))
    return 0;
  if (ehdr->e_ehsize != sizeof(ElfW(Elf, _Ehdr)))
    return 0;
  if ((ehdr->e_version != EV_CURRENT) || (ehdr->e_ident[EI_CLASS] != ElfW(ELFCLASS, )))
    return 0;
  if ((ehdr->e_type != ET_EXEC) && (ehdr->e_type != ET_DYN))
    return 0;

  if (!ehdr->e_phoff || !ehdr->e_phnum || sizeof(ElfW(Elf, _Phdr)) != ehdr->e_phentsize)
    return 0;
  if (ehdr->e_phnum > 65536U / ehdr->e_phentsize - 1)
    return 0;
  if (ehdr->e_phoff > ehdr->e_phoff + (ElfW(Elf, _Off))ehdr->e_phentsize * ehdr->e_phnum)
    return 0;
  if (state->size < ehdr->e_phoff + (ElfW(Elf, _Off))ehdr->e_phentsize * ehdr->e_phnum)
    return 0;

  if (ehdr->e_shoff) {
    if (!ehdr->e_shnum || sizeof(ElfW(Elf, _Shdr)) != ehdr->e_shentsize)
      return 0;
    if (ehdr->e_shnum > 65536U / ehdr->e_shentsize)
      return 0;
    if (ehdr->e_shoff > ehdr->e_shoff + (ElfW(Elf, _Off))ehdr->e_shentsize * ehdr->e_shnum)
      return 0;
    if ((Elf32_Off)state->size < ehdr->e_shoff + (ElfW(Elf, _Off))ehdr->e_shentsize * ehdr->e_shnum)
      return 0;
  }

  state->ops = &ElfW(elf, );
  state->ops->phdr.ElfW(_, ) = (ElfW(Elf, _Phdr) *)(state->map + ehdr->e_phoff);
  state->ops->phnum.ElfW(_, ) = ehdr->e_phnum;
  if (ehdr->e_shoff) {
    state->ops->shdr.ElfW(_, ) = (ElfW(Elf, _Shdr) *)(state->map + ehdr->e_shoff);
    state->ops->shnum.ElfW(_, ) = ehdr->e_shnum;
  } else {
    state->ops->shdr.ElfW(_, ) = NULL;
    state->ops->shnum.ElfW(_, ) = 0;
  }

  return 1;
}

#undef _ElfW_
#undef _ElfW
#undef ElfW
#endif
