/*
 * This piece of src contains the hardcore functions that do process
 * reconstruction back into ELF object and such, and are used by Quenyas
 * unpacking features
 * Author: Ryan O'Neill (C) 2010
 */

#include "elfmod.h"

#define INIT_INDEX 11 /* .init is index 11 in dynamic ET_EXEC (usually) */
/* Dump process image to ET_EXEC */

char shstrtable[] =
"\0"
".interp\0"
".hash\0"
".note.ABI-tag\0"
".gnu.hash\0"
".dynsym\0"
".dynstr\0"
".gnu.version\0"
".gnu.version_r\0"
".rel.dyn\0"
".rel.plt\0"  
".init\0"
".plt\0"
".text\0"
".fini\0"
".rodata\0"
".eh_frame_hdr\0"
".eh_frame\0"
".ctors\0"
".dtors\0"
".jcr\0"
".dynamic\0"
".got\0"
".got.plt\0"
".data\0"
".bss\0"
".shstrtab\0"
".symtab\0"
".strtab\0";

unsigned long memrw(unsigned long *buf, unsigned long vaddr, unsigned int size, int pid)
{
        int i, j, data;
        int ret;
        int ptr = vaddr;

        for (i = 0, j = 0; i < size; i+= sizeof(uint32_t), j++)
        {
                /* PTRACE_PEEK can return -1 on success, check errno */
                if(((data = ptrace(PTRACE_PEEKTEXT, pid, vaddr + i)) == -1) && errno)
                        return -1;
                buf[j] = data;
        }
        return i;
}


int PDump2ELF(int pid, char *name)
{
	/* ultimately I'm going to compile the ptrace lib static */
	/* or create a central function for loading the shared objects */
	/* rather than do it for each function that uses it. This is just */
	/* a temporary way to load the lib */
	/*
	int (*ptrace_open)(struct ptrace_context *, pid_t);
	int (*ptrace_close)(struct ptrace_context *);
	int (*ptrace_read)(struct ptrace_context *, void *, void *, size_t);
	void * (*ptrace_elf_get_dynamic_entry)(struct ptrace_context *, struct link_map *, Elf32_Sword);
	char * (*ptrace_errmsg)(struct ptrace_context *);
	void *handle;
	*/
	extern int global_debug;
	Elf32_Addr *GLOBAL_OFFSET_TABLE;

	struct ptrace_context ptc;
	struct pt_load pt_load;

	char *StringTable;
	uint8_t *pmem;
	char *p;
	uint32_t totlen;
	
	Elf32_Dyn *dyn;
	Elf32_Ehdr ehdr, *ep;
	Elf32_Phdr *phdr;
	Elf32_Shdr shdr;
	Elf32_Sym  *symtab;

	Elf32_Addr dynvaddr, interp_vaddr;
	Elf32_Off dynoffset, interp_off;
	uint32_t dynsize, interp_size;

	Elf32_Addr BaseVaddr, index_vaddr = 0, got;
	Elf32_Off got_off;

	int TS, DS, i, j, fd, bss_len = 0;
	void *handle = global_handle;
	uint8_t null = 0;
	
	if (global_debug)
		printf("[+] Accessing process image of pid %d\n", pid);

	if (Ptrace_open(&ptc, pid) == -1)
	{
		printf("ptrace_open(): %s\n", Ptrace_errmsg(&ptc));
		return -1;
	}

	BaseVaddr = 0x8048000;//GetMemoryBase(pid);
	if (!BaseVaddr)
		return -1;

	if (Ptrace_read(&ptc, &ehdr, (void *)BaseVaddr, sizeof(Elf32_Ehdr)) == -1)
	{
		printf("ptrace_read(): %s\n", Ptrace_errmsg(&ptc));
		return -1;
	}
	
	/* allocate just the initial portion of the image to get necessary info */
	/*
	if ((pmem = malloc(sizeof(Elf32_Ehdr) + sizeof(Elf32_Phdr) + 0x100 )) == NULL)
	{
		printf("Unable to allocate sufficient memory: %s\n", strerror(errno));
		return -1;
	}
	*/
	pmem = alloca(sizeof(Elf32_Ehdr) + sizeof(Elf32_Phdr) + 0x100);

	/* Next lets read in just the phdrs and get the exact size of segments */
	if (Ptrace_read(&ptc, pmem, (void *)BaseVaddr, sizeof(Elf32_Ehdr) + ehdr.e_phentsize * ehdr.e_phnum) == -1)
	{
		  printf("ptrace_read(): %s\n", Ptrace_errmsg(&ptc));
   	          return -1;
        }

	printf("[+] Beginning analysis for executable reconstruction of process image (pid: %d)\n", pid);
	printf("[+] Getting Loadable segment info...\n");

	phdr = (Elf32_Phdr *)(pmem + ehdr.e_phoff);
	for (i = 0; i < ehdr.e_phnum; i++)
	{
		if (phdr[i].p_type == PT_LOAD && !phdr[i].p_offset)
		{
			printf("[+] Found loadable segments: text segment, data segment\n");

			/* TEXT */
			pt_load.text_offset = phdr[i].p_offset;
			pt_load.text_filesz = phdr[i].p_filesz;
				
			/* DATA */
			pt_load.data_offset = phdr[i + 1].p_offset;
			pt_load.data_filesz = phdr[i + 1].p_filesz;
			pt_load.data_vaddr =  phdr[i + 1].p_vaddr;
			
			bss_len = phdr[i + 1].p_memsz - phdr[i + 1].p_filesz;

			TS = i;
			DS = i + 1;
		}
		else
		if (phdr[i].p_type == PT_DYNAMIC)
		{
			dynvaddr = phdr[i].p_vaddr;
			dynoffset = phdr[i].p_offset;
			dynsize = phdr[i].p_filesz;
		}
		else
		if (phdr[i].p_type == PT_INTERP)
		{
			interp_vaddr = phdr[i].p_vaddr;
			interp_off = phdr[i].p_offset;
			interp_size = phdr[i].p_filesz;
		}
	}

	totlen = (pt_load.data_offset + pt_load.data_filesz);
	/*
	if ((pmem = realloc(pmem, totlen)) == NULL)
	{
                printf("Unable to allocate sufficient memory: %s\n", strerror(errno));
                return -1;
        }
	*/
	pmem = alloca(totlen);

	if (Ptrace_read(&ptc, pmem, (void *)BaseVaddr, pt_load.text_filesz) == -1)
	{
                  printf("ptrace_read(): %s\n", Ptrace_errmsg(&ptc));
                  return -1;
        }

	if (Ptrace_read(&ptc, (pmem + pt_load.data_offset), (void *)pt_load.data_vaddr, pt_load.data_filesz) == -1)
        {
                  printf("ptrace_read(): %s\n", Ptrace_errmsg(&ptc));
                  return -1;
        }

	ep = (Elf32_Ehdr *)pmem;
	phdr = (Elf32_Phdr *)(pmem + ep->e_phoff);
	dyn = NULL;

	for (i = 0; i < ep->e_phoff; i++)
		if (phdr[i].p_type == PT_DYNAMIC)
		{
			dyn = (Elf32_Dyn *)(pmem + phdr[i].p_offset);
			break;
		}
	
	int plt_siz;
	if (!dyn)
		printf("Unable to locate dynamic segment, assuming no dynamic linking\n");
	else 
	for (i = 0; dyn[i].d_tag != DT_NULL; i++)
	{
		switch(dyn[i].d_tag)
		{
			case DT_PLTGOT:
				printf("Located PLT GOT Vaddr 0x%x\n", got = (Elf32_Addr)dyn[i].d_un.d_ptr);
				printf("Relevant GOT entries begin at 0x%x\n", (Elf32_Addr)dyn[i].d_un.d_ptr + 12);
				
				/* got[0] link_map */
				got_off = dyn[i].d_un.d_ptr - pt_load.data_vaddr;
				
				GLOBAL_OFFSET_TABLE = (Elf32_Addr *)(pmem + pt_load.data_offset + got_off);
				/*
 				 GLOBAL_OFFSET_TABLE[0] -> link_map (DYNAMIC segment)
				 GLOBAL_OFFSET_TABLE[1] -> /lib/ld-2.6.1.so (Runtime linker)
				 GLOBAL_OFFSET_TABLE[2] -> /lib/ld-2.6.1.so (Runtime linker)
				 Lets increment the GOT to __gmon_start__ (Our base PLT entry) */
				GLOBAL_OFFSET_TABLE += 3;
				break;
			case DT_PLTRELSZ:
				plt_siz = dyn[i].d_un.d_val / sizeof(Elf32_Rel);
				break;
			case DT_STRTAB:		
				StringTable = (char *)dyn[i].d_un.d_ptr;
				break;
			case DT_SYMTAB:
				symtab = (Elf32_Sym *)dyn[i].d_un.d_ptr;
				break;	
			
		}
	}

	if (!dyn)
		goto no_dynamic;
	uint8_t *gp = &pmem[pt_load.data_offset + got_off + 4];
	for (i = 0; i < 8; i++)
		*(gp + i) = 0x0;
	
	/* The first entry in the GOT we check should never change (i.e through lazy linking), so we can use it */
	/* as our resolution point for the PLT */

	Elf32_Addr PLT_VADDR = GLOBAL_OFFSET_TABLE[0]; /* gmon_start */
	/*
 	08048300 <__gmon_start__@plt>:
 	8048300:       ff 25 00 a0 04 08       jmp    *0x804a000
 	8048306:       68 00 00 00 00          push   $0x0  <- Here is where PLT_VADDR is  
 	804830b:       e9 e0 ff ff ff          jmp    80482f0 <_init+0x18>
	*/

	printf("[+] Resolved PLT: 0x%x\n", PLT_VADDR);

	/* PLT_VADDR will correlate to the push instruction within each PLT entry */
	/* which is the stub instruction that pushes the relocation offsets onto the stack */
	/* for the dynamic linker... */
	PLT_VADDR += 16;
	
	printf("PLT Entries: %d\n", plt_siz);

	for (j = 1; j < plt_siz; j++)
	{
		printf("Patch #%d - [0x%x] changed to [0x%x]\n", j, GLOBAL_OFFSET_TABLE[j], PLT_VADDR);
		GLOBAL_OFFSET_TABLE[j] = PLT_VADDR;
		PLT_VADDR += 16;
	}	
	
	printf("[+] Patched GOT with PLT stubs\n");	

	no_dynamic:
	
	if ((fd = open(name, O_TRUNC|O_WRONLY|O_CREAT)) == -1)
	{
		printf("Unable to open file for writing: %s\n", strerror(errno));
		return -1;
	}
	
	if (fchmod(fd, 00777) < 0)
		printf("Warning: Unable to set permissions on output file\n");
	
	/* Writing out new executable --
         * [TEXT][DATA (PLT/GOT)][BSS][String Table]
         * The symbol table and string table will not be included 
         */
	
	ep->e_shstrndx = !dyn ? 4 : 6;
	ep->e_shoff = totlen + bss_len + sizeof(shstrtable);
	ep->e_shnum = !dyn ? 5 : 7;
	Elf32_Off shsoff = totlen + bss_len;

	if (write(fd, pmem, totlen) != totlen)
	{
		printf("Unable to write entire data: %s\n", strerror(errno));
		return -1;
	}
	
	int bw;
	if ((bw = write(fd, &null, bss_len)) == -1) //bss_len)
	{
		printf("Unable to create bss padding %d bytes (but only %d written): %s\n", bss_len, bw, strerror(errno));
		return -1;
	}

	totlen += bss_len;
	
	/* Write string table (final section) */
	if (write(fd, (char *)shstrtable, sizeof(shstrtable)) != sizeof(shstrtable))
	{
		printf("Unable to write string table %d bytes: %s\n", strerror(errno));
		return -1;
	}
	
	int slen = sizeof(Elf32_Shdr);

	/* Add NULL section */
	memset(&shdr, 0, slen);	
	shdr.sh_addr = BaseVaddr;
	
	if (write(fd, &shdr, slen) != slen)
        {
                printf("Error in writing section header: %s\n", strerror(errno));
                return -1;
        }

        totlen += slen;
	
	if (!dyn)
		goto no_interp;

	/* Add .interp section */
	shdr.sh_type = SHT_PROGBITS;
	shdr.sh_offset = interp_off;
	shdr.sh_addr = interp_vaddr;
	shdr.sh_flags = SHF_ALLOC;
	shdr.sh_link = 0;
	shdr.sh_info = 0;
	shdr.sh_entsize = 0;
	shdr.sh_size = interp_size;
	shdr.sh_addralign = 0;
	
	for (i = 0, p = shstrtable ;; i++)
                if (p[i] == '.' && p[i + 1] == 'i' && p[i + 2] == 'n' && p[i + 3] == 't' && p[i + 4] == 'e')
                {
                        shdr.sh_name = i;
                        break;
                }

	if (write(fd, &shdr, slen) != slen)
        {
                printf("Error in writing section header: %s\n", strerror(errno));
                return -1;
        }

        totlen += slen;

	no_interp:
	/* Add .text section */
	shdr.sh_type = SHT_PROGBITS;
	shdr.sh_offset = phdr[TS].p_offset;
	shdr.sh_addr = phdr[TS].p_vaddr;
	shdr.sh_flags = SHF_ALLOC | SHF_EXECINSTR;
	shdr.sh_info = 0;
	shdr.sh_link = 0;
	shdr.sh_entsize = 0;
	shdr.sh_size = phdr[TS].p_filesz;
	shdr.sh_addralign = 0xf;

	for (i = 0, p = shstrtable ;; i++)
		if (p[i] == '.' && p[i + 1] == 't' && p[i + 2] == 'e' && p[i + 3] == 'x' && p[i + 4] == 't')
		{
			shdr.sh_name = i;
			break;
		}
	if (write(fd, &shdr, slen) != slen)
	{
		printf("Error in writing section header: %s\n", strerror(errno));
		return -1;
	}
	
	totlen += slen;

	/* Add .data section */
	shdr.sh_type = SHT_PROGBITS;
        shdr.sh_offset = phdr[DS].p_offset;
        shdr.sh_addr = phdr[DS].p_vaddr;
        shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
        shdr.sh_info = 0;
        shdr.sh_link = 0;
        shdr.sh_entsize = 0;
	shdr.sh_size = phdr[DS].p_filesz;
	shdr.sh_addralign = 4;

	for (i = 0, p = shstrtable ;; i++)
                if (p[i] == '.' && p[i + 1] == 'd' && p[i + 2] == 'a' && p[i + 3] == 't' && p[i + 4] == 'a')
                {
		        shdr.sh_name = i;
			break;
		}
	
	if (write(fd, &shdr, slen) != slen)
        {
                printf("Error in writing section header: %s\n", strerror(errno));
                return -1;
        }

	totlen += slen;

	if (!dyn)
		goto no_dynam_section;

	/* Add .dynamic section */
	shdr.sh_type = SHT_DYNAMIC;
        shdr.sh_offset = dynoffset;
        shdr.sh_addr = dynvaddr;
        shdr.sh_flags = SHF_WRITE | SHF_ALLOC;
        shdr.sh_info = 0;
        shdr.sh_link = 0;
        shdr.sh_entsize = 8;
        shdr.sh_size = dynsize;
	shdr.sh_addralign = 4;

	for (i = 0, p = shstrtable ;; i++)
                if (p[i] == '.' && p[i + 1] == 'd' && p[i + 2] == 'y' && p[i + 3] == 'n' && p[i + 4] == 'a' 
		 		&& p[i + 5] == 'm' && p[i + 6] == 'i' && p[i + 7] == 'c')
                {
		        shdr.sh_name = i;
			break;
		}

	if (write(fd, &shdr, slen) != slen)
        {
                printf("Error in writing section header: %s\n", strerror(errno));
                return -1;
        }
        totlen += slen;
	
	no_dynam_section:

	/* Add .bss section */
	shdr.sh_type = SHT_NOBITS;
        shdr.sh_offset = phdr[DS].p_offset + phdr[DS].p_filesz;
        shdr.sh_addr = phdr[DS].p_vaddr + phdr[DS].p_filesz;
        shdr.sh_flags = SHF_WRITE | SHF_ALLOC;
        shdr.sh_info = 0;
        shdr.sh_link = 0;
        shdr.sh_entsize = 0;
        shdr.sh_size = bss_len;
	shdr.sh_addralign = 4;

        for (i = 0, p = shstrtable ;; i++)
                if (p[i] == '.' && p[i + 1] == 'b' && p[i + 2] == 's' && p[i + 3] == 's')
                {
                        shdr.sh_name = i;
                        break;
                }

        if (write(fd, &shdr, slen) != slen)
        {
                printf("Error in writing section header: %s\n", strerror(errno));
                return -1;
        }
        totlen += slen;

	/* add .shstrtab */
	shdr.sh_type = SHT_STRTAB;
	shdr.sh_offset = shsoff;
	shdr.sh_addr = BaseVaddr + shsoff;
	shdr.sh_flags = 0;
	shdr.sh_info = 0;
	shdr.sh_link = 0;
	shdr.sh_entsize = 0;
	shdr.sh_size = sizeof(shstrtable);
	shdr.sh_addralign = 1;

	for (i = 0, p = shstrtable ;; i++)
                if (p[i] == '.' && p[i + 1] == 's' && p[i + 2] == 'h' && p[i + 3] == 's' && p[i + 4] == 't')
                {
                        shdr.sh_name = i;
                        break;
                }

	if (write(fd, &shdr, slen) != slen)
        {
                printf("Error in writing section header: %s\n", strerror(errno));
                return -1;
        }
        totlen += slen;
	
	Ptrace_close(&ptc);
	close(fd);
}

/* Same function as above but designed to unpack a process that quenya executes itself */
int PDump2ELF_child(int pid, char *filename)
{
        extern int global_debug;
        Elf32_Addr *GLOBAL_OFFSET_TABLE;

        struct ptrace_context ptc;
        struct pt_load pt_load;

        char *StringTable;
        uint8_t *pmem;
        char *p;
        uint32_t totlen;

        Elf32_Dyn *dyn;
        Elf32_Ehdr ehdr, *ep;
        Elf32_Phdr *phdr;
        Elf32_Shdr shdr;
        Elf32_Sym  *symtab;

        Elf32_Addr dynvaddr, interp_vaddr;
        Elf32_Off dynoffset, interp_off;
        uint32_t dynsize, interp_size;

        Elf32_Addr BaseVaddr, index_vaddr = 0, got;
        Elf32_Off got_off = 0x0;

        int TS, DS, i, j, fd, bss_len = 0, found_loadables = 0;
        void *handle = global_handle;
        uint8_t null = 0;
	long word;

	char outfile[255];
	
	snprintf(outfile, sizeof(outfile) - 9, "%s.unpacked", filename);

        if (global_debug)
                printf("[+] Accessing process image of pid %d\n", pid);


        BaseVaddr = 0x8048000;//GetMemoryBase(pid);
        if (!BaseVaddr)
                return -1;

        /* allocate just the initial portion of the image to get necessary info */
        /*
	if ((pmem = malloc(sizeof(Elf32_Ehdr) + sizeof(Elf32_Phdr) + 0x100 )) == NULL)
        {
                printf("Unable to allocate sufficient memory: %s\n", strerror(errno));
                return -1;
        }
	*/

	pmem = alloca(sizeof(Elf32_Ehdr) + sizeof(Elf32_Phdr) + 0x100); 

	memrw((unsigned long *)&ehdr, BaseVaddr, sizeof(Elf32_Ehdr), pid);
	memrw((unsigned long *)pmem, BaseVaddr, sizeof(Elf32_Ehdr) + ehdr.e_phentsize * ehdr.e_phnum, pid);
	
        printf("[+] Beginning analysis for executable reconstruction of process image (pid: %d)\n", pid);
        printf("[+] Getting Loadable segment info...\n");

	if (global_debug)
	{
		for (i = 0; i < 16; i++)
			printf("%02x ", pmem[i]);
		printf("\n");
	}
        phdr = (Elf32_Phdr *)(pmem + ehdr.e_phoff);
        for (i = 0; i < ehdr.e_phnum; i++)
        {
                if (phdr[i].p_type == PT_LOAD && !phdr[i].p_offset)
                {
                        printf("[+] Found loadable segments: text segment, data segment\n");

                        /* TEXT */
                        pt_load.text_offset = phdr[i].p_offset;
                        pt_load.text_filesz = phdr[i].p_filesz;

			if (phdr[i + 1].p_type != PT_LOAD)
			{
				TS = i;
				found_loadables = 1;
				break;
			}
                        /* DATA */
                        pt_load.data_offset = phdr[i + 1].p_offset;
                        pt_load.data_filesz = phdr[i + 1].p_filesz;
                        pt_load.data_vaddr =  phdr[i + 1].p_vaddr;

                        bss_len = phdr[i + 1].p_memsz - phdr[i + 1].p_filesz;
			
			printf("[+] text_vaddr: 0x%x text_offset: 0x%x\n[+] data_vaddr: 0x%x data_offset: 0x%x\n",
			phdr[i].p_vaddr, phdr[i].p_offset, phdr[i+1].p_vaddr, phdr[i+1].p_offset);

                        TS = i;
                        DS = i + 1;
			found_loadables = 1;
                }
                else
                if (phdr[i].p_type == PT_DYNAMIC)
                {
                        dynvaddr = phdr[i].p_vaddr;
                        dynoffset = phdr[i].p_offset;
                        dynsize = phdr[i].p_filesz;
                }
                else
                if (phdr[i].p_type == PT_INTERP)
                {
                        interp_vaddr = phdr[i].p_vaddr;
                        interp_off = phdr[i].p_offset;
                        interp_size = phdr[i].p_filesz;
                }
        }
	
	if (found_loadables == 0)
	{
		printf("Could not find loadable segments, failure...\n");
		return -1;
	}

        totlen = (pt_load.data_offset + pt_load.data_filesz);
 
        pmem = alloca(totlen);
	/*
	if ((pmem = realloc(pmem, totlen)) == NULL)
        {
                printf("Unable to allocate sufficient memory: %s\n", strerror(errno));
                return -1;
        }
	*/
	memrw((unsigned long *)pmem, BaseVaddr, pt_load.text_filesz, pid);
	memrw((unsigned long *)&pmem[pt_load.data_offset], pt_load.data_vaddr, pt_load.data_filesz, pid);
		

        ep = (Elf32_Ehdr *)pmem;
        phdr = (Elf32_Phdr *)(pmem + ep->e_phoff);
        dyn = NULL;

        for (i = 0; i < ep->e_phoff; i++)
                if (phdr[i].p_type == PT_DYNAMIC)
                {
                        dyn = (Elf32_Dyn *)(pmem + phdr[i].p_offset);
                        break;
                }
	
	printf("[+] Dynamic segment location %s\n", dyn ? "successful" : "unsuccessful");
	got_off = 0;
	
	int plt_siz = 0;

        if (!dyn)
                printf("Unable to locate dynamic segment, assuming no dynamic linking\n");
        else
        for (i = 0; dyn[i].d_tag != DT_NULL; i++)
        {
                switch(dyn[i].d_tag)
                {
                        case DT_PLTGOT:
                                printf("Located PLT GOT Vaddr 0x%x\n", got = (Elf32_Addr)dyn[i].d_un.d_ptr);
                                printf("Relevant GOT entries begin at 0x%x\n", (Elf32_Addr)dyn[i].d_un.d_ptr + 12);

                                /* got[0] link_map */
                                got_off = dyn[i].d_un.d_ptr - pt_load.data_vaddr;
				
				printf("[+] GOT[0] (link_map): 0x%x\n", got_off);

                                GLOBAL_OFFSET_TABLE = (Elf32_Addr *)(pmem + pt_load.data_offset + got_off);
                                GLOBAL_OFFSET_TABLE += 3;
                                break;
			case DT_PLTRELSZ:
				plt_siz = dyn[i].d_un.d_val / sizeof(Elf32_Rel);
				break;
                        case DT_STRTAB:
                                StringTable = (char *)dyn[i].d_un.d_ptr;
                                break;
                        case DT_SYMTAB:
                                symtab = (Elf32_Sym *)dyn[i].d_un.d_ptr;
                                break;

                }
        }

        if (!dyn)
                goto no_dynamic;
		
	printf("[+] PLT/GOT Location: %s\n", got_off ? "Successful" : "Failed");	
	
	if (got_off == 0)
	{
		printf("[+] Could not locate PLT/GOT within dynamic segment; attempting to skip PLT patches...\n");
		goto no_dynamic;	
	}

        uint8_t *gp = &pmem[pt_load.data_offset + got_off + 4];
        for (i = 0; i < 8; i++)
                *(gp + i) = 0x0;

        /* The first entry in the GOT we check should never change (i.e through lazy linking), so we can use it */
        /* as our resolution point for the PLT */

	Elf32_Addr PLT_VADDR = GLOBAL_OFFSET_TABLE[0]; 
        printf("[+] Resolved PLT: 0x%x\n", PLT_VADDR);

        /* PLT_VADDR will correlate to the push instruction within each PLT entry */
        /* which is the stub instruction that pushes the relocation offsets onto the stack */
        /* for the dynamic linker... */
        PLT_VADDR += 16;
	
	printf("PLT Entries: %d\n", plt_siz);

        for (j = 1; j < plt_siz; j++)
        {
                printf("Patch #%d - [0x%x] changed to [0x%x]\n", j, GLOBAL_OFFSET_TABLE[j], PLT_VADDR);
                GLOBAL_OFFSET_TABLE[j] = PLT_VADDR;
                PLT_VADDR += 16;
        }

        printf("[+] Patched GOT with PLT stubs\n");

        no_dynamic:
	
	printf("Opening output file: %s\n", outfile);

        if ((fd = open(outfile, O_TRUNC|O_WRONLY|O_CREAT)) == -1)
        {
                printf("Unable to open file for writing: %s\n", strerror(errno));
                return -1;
        }

        if (fchmod(fd, 00777) < 0)
                printf("Warning: Unable to set permissions on output file\n");

        /* Writing out new executable --
 *          * [TEXT][DATA (PLT/GOT)][BSS][String Table]
 *                   * The symbol table and string table will not be included
 *
 */

        ep->e_shstrndx = !dyn ? 4 : 6;
        ep->e_shoff = totlen + bss_len + sizeof(shstrtable);
        ep->e_shnum = !dyn ? 5 : 7;
        Elf32_Off shsoff = totlen + bss_len;

        if (write(fd, pmem, totlen) != totlen)
        {
                printf("Unable to write entire data: %s\n", strerror(errno));
                return -1;
        }
	
	int bw;
        if ((bw = write(fd, &null, bss_len)) != bss_len)
        {
                printf("Unable to create bss padding %d bytes (but only %d written): %s\n", bss_len, bw, strerror(errno));
                return -1;
        }

        totlen += bss_len;

        /* Write string table (final section) */
        if (write(fd, (char *)shstrtable, sizeof(shstrtable)) != sizeof(shstrtable))
        {
                printf("Unable to write string table %d bytes: %s\n", strerror(errno));
                return -1;
        }

        int slen = sizeof(Elf32_Shdr);

        /* Add NULL section */
        memset(&shdr, 0, slen);
        shdr.sh_addr = BaseVaddr;

        if (write(fd, &shdr, slen) != slen)
        {
                printf("Error in writing section header: %s\n", strerror(errno));
                return -1;
        }

        totlen += slen;

        if (!dyn)
                goto no_interp;

        /* Add .interp section */
        shdr.sh_type = SHT_PROGBITS;
        shdr.sh_offset = interp_off;
        shdr.sh_addr = interp_vaddr;
        shdr.sh_flags = SHF_ALLOC;
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_entsize = 0;
        shdr.sh_size = interp_size;
        shdr.sh_addralign = 0;

        for (i = 0, p = shstrtable ;; i++)
                if (p[i] == '.' && p[i + 1] == 'i' && p[i + 2] == 'n' && p[i + 3] == 't' && p[i + 4] == 'e')
                {
                        shdr.sh_name = i;
                        break;
                }

        if (write(fd, &shdr, slen) != slen)
        {
                printf("Error in writing section header: %s\n", strerror(errno));
                return -1;
        }

        totlen += slen;

        no_interp:
        /* Add .text section */
        shdr.sh_type = SHT_PROGBITS;
        shdr.sh_offset = phdr[TS].p_offset;
        shdr.sh_addr = phdr[TS].p_vaddr;
        shdr.sh_flags = SHF_ALLOC | SHF_EXECINSTR;
        shdr.sh_info = 0;
        shdr.sh_link = 0;
        shdr.sh_entsize = 0;
        shdr.sh_size = phdr[TS].p_filesz;
        shdr.sh_addralign = 0xf;

        for (i = 0, p = shstrtable ;; i++)
                if (p[i] == '.' && p[i + 1] == 't' && p[i + 2] == 'e' && p[i + 3] == 'x' && p[i + 4] == 't')
                {
                        shdr.sh_name = i;
                        break;
                }
        if (write(fd, &shdr, slen) != slen)
        {
                printf("Error in writing section header: %s\n", strerror(errno));
                return -1;
        }

        totlen += slen;

        /* Add .data section */
        shdr.sh_type = SHT_PROGBITS;
        shdr.sh_offset = phdr[DS].p_offset;
        shdr.sh_addr = phdr[DS].p_vaddr;
        shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
        shdr.sh_info = 0;
        shdr.sh_link = 0;
        shdr.sh_entsize = 0;
        shdr.sh_size = phdr[DS].p_filesz;
        shdr.sh_addralign = 4;

        for (i = 0, p = shstrtable ;; i++)
                if (p[i] == '.' && p[i + 1] == 'd' && p[i + 2] == 'a' && p[i + 3] == 't' && p[i + 4] == 'a')
                {
                        shdr.sh_name = i;
                        break;
                }

        if (write(fd, &shdr, slen) != slen)
        {
                printf("Error in writing section header: %s\n", strerror(errno));
                return -1;
        }

        totlen += slen;

        if (!dyn)
                goto no_dynam_section;

        /* Add .dynamic section */
        shdr.sh_type = SHT_DYNAMIC;
        shdr.sh_offset = dynoffset;
        shdr.sh_addr = dynvaddr;
        shdr.sh_flags = SHF_WRITE | SHF_ALLOC;
        shdr.sh_info = 0;
        shdr.sh_link = 0;
        shdr.sh_entsize = 8;
        shdr.sh_size = dynsize;
        shdr.sh_addralign = 4;

        for (i = 0, p = shstrtable ;; i++)
                if (p[i] == '.' && p[i + 1] == 'd' && p[i + 2] == 'y' && p[i + 3] == 'n' && p[i + 4] == 'a'
                                && p[i + 5] == 'm' && p[i + 6] == 'i' && p[i + 7] == 'c')
                {
                        shdr.sh_name = i;
                        break;
                }

        if (write(fd, &shdr, slen) != slen)
        {
                printf("Error in writing section header: %s\n", strerror(errno));
                return -1;
        }
       totlen += slen;

        no_dynam_section:

        /* Add .bss section */
        shdr.sh_type = SHT_NOBITS;
        shdr.sh_offset = phdr[DS].p_offset + phdr[DS].p_filesz;
        shdr.sh_addr = phdr[DS].p_vaddr + phdr[DS].p_filesz;
        shdr.sh_flags = SHF_WRITE | SHF_ALLOC;
        shdr.sh_info = 0;
        shdr.sh_link = 0;
        shdr.sh_entsize = 0;
        shdr.sh_size = bss_len;
        shdr.sh_addralign = 4;

        for (i = 0, p = shstrtable ;; i++)
                if (p[i] == '.' && p[i + 1] == 'b' && p[i + 2] == 's' && p[i + 3] == 's')
                {
                        shdr.sh_name = i;
                        break;
                }

        if (write(fd, &shdr, slen) != slen)
        {
                printf("Error in writing section header: %s\n", strerror(errno));
                return -1;
        }
        totlen += slen;

        /* add .shstrtab */
        shdr.sh_type = SHT_STRTAB;
        shdr.sh_offset = shsoff;
        shdr.sh_addr = BaseVaddr + shsoff;
        shdr.sh_flags = 0;
        shdr.sh_info = 0;
        shdr.sh_link = 0;
        shdr.sh_entsize = 0;
        shdr.sh_size = sizeof(shstrtable);
        shdr.sh_addralign = 1;

        for (i = 0, p = shstrtable ;; i++)
                if (p[i] == '.' && p[i + 1] == 's' && p[i + 2] == 'h' && p[i + 3] == 's' && p[i + 4] == 't')
                {
                        shdr.sh_name = i;
                        break;
                }

        if (write(fd, &shdr, slen) != slen)
        {
                printf("Error in writing section header: %s\n", strerror(errno));
                return -1;
        }
        totlen += slen;

        close(fd);
	
	printf("Successfully created executable\n");
}
                   
