/*
 * Part of Anti-Virus UNIX            
 * Author: Ryan O'Neill <ryan@bitlackeys.com>
 * This code detects memory resident parasites and viruses
 * <ryan@bitlackeys.com>
 */ 

#include "avu.h"


struct reloc_info
{
	uint32_t reloc_count;
	Elf32_Addr *reloc_vaddr;
} reloc_info;

	
unsigned long memread(unsigned long *buf, unsigned long vaddr, unsigned int size, int pid)
{
	int i, j, data;

	if (size == 1 && !buf)
		return (unsigned long)ptrace(PTRACE_PEEKTEXT, pid, vaddr);

	for (i = 0, j = 0; i < size; i+= sizeof(uint32_t), j++) 
	{	
		/* PTRACE_PEEK can return -1 on success, check errno */
		if(((data = ptrace(PTRACE_PEEKTEXT, pid, vaddr + i)) == -1) && errno)
			return -1;
		buf[j] = data;
	}
	return 1;
}


void catch_alarm(int sig)
{
	signal(sig, catch_alarm);
}
		
int scan_process(int pid)
{

	struct segment_info *seghdrs;
	char meminfo[20], ps[7], buf[MAXBUF], tmp[MAXBUF], *p, *file;
	FILE *fd;
	uint32_t i = 0, rc = 0;
	struct stat st;
	unsigned char *mem, *vmtext, *vmfile, *mp;
	int md, mods = 0, status;
	Elf32_Addr *reloc_vaddr;
	Elf32_Ehdr *ehdr;
	char type_dyn = 0;
	Elf32_Addr text_vaddr;
	Elf32_Addr export;
	unsigned long pvaddr;
	struct linking_info *lp;

	gpid = (int) pid;
	
	/* we can't attach to ourself */
	if (pid == getpid())
		return -1;

	signal(SIGALRM, catch_alarm);

	itoa(pid, ps);
	snprintf(meminfo, sizeof(meminfo)-1, "/proc/%s/maps" , ps);
	
	if ((fd = fopen(meminfo, "r")) == NULL)
	{
		printf("PID: %i cannot be checked, /proc/%i/maps does not exist\n", pid, pid);
		return -1;
	}

	fgets(buf, MAXBUF-1, fd);
	strncpy(tmp, buf, MAXBUF-1);
	
	if ((p = strchr(buf, '-')))
		*p = '\0';
	else
		return -1;

	text_vaddr = strtoul(buf, NULL, 16);
	
	if (strstr(tmp, "/"))
		while (tmp[i++] != '/');
	else
	{
		fclose (fd);
		return -1;
	}

	if ((file = strdup((char *)&tmp[i - 1])) == NULL)
	{
		failed_process++;	
		return -1;
	}
	
	i = 0;
	while (file[i++] != '\n');
	       file[i - 1] = '\0';
	
	if (!strcmp(file, "/sbin/init") || !strcmp(file, "/dev/mem"))
		return -1;
	
	if (opts.memscan == 2 || opts.debug || opts.verbose)
                printv((opts.logging)?1:0,"Scanning %s (pid: %i) for parasite infection\n", file, pid);

	if ((md = open(file, O_RDONLY)) == -1)
	{
		failed_process++;
		return -1;
	}

	if (fstat(md, &st) < 0)
	{
		failed_process++;
		return -1;
	}

	mem = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, md, 0);
	if (mem == MAP_FAILED)
	{
		perror("mmap");
	      	return -1;
	}
	
	ehdr = (Elf32_Ehdr *)mem;
	seghdrs = query_elf_segments(mem);
	
	if ((vmtext = malloc(seghdrs[TEXT].p_memsz)) == NULL)
	{
		failed_process++;
		return -1;
	}

	if (opts.plt_hijack)
	{
		if ((vmfile = malloc(st.st_size)) == NULL)
		{
			failed_process++;
			return -1;
		}
	}

	if (ehdr->e_type == ET_DYN) 
	{
		if (opts.memscan > 1)
			printv((opts.logging)?1:0,"PID: %d - Binary: %s is of type ET_DYN,"
			"AVU does not currently scan this type of process image\n",pid, file);
		goto done;
	}

 	if (ptrace(PTRACE_ATTACH, pid, NULL, NULL))
        {
		if (opts.verbose)
			printv((opts.logging)?1:0,"! - Notice -> Failed to attach to %s\n", file);
                failed_process++;
                return -1;
        }
	waitpid(pid, &status, WUNTRACED);
	/* read text segment from memory */
	attached_to_process = 1;
	alarm(3);
	
  	if (opts.plt_hijack)
   	{
		 memread((unsigned long *)vmfile, seghdrs[TEXT].p_vaddr, st.st_size, pid);

       		 if ((lp = (struct linking_info *)get_plt(mem)) == NULL)
        	 {
                	 printf("get_plt() failed\n");
                         goto done;
                 }
	
		 for (i = 0; i < lp[0].count; i++)
		 {
		 	export = memread(NULL, lp[i].r_offset, 1, pid);	
			if (opts.debug)
			{
				printv((opts.logging)?1:0,"\nr_offset: %x\n"
				       "symbol:   %s\n"
				       "export address: %x\n", lp[i].r_offset, lp[i].name, export);
			}
		 }
	}

	memread((unsigned long *)vmtext, seghdrs[TEXT].p_vaddr, seghdrs[TEXT].p_memsz, pid);
	
	/* compare text segment instructions from ELF file against process image text */
	mp = mem + seghdrs[TEXT].p_offset;
	if (opts.debug)
		printv((opts.logging)?1:0,"Checking text segment for modifications\n");

	pvaddr = seghdrs[TEXT].p_vaddr;
  	for (i = 0; i < seghdrs[TEXT].p_filesz; i++)
	{
		if (opts.debug)
			printv((opts.logging)?1:0,"Comparing %.2x to %.2x\n", mp[i], vmtext[i]); 

		if (mp[i] != vmtext[i]) 
		{
			if (opts.extract_parasite)
			{ 
				if (opts.verbose || opts.debug)
					printv((opts.logging)?1:0, "[Original code] %.2x [Parasite code] %.2x\n",mp[i], vmtext[i]);
				else
					if (mods)
						printv((opts.logging)?1:0, "%.2x ", vmtext[i]);
			}
			switch(mods)
			{
				case 0:
					printv((opts.logging)?1:0,"\nFound modifications to Text segment in process: %s pid: %d\n", file, pid);
					if (opts.extract_parasite)
						printv((opts.logging)?1:0, "%.2x ", vmtext[i]);
			 		break;
				default:
					break;
			}
			mods++;
		}
		next:
			continue;
	}
	if (mods)
		memvirus++;
	
	if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1)
	{
		if (opts.verbose)
			perror("ptrace_detach");
		goto done;
	}
	
	if (mods)
		if (opts.kp)
		{
			printf("! ATTENTION ! - Killing process - PID %d due to infection\n", pid);
			if (kill(pid, SIGKILL) == -1)
				printf("Warning: Unable to kill process - PID %d - infection remains active\n", pid);
		}
				
	done:
	fclose (fd);
	close (md);
	free(file);
	munmap(NULL, st.st_size);
	attached_to_process = 0;
	if (opts.plt_hijack)
		free(lp);
}

