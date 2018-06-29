/*
 * (AVU) Anti Virus UNIX - (C) 2008 Ryan O'Neill <ryan@bitlackeys.com>
 * Detects & Removes Viruses that hide in ELF Executables.
 * This code has only been tested on Linux, but should work in other 32-bit OS's
 * that use ELF.     
 */


#include "avu.h"

/* globals */
char *exec_name;
int virus = 0;
int memvirus = 0;
int failed_process = 0;

struct status 
{
	int failed;
	int success;
} status;

struct current_infection 
{
	int current_method;
	int parasite_offset;
	int parasite_length;
	int bss_size;
} current;

char *filename;

int gpid;
int attached_to_process;
int pt_interp = 0;

struct stat st;

int global_force_elf = 0;
char **global_envp;

/*
 * -- DISINFECTION CODE --
 * The following function is a prototype disinfection algorithm that can disinfect the 3 major
 * ELF executable infection types. PRE-TEXT INFECTION, TEXT PADDING INFECTION, DATA SEGMENT INFECTION.
 * This code can be improved, but I was able to disinfect the brundle fly virus with it, which I had
 * never seen while writing the code for this function, so it is still intelligent code.
 */

int remove_infection(uint32_t e_entry, uint32_t sh_addr, Elf32_Off sh_offset, uint32_t sh_size, unsigned char *mem, 
		     char type)
{
	struct segment_info *phdr;
	int fd, i;

	char ep[4] = {0};

	Elf32_Ehdr *e_hdr;
	Elf32_Shdr *s_hdr;
	Elf32_Phdr *p_hdr;

	uint32_t p_vaddr;

	/* jmp or push are used to return to real entry point */
	/* the following are several entry return code methods */
	/* but we are best suited to rely on the glibc initialization */
	/* fingerprint. If however we rely on jmp/push entry point */
	/* return methods, we can remove multiple viruses. */
	unsigned jmp[4];
	jmp[0] = 0xb8;
	jmp[1] = 0xff;
	jmp[2] = 0xe0;
	
	unsigned jmp_ebp[4];
	jmp_ebp[0] = 0xbd;
	jmp_ebp[1] = 0xff;
	jmp_ebp[2] = 0xe5;

	unsigned push[3];
	push[0] = 0x68;
	push[1] = 0xc3;
	
	/* GLIBC INITIALIZATION FINGERPRINT */
	/* the glibc init (_start) is generally the entry point */
	/* this is our *primary* method of learning the host entry */
	unsigned  _start[12];
	_start[0] = 0x31;
	_start[1] = 0xed;
	_start[2] = 0x5e;
	_start[3] = 0x89;
	_start[4] = 0xe1;
	_start[5] = 0x83;
	_start[6] = 0xe4;
	_start[7] = 0xf0;
	_start[8] = 0x50;
	_start[9] = 0x54;
	_start[10] = 0x52;
	
	unsigned long host_entry = 0;
	unsigned long tmp_host_entry = 0;

	char found_entry = 0;
	char found_data;
	char entry_code;

	unsigned int plen;
	phdr = query_elf_segments(mem);
	
	/* the current elf headers will altered by the virus */
	e_hdr = (Elf32_Ehdr *)mem;
	s_hdr = (Elf32_Shdr *)(mem + e_hdr->e_shoff);
	p_hdr = (Elf32_Phdr *)(mem + e_hdr->e_phoff);
	
	unsigned char *dp;
	unsigned char *tp = mem + sh_offset;
	
	switch(type) {
	
	/*
         * -- DISINFECT TEXT SEGMENT PADDING INFECTION --                  
         * This probably requires the most work, but has some more predictable aspects
         * that make it relatively straight forward. It needs some work though. Currently
         * it assumes that the padding length is a PAGE_SIZE -- this type of infection requires
         * that the padding be page aligned, so technically it can be larger than a page. 
         * TODO: Determine padding length.
         */

	case TEXT_PADDING_INFECTION:
	
	/* If 'host_entry_detection=alt' in avu.conf */
	/* then do not use the more reliable method */
	/* of finding the host entry point, otherwise */
	/* do */ 
	if (!opts.alternative_entry_detection)
	{
		if ((host_entry = get_host_entry(mem, _start)) == 0)
			found_entry = 0;
		else
			found_entry = 1;
	
		if (found_entry)
			goto disinfect_text_padding;
   	} 

	tp += sh_size - 7;
	printv((opts.logging)?1:0,"Attempting to disinfect text-segment-padding infection\n");
	if ((tp[0] == push[0]) && (tp[5] == push[1]))
	{
		/* found entry point */
		tp++;
		host_entry = tp[0] + (tp[1] << 8) + (tp[2] << 16) + (tp[3] << 24);
		e_hdr->e_entry = host_entry;
		found_entry = 1;
	}
	 else
        /* lets try incrementing by one and see if we can see push now */
        /* this is a position changed I noticed only on gentoo systems */
        {
                tp++;
                if ((tp[0] == push[0]) && (tp[5] == push[1]))
                {
                        /* found entry point */
                        tp++;
                        host_entry = tp[0] + (tp[1] << 8) + (tp[2] << 16) + (tp[3] << 24);
                        e_hdr->e_entry = host_entry;
                        found_entry = 1;
                }
        }
	
	/* The virus may also be using jmp to return control to the entry point */
	if (!found_entry)
	{
		tp = mem + sh_offset;
		tp += sh_size - 8;
		if ((tp[0] == jmp[0]) && (tp[5] == jmp[1]) && (tp[6] == jmp[2]))
		{
			/* found entry point */
			tp++;
			host_entry = tp[0] + (tp[1] << 8) + (tp[2] << 16) + (tp[3] << 24);
			e_hdr->e_entry = host_entry;
			found_entry = 1;
		}
		else
		if ((tp[0] == jmp_ebp[0]) && (tp[5] == jmp_ebp[1]) && (tp[6] == jmp_ebp[2]))
		{
			tp++;
		        host_entry = tp[0] + (tp[1] << 8) + (tp[2] << 16) + (tp[3] << 24);
                        e_hdr->e_entry = host_entry;
                        found_entry = 1;
		}
		
	
	}
	
	/* if we have still not found the entry point using the method */
	/* that assumes the entry point jmp as at the end of the code */
	/* we must check all of the parasite for a change in execution */
	if (!found_entry)
	{
	  i = 0;
	  tp = mem + sh_offset;
	  while (found_entry != 1)
          {
                        if ((tp[0] == push[0]) && (tp[5] == push[1]))
                        {
                                /* found entry point */
                                tp++;
                                host_entry = tp[0] + (tp[1] << 8) + (tp[2] << 16) + (tp[3] << 24);
                                e_hdr->e_entry = host_entry;
                                found_entry = 1;
                        }

                        else
                        if ((tp[0] == jmp[0]) && (tp[5] == jmp[1]) && (tp[6] == jmp[2]))
                        {
                                /* found entry point */
                                tp++;
                                host_entry = tp[0] + (tp[1] << 8) + (tp[2] << 16) + (tp[3] << 24);
                                e_hdr->e_entry = host_entry;
                                found_entry = 1;
                                entry_code = JMP;
                        }
                        else
                        if ((tp[0] == jmp_ebp[0]) && (tp[5] == jmp_ebp[1]) && (tp[6] == jmp_ebp[2]))
                        {
                                /* found entry point */
                                tp++;
                                host_entry = tp[0] + (tp[1] << 8) + (tp[2] << 16) + (tp[3] << 24);
                                e_hdr->e_entry = host_entry;
                                found_entry = 1;
                                entry_code = JMP;
                        }


                        if (i++ >= ((sh_offset + sh_size) - sh_offset))
                        {
                                printv((opts.logging)?1:0,"Checked %d positions and did not find entry-return-code\n", ((sh_offset + sh_size) - sh_offset));
                                printv((opts.logging)?1:0,"The binary remains infected.\n");
                                break;
                        }
                        tp++;
          }    
	} 
	
	disinfect_text_padding: 
	e_hdr->e_entry = host_entry;

	if (found_entry)
		printv((opts.logging)?1:0,"Found original entry point: 0x%x\n", host_entry);
        else
	{
	 	printv((opts.logging)?1:0,"Could not locate original entry point, the binary remains infected\n");
		return 0;
	}

	printv((opts.logging)?1:0,"Attempting to reverse infection and rewrite the binary\n");

	char text_found;

	text_found = 0;
	current.parasite_length = sh_size;

        for (i = e_hdr->e_phnum; i-- > 0; p_hdr++) 
        {
                if (text_found) 
                {
                        p_hdr->p_offset -= PAGE_SIZE;
                        continue;
                }
                else 
                if (p_hdr->p_type == PT_LOAD) 
                {
                        if (p_hdr->p_flags == (PF_R | PF_X)) 
                        {
				p_vaddr = p_hdr->p_vaddr + p_hdr->p_filesz;
				p_hdr->p_filesz -= current.parasite_length;
				p_hdr->p_memsz -= current.parasite_length;
				phdr[TEXT].end_of_segment = p_hdr->p_offset + p_hdr->p_filesz;
				text_found++;
			} 
		}
        }

        s_hdr = (Elf32_Shdr *) (mem + e_hdr->e_shoff);
    	for (i = e_hdr->e_shnum; i-- > 0; s_hdr++) 
        {
        	  if (s_hdr->sh_offset >= phdr[TEXT].end_of_segment)
                  	s_hdr->sh_offset -= PAGE_SIZE;
 	          else 
         	  if (s_hdr->sh_size + s_hdr->sh_addr == p_vaddr)
	  		s_hdr->sh_size -= current.parasite_length;
        }
	  
	e_hdr->e_shoff -= PAGE_SIZE;
	
	if ((fd = open(TMP, O_CREAT | O_TRUNC | O_WRONLY, st.st_mode)) == -1)
	{
		perror("open tmp");
		exit(-1);
	}
	
	if (write(fd, mem, phdr[TEXT].end_of_segment) != phdr[TEXT].end_of_segment)
	{
		perror("write: first chunk");
		exit(-1);
	}

	mem += phdr[TEXT].end_of_segment + PAGE_SIZE;
	unsigned int last_chunk = st.st_size - (phdr[TEXT].end_of_segment + PAGE_SIZE);
	
	if (write(fd, mem, last_chunk) != last_chunk)
	{
		perror("write: last chunk");
		exit(-1);
	} 

 	if (fchown(fd, st.st_uid, st.st_gid) < 0)
	{
                perror("chown");
                exit(-1);
	}

	break;
	/* ---------------- data infection removal --------------- */
	case DATA_INFECTION:
	
	printv((opts.logging)?1:0,"Attempting to un-infect data infection\n");
	/* because there is no section we can't use sh_size to locate host_entry */
	/* we must check every memory location for jmp/push code */
	if (current.current_method == NO_SECTION)
	{
		dp = mem + current.parasite_offset;
		found_entry = 0;
		i = current.parasite_offset;
		locate_return:
		while (found_entry != 1)
		{
			if ((dp[0] == push[0]) && (dp[5] == push[1]))
 	        	{
                		/* found entry point */
         	        	dp++;
                		host_entry = dp[0] + (dp[1] << 8) + (dp[2] << 16) + (dp[3] << 24);
                		e_hdr->e_entry = host_entry;
               	        	found_entry = 1;
                        }
			
			else
			if ((dp[0] == jmp[0]) && (dp[5] == jmp[1]) && (dp[6] == jmp[2]))
 		        {
               		        /* found entry point */
                 	        dp++;
                        	host_entry = dp[0] + (dp[1] << 8) + (dp[2] << 16) + (dp[3] << 24);
                        	e_hdr->e_entry = host_entry;
                        	found_entry = 1; 
				entry_code = JMP;
			}
			else
			if ((dp[0] == jmp_ebp[0]) && (dp[5] == jmp_ebp[1]) && (dp[6] == jmp_ebp[2]))
			{
				/* found entry point */
				dp++;
				host_entry = dp[0] + (dp[1] << 8) + (dp[2] << 16) + (dp[3] << 24);
				e_hdr->e_entry = host_entry;
				found_entry = 1;
				entry_code = JMP;
			}
				
			
			if (i++ == phdr[DATA].end_of_segment)
			{
				printv((opts.logging)?1:0,"Checked 1,000 positions and did not find entry return code\n"); 
				printv((opts.logging)?1:0,"The binary remains infected.\n");
				break;
			}
			dp++;
                 } 
		 
		 if (found_entry) 
		 {
		 	 if(!opts.alternative_entry_detection)
			 	if ((tmp_host_entry = get_host_entry(mem, _start)) != host_entry)
						host_entry = tmp_host_entry;

                	 printv((opts.logging)?1:0,"Found original entry point: 0x%x Offset: %d\n", host_entry, i);
			 current.parasite_length = i - current.parasite_offset;
			 if (entry_code == JMP)
			 	current.parasite_length += 7;
			 else
			 if (entry_code == PUSH)
			 	current.parasite_length += 6;

			 printv((opts.logging)?1:0,"Parasite length: %d\n", current.parasite_length);
		 }
        	 else
         	 {
                 	printv((opts.logging)?1:0,"Could not locate original entry point, the binary remains infected\n");
                	return 0;
        	 }
		
		printv((opts.logging)?1:0,"Attempting to reverse infection, and rewrite binary\n");

		phdr = query_elf_segments(mem);
		current.bss_size = phdr[DATA].p_memsz - phdr[DATA].p_filesz; 
		plen = current.parasite_length + current.bss_size;
		found_data = 0;
		
		/* begin the un-infection */
		for (i = e_hdr->e_phnum; i-- > 0; p_hdr++)
 	        {
			if (found_data && p_hdr->p_type != PT_DYNAMIC)
			{
				p_hdr->p_offset -= plen;
				continue;
			}
			else
		 	if (p_hdr->p_type == PT_LOAD && p_hdr->p_offset != 0)
			{
				found_data = 1;
				e_hdr->e_entry = host_entry;
				p_hdr->p_filesz -= plen;
				p_hdr->p_memsz -= plen;
			}
		 }
		 
		 s_hdr = (Elf32_Shdr *) (mem + e_hdr->e_shoff);
 	         for (i = e_hdr->e_shnum; i-- > 0; s_hdr++)
        	 {
                 	 if (s_hdr->sh_offset >= phdr[DATA].end_of_segment) 
                         	s_hdr->sh_offset -= plen; 
		 }
		 
		 /* phdr[DATA].end_of_segment is equal to data segments p_offset + p_filesz */
		 /* which should be decreased by parasite len at this point	  */

		 phdr[DATA].end_of_segment -= plen; 
		 e_hdr->e_shoff -= plen;
		
	         if ((fd = open(TMP, O_CREAT | O_TRUNC | O_WRONLY, st.st_mode)) == -1)
        	 {
                 	perror("open tmp");
                	exit(-1);
        	 }

		 unsigned int totlen = 0;
		 int c;
	
		 /* write .data segment */
        	 if ((c = write(fd, mem, phdr[DATA].end_of_segment)) != phdr[DATA].end_of_segment)
        	 {
                 	printv((opts.logging)?1:0,"Failed writing data segment, wrote %d bytes\n", c);
                 	exit(-1);
        	 }	
		 
           	 mem += phdr[DATA].end_of_segment + plen;
		 totlen += phdr[DATA].end_of_segment;
		 
	         unsigned int last_chunk = st.st_size - (totlen + plen);
		  
	         if ((c = write(fd, mem, last_chunk)) != last_chunk)
        	 {	 
                 	printf("Wrote %d bytes\n", c);
                 	exit(-1);
        	 }
		
		 if (fchown(fd, st.st_uid, st.st_gid) < 0) 
		 {
		 	perror("fchown");	
			exit(-1);
		 }

		  
	}
		break;
	case TEXT_INFECTION:
		/*--------disinfect text infection-------*/

		printv((opts.logging)?1:0,"Attempting to reverse infection and rewrite binary\n");
		found_entry = 1; /* entry point isn't modified in this algorithm */
		text_found = 0;
		p_hdr[0].p_offset -= PAGE_SIZE;
		p_hdr[1].p_offset -= PAGE_SIZE;

		for (i = e_hdr->e_phnum; i-- > 0; p_hdr++) 
       		{         
          		if (text_found)
                  		p_hdr->p_offset -= PAGE_SIZE;

           		if(p_hdr->p_type == PT_LOAD)
                		if (p_hdr->p_flags == (PF_R | PF_X))
                		{
                          		p_hdr->p_vaddr += PAGE_SIZE;
                       		  	p_hdr->p_paddr += PAGE_SIZE;
                          		p_hdr->p_filesz -= PAGE_SIZE;
                       		        p_hdr->p_memsz -= PAGE_SIZE;
                          		text_found = 1;
				}
                }

		int c;
		s_hdr = (Elf32_Shdr *)(mem + e_hdr->e_shoff);
 	        for (i = e_hdr->e_shnum; i-- > 0; s_hdr++)
         	       s_hdr->sh_offset -= PAGE_SIZE;

		 e_hdr->e_shoff -= PAGE_SIZE;
 	         e_hdr->e_phoff -= PAGE_SIZE;

	         if ((fd = open(TMP, O_CREAT | O_TRUNC | O_WRONLY, st.st_mode)) == -1)
                 {
                        perror("open tmp");
                        exit(-1);
                 }

	         if ((c = write(fd, mem, 52)) != 52)
        	 {
                 	printf("failed writing ehdr, wrote %d bytes\n", c);
                 	exit(-1);
      		 }

		 mem += PAGE_SIZE + 52;

		 last_chunk = st.st_size - (PAGE_SIZE + 52);

		 if ((c = write(fd, mem, last_chunk)) != last_chunk)
		 {
		 	printf("failed to write last chunk of file: text disinfection, wrote %d\n", c);
			exit(-1);
		 }

		 if (fchown(fd, st.st_uid, st.st_gid) < 0)
 	         {
           	        perror("chown");
                	exit(-1);
 	         }
		 break;


}	
	close(fd);

	if (quarantine(exec_name, filename))
		printv((opts.logging)?1:0,"Successfully backed up and quarantined %s into %s\n", exec_name, ZIPDIR);
	else
		printv((opts.logging)?1:0,"Unable to backup and quarantine %s: unknown error\n", exec_name);

	rename(TMP, exec_name);
	if (found_entry)
		printv((opts.logging)?1:0,"Sucessfully disinfected the binary\n");
	return 1;
	 
}

void fatal(char *msg)
{
	printv((opts.logging)?1:0,"a fatal error has occured, exiting...\n");
	printv((opts.logging)?1:0,"die message: %s\n", msg);
	exit(-1);
}

int virus_check(unsigned char *membuf)
{
	unsigned long EntryPoint, tmp;
	struct segment_info *segment_headers;
	char *StringTable;
	int i, ret;
	int section_count = 0, past_ds = 0, check_v = 0, found_section = 0;
	
	Elf32_Ehdr *e_hdr;
	Elf32_Phdr *p_hdr;
	Elf32_Shdr *s_hdr;

	e_hdr = (Elf32_Ehdr *)membuf;
	
	if (e_hdr->e_shstrndx == SHN_UNDEF)
		return 0;
	
	s_hdr = (Elf32_Shdr *)(membuf + e_hdr->e_shoff);
	
	/* setup a coherent and easy to use string table */

	StringTable = &membuf[s_hdr[e_hdr->e_shstrndx].sh_offset];
	EntryPoint = e_hdr->e_entry;

	/* lets check for a text infection which extends itself backwards first */
	/* the obvious oddity here is that the text p_vaddr will not be 8048000 */
	/* the result can also be used to calculate the parasite size as well */

	segment_headers = query_elf_segments(membuf);
	if (segment_headers[TEXT].p_vaddr != TEXT_VADDR && segment_headers[TEXT].p_vaddr != 0)
	{
		if (TEXT_VADDR > segment_headers[TEXT].p_vaddr)
		{
			tmp = TEXT_VADDR - segment_headers[TEXT].p_vaddr;

			printv((opts.logging)?1:0,"\n-= Warning =-\n"
			"Discovered probable text infection\n"
			"Text segment current vaddr: 0x%x\n"
			"Estimated parasite length: %d bytes\n", 
			segment_headers[TEXT].p_vaddr, tmp);
		
			if (!opts.elf_disinfect)
				goto end;
			current.parasite_length = tmp; 
			ret = remove_infection(0,0,0,0, membuf, TEXT_INFECTION);
		        if (ret)
				status.success++;
			else		
				status.failed++;
			virus++;
			return 0;
		}
	}
		
		
	for (i = e_hdr->e_shnum; i-- > 0; s_hdr++)
	{
		if (s_hdr->sh_name == 0)
			continue;
		
		if (strcmp(&StringTable[s_hdr->sh_name], ".text") == 0)
		{
			/* usually the entry point is .text sections sh_addr */
			if (e_hdr->e_entry != s_hdr->sh_addr)
                        {
                        	printv((opts.logging)?1:0,"\n\n-= warning =-\n");
                                printv((opts.logging)?1:0,"executable: %s\n", exec_name);
                                printv((opts.logging)?1:0,"entry point 0x%x may not be in .text\n", e_hdr->e_entry);
				
				if (EntryPoint >= s_hdr->sh_addr && EntryPoint < (s_hdr->sh_addr + s_hdr->sh_size))
					return 0;
				else
					check_v = 1;

			}
		}  
	}
	if (check_v == 1)  
	{
		section_count = 1;
		found_section = 0;
		s_hdr = (Elf32_Shdr *) (membuf + e_hdr->e_shoff);

		/* entry point is not within .text */
		for (i = e_hdr->e_shnum; i-- > 0; s_hdr++)
		{
			if (s_hdr->sh_name == 0)
			{
				section_count++;
				continue;
			}
		
			if (strcmp(&StringTable[s_hdr->sh_name], ".data") == 0)
				past_ds = 1;
		
			if (EntryPoint >= s_hdr->sh_addr && EntryPoint < (s_hdr->sh_addr + s_hdr->sh_size))
			{
				current.current_method = SECTION_EXISTS;
				found_section = 1;
			}
			
			if (found_section)
			{
				disinfect:
				if (!past_ds)
				{
					virus++;
					current.parasite_offset = segment_headers[TEXT].p_offset + (EntryPoint - segment_headers[TEXT].p_vaddr);

					printv((opts.logging)?1:0,"Found entry point in section: %s\n", &StringTable[s_hdr->sh_name]);
                                	printv((opts.logging)?1:0,"Detected A parasite between text & data segment\n");
                                	printv((opts.logging)?1:0,"Type: Text segment padding virus (padding infection)\n");
					
					if (current.current_method == SECTION_EXISTS)
                                		printv((opts.logging)?1:0,"Infected section: %s\n", &StringTable[s_hdr->sh_name]); 
					
					printv((opts.logging)?1:0,"Parasite Offset: %d\n", current.parasite_offset);
					if (!opts.elf_disinfect)
						goto end;
					ret = remove_infection(e_hdr->e_entry, s_hdr->sh_addr,
                                        s_hdr->sh_offset, s_hdr->sh_size, membuf, TEXT_PADDING_INFECTION);
                                        
					if (ret)
                                         	status.success++;
                                         else
                                                status.failed++;
					 return 0;

				}
				else
				{
					if (current.current_method == SECTION_EXISTS)
						printv((opts.logging)?1:0,"parasite entry is [%s](%x)\n", &StringTable[s_hdr->sh_name], EntryPoint);
                                        virus++;

                                        if(EntryPoint > segment_headers[DATA].p_vaddr + segment_headers[DATA].p_memsz)
                                        {
                                                printv((opts.logging)?1:0,"Detected a parasite that has been"
                                                "inserted after the data segment\n");
                                                return 0;
                                        }

                                        current.parasite_offset = segment_headers[DATA].p_offset + (EntryPoint - segment_headers[DATA].p_vaddr);
                                        
					printv((opts.logging)?1:0,"Detected a parasite within the data segment\n"
                                        "Type: Data segment virus (data infection)\n"); 
					
					if (current.current_method == SECTION_EXISTS)
						printv((opts.logging)?1:0,"Infected section: %s\n", &StringTable[s_hdr->sh_name]);
                                        
					printv((opts.logging)?1:0,"Parasite offset: %u\n", current.parasite_offset);
                                     
				     	if (!opts.elf_disinfect)
						goto end;
				        ret = remove_infection(e_hdr->e_entry, s_hdr->sh_addr,
                                        s_hdr->sh_offset, s_hdr->sh_size, membuf, DATA_INFECTION);
                                        past_ds = 0;
                                        if (ret)
   	                                      status.success++;
                                        else
                                              status.failed++;
					return 0;
				}
			
		  	}	
			else
			if (!found_section && section_count == e_hdr->e_shnum)
			{
				current.current_method = NO_SECTION;
				goto disinfect;
			}
			section_count++;
		 }
	}
	end:
	return 0;	 
}


struct segment_info * query_elf_segments(unsigned char * mem) 
{
	Elf32_Phdr *p_hdr;
	Elf32_Ehdr *e_hdr;
	
	struct segment_info *segment_pointer = malloc(sizeof(struct segment_info) * 2);

	int i, check = 0;

	e_hdr = (Elf32_Ehdr *)mem;
	p_hdr = (Elf32_Phdr *)(mem + e_hdr->e_phoff);
 	
	for (i = e_hdr->e_phnum; i-- > 0; p_hdr++)
	{
		if (p_hdr->p_type == PT_LOAD && p_hdr->p_offset == 0)
		{
			if (p_hdr->p_flags == (PF_R | PF_X))
			{	
				/* TEXT */
				segment_pointer[TEXT].p_offset = p_hdr->p_offset;
				segment_pointer[TEXT].p_memsz = p_hdr->p_memsz;
				segment_pointer[TEXT].p_filesz = p_hdr->p_filesz;
				segment_pointer[TEXT].p_vaddr = p_hdr->p_vaddr;
				segment_pointer[TEXT].end_of_segment = p_hdr->p_offset + p_hdr->p_filesz;
				/* DATA */
				p_hdr++;
				segment_pointer[DATA].p_offset = p_hdr->p_offset;
				segment_pointer[DATA].p_memsz = p_hdr->p_memsz;
				segment_pointer[DATA].p_filesz = p_hdr->p_filesz;
				segment_pointer[DATA].p_vaddr = p_hdr->p_vaddr;
				segment_pointer[DATA].end_of_segment = p_hdr->p_offset + p_hdr->p_filesz;
				check = 1;
				break;
			}
		}	
	}
	if (!check)
		segment_pointer[TEXT].NoSegment = 1;

	return segment_pointer;
	
}          

int main(int argc, char **argv, char **envp)
{
	
	Elf32_Ehdr *e_hdr;
	Elf32_Phdr *p_hdr;
	Elf32_Shdr *s_hdr;
	
	int i, k, off1, off2, j, nread;
	int dd, dnum, index = 0, bpos, fd;

	char section[BUF_SIZE] = {0}; 
	char buf[4096];
 	char **directory;
	char *temp_mem;
	unsigned char *mem;
	char ret, check = 0;

	struct segment_info *segment_headers;
	struct linux_dirent *d;

	pid_t uid;
	gid_t gid;
	
	/* TODO: memset for initialization */
	opts.alternative_entry_detection = 0;
	opts.kp = 0;
	opts.memscan = 0;
	opts.recursion = 0;
	opts.logging = 0;
	opts.verbose = 0;
	opts.debug = 0;
	opts.nostdout = 0;
	opts.extract_parasite = 0;
	opts.plt_hijack = 0;
	opts.unpack = 0;

	/* For unpack_executable which requires an arg vector */
	char **args, *arg_string;

	struct sigaction act;
 	sigset_t set;
	struct linking_info *lp;
  	act.sa_handler = sighandle;
  	sigemptyset (&act.sa_mask);
  	act.sa_flags = 0;
  	sigaction (SIGINT, &act, NULL);
  	sigemptyset (&set);
  	sigaddset (&set, SIGINT);

	if (argc < 2)	
		usage();
	
	/* TODO -- clean getopts() code */
	if (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-h"))
		usage();
	if (!strcmp(argv[1], "--memscan") || !strcmp(argv[1], "-m"))
		opts.memscan = 1;
	if (!strcmp(argv[1], "--unpack") || !strcmp(argv[1], "-u"))
		opts.unpack = 1;

	/* options are set in config file */
	parse_config(CONFIG);
	uid = getuid();
	gid = getgid();
		
	/* UNPACK AN EXECUTABLE */
	if (opts.unpack && argc >= 3)
	{
		global_envp = envp;

		char *target_path = argv[2];
			
		/* When unpacking its possible the packed executable */	
		/* stub code will not even appear to be an ELF file */
		/* and our IsElf() function will fail, unless we force */
		/* it to load the file. */
		global_force_elf = 1;

		if (argc == 3)
		{
			unpack_executable(target_path, NULL);
			goto done;
		}
		
		/* If we are here it means we are passing the */
		/* executable some type of args */
		MakeString(&argv[2], argc-2, arg_string);
		printf("args_string: %s\n", arg_string);
		ExecVector(&args, " ", arg_string);
		unpack_executable(target_path, args);
		goto done;
		
		
	}
	/* SCAN A SINGLE PROCESS */
	if (opts.memscan && argc >= 3)
	{
		i = 0;
		opts.memscan++;
		while (argv[2][i] >= '0' && argv[2][i] <= '9')
			i++;
		if (i != strlen(argv[2]))
			usage();
		scan_process(atoi(argv[2]));
		goto done;
	}
	else
	/* THIS MEANS SCAN ALL PROCESSES IN /proc */
	if (opts.memscan)
	{
	
                if ((dd = open("/proc", O_RDONLY | O_DIRECTORY)) == -1)
                {
                        perror("open dir");
                        exit(-1);
                }
		
		for (;;)
		{
			if ((nread = syscall(SYS_getdents, dd, buf, 1024)) == -1)
			{
				perror("getdents");
				exit(-1);
			} 
			
			if (nread == 0)
				break;
	
	 		for (bpos = 0; bpos < nread;)
                	{
				i = 0;
                        	d = (struct linux_dirent *)(buf + bpos);
                        	bpos += d->d_reclen; 
				while (d->d_name[i] >= '0' && d->d_name[i] <= '9')
					i++;
				if (i != strlen(d->d_name))	
					continue;
				scan_process(atoi((char *)d->d_name));
			}
		}
		goto done;
	}
			
		
        mkzip_dir(uid, gid);
	
	status.success = 0;
	status.failed = 0;

	dnum = argc - 1;

	if ((directory = calloc(argc, sizeof(char *))) == NULL)
	{
		perror("calloc");
		exit(-1);
	}
	
	for (i = 0, j = 1; i < dnum; i++, j++)
	{
		if (!(directory[i] = strdup(argv[j])))
		{
			perror("strdup");
			exit(-1);
		}
	}
	
	for (i = 0; i < dnum; i++)
	{
		if ((dd = open(directory[i], O_RDONLY | O_DIRECTORY)) == -1)
		{
			perror("open dir");
			exit(-1);
		}
	
		for (;;)
		{
			if ((nread = syscall(SYS_getdents, dd, buf, 4096)) == -1)
			{
				perror("getdents");
				exit(-1);
			}
			
			if (nread == 0)
				break;

			for (bpos = 0; bpos < nread;)
			{
				d = (struct linux_dirent *)(buf + bpos);
				bpos += d->d_reclen; 
			
				if (!strcmp(d->d_name, ".") || !strcmp(d->d_name, ".."))
					continue; 
				filename = d->d_name;
				char bin[strlen(directory[i]) + strlen(d->d_name)];
				memset(bin, 0, sizeof(bin));	
		        	strcpy(bin, directory[i]);
				bin[strlen(bin)] = '/';
				strcat(bin, d->d_name);	
			
				rescan:
				if ((fd = open((check == 1) ? exec_name : bin, O_RDONLY)) == -1)
					continue;

				exec_name = bin;
				if (stat(bin, &st) < 0)
				{
					perror("stat");
					exit(-1);
				}

				if (S_ISDIR(st.st_mode) || S_ISFIFO(st.st_mode))
					continue;
			
				if (!st.st_size)
					continue;
				
				mem = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
				if (mem == MAP_FAILED)
				{
					perror("mmap");
					exit(-1);
				}
				close(fd);
				
				/* perform initial integrity check */
				switch(integrity_check(mem, exec_name))
				{
					case SEV1:
						printf("\nFile: %s may be infected, but has failed to meet certain ELF specifications\n"
						"that are required by AVU to properly discern whether or not the file is carrying a virus\n"
						"or parasite; AVU is choosing not to assess this file.\n", exec_name);

						goto loop; 
					case SEV2:
					/* this might change the behavior */
					/* or method that avu analyzes the file */
					/* (i.e being less dependent on sections */
					/* but is reserved for future use. Currently */
					/* this severity is considered safe */
						goto virus_scan;
					case SEV3:
					/* unused */
					case 0:
						/* HEALTHY LITTLE ELF! */ 
						goto virus_scan;
					case -1:
						goto loop;

				}
			
			virus_scan:
				
				if (pt_interp)
				{
                                	if ((lp = (struct linking_info *)get_plt(mem)) == NULL)
                                	{
                                       		printf("get_plt() failed\n");
                                        	continue;
                                	}
				
                                	if (opts.debug)
                               		{
                                        	printf("%d relocation entries\nOffset\tSymbol Name\n", lp[0].count);
                                    		int cnt;
				        	for (cnt = 0; cnt < lp[0].count; cnt++)
                                                	printf("%x\t%s\n", lp[cnt].r_offset, lp[cnt].name);
                                	}
				}

			/* --- check for infection --- */
			virus_check(mem);
		
				if (opts.alternative_entry_detection)
				{
					if (check == 1)
					{
						check = 0;
						goto loop;
					}
					else
					{ 
						check = 1;
						goto rescan;
					}
				}
			loop:
				continue;

		 }
	 }
}
	done:					
	if (opts.unpack)
		goto out;
	if (opts.memscan)
	{
		if (!memvirus)	
			printv((opts.logging)?1:0,"\nAVU does not see any infected processes\n");
		else
			printv((opts.logging)?1:0,"\nAVU found %d infected processes\n", memvirus);
		
		if (opts.verbose)
			printv((opts.logging)?1:0,"Failed to attach to %d processes\n", failed_process);
		exit(0);
	} 
	else
	{
		printf("\n%sMalware analysis Summary:%s\n",RED,END);
		if (!virus)
			printv((opts.logging)?1:0,"\nAVU does not see any infected binaries\n");
		else
		{
			printv((opts.logging)?1:0,"\nAVU discovered %d virus-infected binary\n", virus);
			if (status.success)
				printv((opts.logging)?1:0,"AVU Sucessfully removed the parasite from %d files\n", status.success);
			if (status.failed)
				printv((opts.logging)?1:0,"AVU Failed to remove the parasite from %d files\n", status.failed);
		}
	}

	out:
	if (opts.logging)
		free(opts.logfile);		
	free(directory);
	exit(0);
	
}
	
	
	
	
